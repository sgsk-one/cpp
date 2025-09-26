// xeon_profiler_dwfl_safe.cpp
// Perf-based profiler (Xeon-friendly) with VERY robust DWFL symbolization.
// Key hardening:
//  - Never call dwfl_module_* unless mod!=nullptr AND dwfl_module_getelf(mod)!=nullptr
//  - Skip bracketed pseudo-modules ([vdso], [anon], [kernel], etc.) for DWFL calls
//  - Fallback to dladdr() → "module!0xADDR" for everything else
//  - Guard every pointer, add caching, and sanitize names

#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <string_view>
#include <algorithm>
#include <optional>
#include <chrono>

#include <dlfcn.h>
#include <cxxabi.h>
#include <elfutils/libdwfl.h>

static int perf_event_open(perf_event_attr* attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}
static std::string demangle(const char* name) {
    if (!name) return {};
    int status = 0; size_t len = 0;
    char* out = abi::__cxa_demangle(name, nullptr, &len, &status);
    std::string s = (status == 0 && out) ? std::string(out) : std::string(name);
    free(out);
    return s;
}
static std::string basename_of(const char* path) {
    if (!path) return {};
    const char* slash = std::strrchr(path, '/');
    return slash ? std::string(slash + 1) : std::string(path);
}
static inline bool is_bracketed_module_name(const char* modname) {
    return modname && modname[0] == '['; // [vdso], [kernel], [anon], etc.
}
static std::string hex_addr(uint64_t ip) {
    char b[32]; std::snprintf(b, sizeof(b), "0x%llx", (unsigned long long)ip);
    return b;
}

// =================== DWARF Symbolizer (SAFE) ===================
class DwflSymbolizer {
public:
    DwflSymbolizer() : dwfl_(nullptr) {}
    ~DwflSymbolizer() { if (dwfl_) dwfl_end(dwfl_); }

    bool init_for_self() {
        Dwfl_Callbacks cb{};
        cb.find_elf       = dwfl_linux_proc_find_elf;
        cb.find_debuginfo = dwfl_standard_find_debuginfo;
        dwfl_ = dwfl_begin(&cb);
        if (!dwfl_) return false;
        if (dwfl_linux_proc_report(dwfl_, getpid()) != 0) return false;
        if (dwfl_report_end(dwfl_, nullptr, nullptr) != 0) return false;
        return true;
    }

    // Full label for stacks: "module!function+0xOFF" or fallbacks.
    std::string frame_label(uint64_t ip) const {
        // Try safe DWFL path; otherwise fallback.
        std::string mod, func_with_off;
        if (safe_lookup_(ip, /*want_offset=*/true, mod, func_with_off)) {
            if (!func_with_off.empty()) return mod.empty() ? func_with_off : (mod + "!" + func_with_off);
            if (!mod.empty()) return mod + "!" + hex_addr(ip);
            return hex_addr(ip);
        }
        // fallback via dladdr
        Dl_info info{};
        if (dladdr(reinterpret_cast<void*>(ip), &info) && info.dli_fname) {
            std::string m = basename_of(info.dli_fname);
            return m.empty() ? hex_addr(ip) : (m + "!" + hex_addr(ip));
        }
        return hex_addr(ip);
    }

    // Canonical function key: "module!function" (no offsets), normalized.
    std::string func_key(uint64_t ip) const {
        auto it = cache_.find(ip);
        if (it != cache_.end()) return it->second;

        std::string mod, func;
        // Try DWFL (safe)
        if (safe_lookup_(ip, /*want_offset=*/false, mod, func)) {
            std::string key;
            if (!func.empty()) {
                key = mod.empty() ? func : (mod + "!" + func);
            } else {
                key = mod.empty() ? hex_addr(ip) : (mod + "!" + hex_addr(ip));
            }
            cache_.emplace(ip, key);
            return key;
        }

        // Fallback: dladdr
        Dl_info info{};
        if (dladdr(reinterpret_cast<void*>(ip), &info) && info.dli_fname) {
            std::string m = basename_of(info.dli_fname);
            std::string key = m.empty() ? hex_addr(ip) : (m + "!" + hex_addr(ip));
            cache_.emplace(ip, key);
            return key;
        }
        std::string key = hex_addr(ip);
        cache_.emplace(ip, key);
        return key;
    }

private:
    Dwfl* dwfl_;
    mutable std::unordered_map<uint64_t, std::string> cache_;

    static const char* module_name_(Dwfl_Module* mod) {
        if (!mod) return nullptr;
        return dwfl_module_info(mod, nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr);
    }
    static std::string mod_basename_(const char* modname) {
        if (!modname) return {};
        if (is_bracketed_module_name(modname)) return std::string(modname);
        return basename_of(modname);
    }

    // Canonicalize function names (strip suffix noise).
    static inline void remove_all(std::string& s, std::string_view what) {
        for (;;) { auto p = s.find(what); if (p==std::string::npos) break; s.erase(p, what.size()); }
    }
    static inline void strip_after(std::string& s, char ch) {
        auto p = s.find(ch); if (p != std::string::npos) s.resize(p);
    }
    static std::string canonicalize_function_(std::string name) {
        if (name.empty()) return name;
        strip_after(name, '+'); // drop offsets if any
        // strip common compiler/linker noise
        static const std::string junk[] = {
            ".cold", ".part", ".clone", ".plt", "._plt", "@plt",
            ".__omp_outlined__", ".__omp_outlined.", "._omp_fn.", "._omp_fn",
            ".isra.", ".constprop.", ".constprop", ".isra", ".llvm.", ".lto_priv.", ".lto_priv",
            ".thunk", "_thunk", " thunk"
        };
        for (const auto& j : junk) remove_all(name, j);
        strip_after(name, '@'); // GLIBC versioning if it sneaks in
        while (!name.empty() && isspace((unsigned char)name.back())) name.pop_back();
        return name;
    }

    // SAFE DWFL lookup. Returns true if DWFL was used (even if function empty).
    // Outputs:
    //   mod_out  = module basename or bracketed name (never nullptr)
    //   func_out = demangled function (canonicalized), "" if unknown
    bool safe_lookup_(uint64_t ip, bool want_offset,
                      std::string& mod_out, std::string& func_out) const {
        mod_out.clear(); func_out.clear();
        if (!dwfl_) return false;

        Dwfl_Module* mod = dwfl_addrmodule(dwfl_, (Dwarf_Addr)ip);
        const char* modname = module_name_(mod);
        mod_out = mod_basename_(modname);

        // If no module OR pseudo-module (e.g., [vdso], [anon]), do not call DWFL module APIs.
        if (!mod || is_bracketed_module_name(modname)) return true; // DWFL used, but no symbolization

        // Only call deeper DWFL APIs if module has an ELF handle.
        Elf* elf = dwfl_module_getelf(mod, nullptr);
        if (!elf) {
            // We still can try addrname; in practice addrname may work even without ELF,
            // but to be maximally safe (given your crash), guard it behind elf!=nullptr.
            return true; // DWFL used; no function
        }

        // Get a function name
        const char* nm = dwfl_module_addrname(mod, (Dwarf_Addr)ip);
        if (nm && *nm) {
            std::string pretty = demangle(nm);
            if (want_offset) {
                // Append +offset if we can determine it safely
                GElf_Sym sym{}; GElf_Off off = 0;
                if (dwfl_module_addrinfo(mod, (Dwarf_Addr)ip, &sym, &off, nullptr, nullptr, nullptr) == 0) {
                    if (sym.st_value && (uint64_t)ip > sym.st_value) {
                        char buf[32];
                        std::snprintf(buf, sizeof(buf), "+0x%llx",
                                      (unsigned long long)((uint64_t)ip - (uint64_t)sym.st_value));
                        pretty += buf;
                    }
                }
            }
            func_out = want_offset ? pretty : canonicalize_function_(pretty);
            return true;
        }

        // As a last DWFL attempt: try addrinfo just to validate symbol range (still guarded by elf!=nullptr)
        if (!want_offset) {
            GElf_Sym sym{}; GElf_Off off = 0;
            if (dwfl_module_addrinfo(mod, (Dwarf_Addr)ip, &sym, &off, nullptr, nullptr, nullptr) == 0) {
                if (sym.st_name) {
                    // We don't have the name string here easily; leave func empty.
                }
            }
        }
        return true;
    }
};

// =================== Perf ring & sampling ===================
struct PerfRB {
    int fd{-1};
    void* base{nullptr};
    size_t pg{size_t(sysconf(_SC_PAGESIZE))};
    size_t n_pages{512};
    perf_event_mmap_page* meta{nullptr};
    uint8_t* data{nullptr};
    size_t data_sz{0};

    bool map() {
        size_t map_sz = (n_pages + 1) * pg;
        void* p = mmap(nullptr, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) { perror("mmap"); return false; }
        base = p; meta = reinterpret_cast<perf_event_mmap_page*>(base);
        data = reinterpret_cast<uint8_t*>(base) + pg;
        data_sz = n_pages * pg;
        return true;
    }
    void unmap() {
        if (!base) return;
        munmap(base, (n_pages + 1) * pg);
        base = nullptr; meta = nullptr; data = nullptr; data_sz = 0;
    }
    uint64_t head() const { uint64_t h = meta->data_head; __sync_synchronize(); return h; }
    void set_tail(uint64_t t) { __sync_synchronize(); meta->data_tail = t; }
};

struct HashVec {
    size_t operator()(const std::vector<uint64_t>& v) const {
        size_t h = 1469598103934665603ull;
        for (auto x : v) { h ^= x + 0x9e3779b97f4a7c15ull + (h<<6) + (h>>2); }
        return h;
    }
};
struct EqVec {
    bool operator()(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) const { return a == b; }
};

// =================== Profiler class ===================
class XeonProfiler {
public:
    struct Options {
        enum class Scope { Thread, Process } scope = Scope::Thread;
        int   freq_hz         = 2000;
        bool  include_kernel  = false;
        bool  force_no_lbr    = false;
        bool  time_task_clock = true; // TASK_CLOCK vs CPU_CLOCK
        int   top_n           = 25;
        std::string collapsed_out = "stacks.collapsed";
    };

    explicit XeonProfiler(const Options& opt) : opt_(opt) {}

    bool setup() {
        if (!dwfl_.init_for_self()) {
            std::cerr << "[warn] libdwfl init failed; names may be poor.\n";
        }
        attach_pid_ = (opt_.scope == Options::Scope::Process ? getpid() : 0);
        attach_cpu_ = -1;
        inherit_    = (opt_.scope == Options::Scope::Process);

        if (!time_.open(StreamKind::TimeNS, !opt_.force_no_lbr,
                        !opt_.include_kernel, inherit_, opt_.freq_hz,
                        attach_pid_, attach_cpu_, opt_.time_task_clock)) {
            if (!time_.open(StreamKind::TimeNS, false,
                            !opt_.include_kernel, inherit_, opt_.freq_hz,
                            attach_pid_, attach_cpu_, opt_.time_task_clock)) {
                perror("perf_event_open(time)");
                return false;
            } else {
                std::cerr << "[info] time: LBR unavailable; using CALLCHAIN.\n";
            }
        }
        if (!cycles_.open(StreamKind::Cycles, !opt_.force_no_lbr,
                          !opt_.include_kernel, inherit_, opt_.freq_hz,
                          attach_pid_, attach_cpu_, /*time_task*/ true)) {
            if (!cycles_.open(StreamKind::Cycles, false,
                              !opt_.include_kernel, inherit_, opt_.freq_hz,
                              attach_pid_, attach_cpu_, /*time_task*/ true)) {
                perror("perf_event_open(cycles)");
                return false;
            } else {
                std::cerr << "[info] cycles: LBR unavailable; using CALLCHAIN.\n";
            }
        }
        return true;
    }

    void start() {
        t0_ = std::chrono::steady_clock::now();
        time_.enable();
        cycles_.enable();
    }
    void stop() {
        cycles_.disable();
        time_.disable();
        t1_ = std::chrono::steady_clock::now();
        drain_all_();
    }

    void report(std::ostream& os) {
        struct Row { std::string fn; __uint128_t tns{0}; __uint128_t cyc{0}; };
        std::vector<Row> rows;
        rows.reserve(std::max(func_time_ns_.size(), func_cycles_.size()) + 8);

        for (auto& kv : func_time_ns_) rows.push_back({kv.first, kv.second, 0});
        for (auto& kv : func_cycles_) {
            auto it = std::find_if(rows.begin(), rows.end(), [&](const Row& r){ return r.fn == kv.first; });
            if (it == rows.end()) rows.push_back({kv.first, 0, kv.second});
            else it->cyc += kv.second;
        }

        auto to_ld = [](__uint128_t v)->long double { return (long double)v; };
        long double total_ns = to_ld(total_time_ns_); if (total_ns == 0) total_ns = 1;
        long double total_cy = to_ld(total_cycles_);  if (total_cy == 0) total_cy = 1;

        std::sort(rows.begin(), rows.end(), [&](const Row& a, const Row& b){
            if (a.tns != b.tns) return a.tns > b.tns;
            return a.cyc > b.cyc;
        });

        const auto wall_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1_ - t0_).count();
        long double wall_ns = (long double)std::chrono::duration_cast<std::chrono::nanoseconds>(t1_ - t0_).count();
        long double util_pct = (opt_.scope == Options::Scope::Thread && opt_.time_task_clock)
                               ? (100.0L * to_ld(total_time_ns_) / (wall_ns ? wall_ns : 1)) : -1.0L;

        os << "========== Hot Functions (Top " << opt_.top_n << ") ==========\n";
        os << "  time: " << (opt_.time_task_clock ? "TASK_CLOCK" : "CPU_CLOCK")
           << " (ns), cycles: HW CPU cycles\n";
        os << "  scope: " << (opt_.scope == Options::Scope::Thread ? "thread" : "process")
           << (opt_.include_kernel ? " (user+kernel)" : " (user-only)") << ", freq=" << opt_.freq_hz << " Hz\n";
        if (util_pct >= 0) os << "  wall: " << wall_ms << " ms, CPU util: " << (double)util_pct << "%\n";
        else               os << "  wall: " << wall_ms << " ms\n";
        if (lost_time_ || lost_cycles_) {
            os << "  [warn] Lost records: time=" << lost_time_ << ", cycles=" << lost_cycles_
               << " (increase ring buffer or lower --freq)\n";
        }
        os << "------------------------------------------------------------\n";
        os << "  #      TIME(ns)    %        CYCLES    %     cycles/ns     Function\n";
        os << "------------------------------------------------------------\n";

        auto fmt_ull = [](__uint128_t v)->unsigned long long { return (unsigned long long)v; };
        int shown = 0;
        for (const auto& r : rows) {
            if (shown++ >= opt_.top_n) break;
            long double t = (long double)r.tns;
            long double c = (long double)r.cyc;
            long double pt = 100.0L * (t / total_ns);
            long double pc = 100.0L * (c / total_cy);
            long double cpn = (t > 0) ? (c / t) : 0.0L;

            char line[512];
            std::snprintf(line, sizeof(line),
                          "  %2d  %12llu  %5.1f  %12llu  %5.1f  %12.3Lf   %s\n",
                          shown,
                          fmt_ull(r.tns), (double)pt,
                          fmt_ull(r.cyc), (double)pc,
                          cpn,
                          r.fn.c_str());
            os << line;
        }
        os << "------------------------------------------------------------\n";
        os << "Totals: time_ns=" << (unsigned long long)total_time_ns_
           << ", cycles=" << (unsigned long long)total_cycles_ << "\n\n";
    }

    bool write_collapsed(const std::string& path) {
        std::ofstream ofs(path);
        if (!ofs) { std::perror("open collapsed output"); return false; }
        for (const auto& kv : stacks_time_) {
            const auto& stk = kv.first;
            __uint128_t w = kv.second;
            if (stk.empty()) continue;
            for (size_t i = 0; i < stk.size(); ++i) {
                if (i) ofs << ';';
                ofs << dwfl_.frame_label(stk[i]);
            }
            ofs << ' ' << (unsigned long long)w << "\n";
        }
        return true;
    }

    template <class F> void run(F&& f) { start(); f(); stop(); }
    ~XeonProfiler() { time_.close_all(); cycles_.close_all(); }

private:
    enum class StreamKind { TimeNS, Cycles };

    struct SampleParser {
        uint64_t sample_type{0};
        uint64_t branch_sample_type{0};
        bool using_lbr{false};

        static inline uint64_t r64(const uint8_t*& p){ uint64_t v; std::memcpy(&v,p,8); p+=8; return v; }
        static inline uint32_t r32(const uint8_t*& p){ uint32_t v; std::memcpy(&v,p,4); p+=4; return v; }

        void parse_to_stack(const uint8_t* payload, size_t len,
                            std::vector<uint64_t>& out_stack,
                            uint64_t& out_leaf_ip,
                            uint64_t& out_weight) const {
            out_stack.clear(); out_leaf_ip = 0; out_weight = 0;
            const uint8_t* p = payload;
            const uint8_t* end = payload + len;

            uint64_t ip = 0;
            if (sample_type & PERF_SAMPLE_IP) ip = r64(p);
            if (sample_type & PERF_SAMPLE_TID) { (void)r32(p); (void)r32(p); }
            if (sample_type & PERF_SAMPLE_TIME){ (void)r64(p); }
            if (sample_type & PERF_SAMPLE_ADDR){ (void)r64(p); }
            if (sample_type & PERF_SAMPLE_ID)  { (void)r64(p); }
            if (sample_type & PERF_SAMPLE_STREAM_ID){ (void)r64(p); }
            if (sample_type & PERF_SAMPLE_CPU) { (void)r32(p); (void)r32(p); }
            if (sample_type & PERF_SAMPLE_PERIOD){ out_weight = r64(p); }

            if ((sample_type & PERF_SAMPLE_BRANCH_STACK) && using_lbr) {
                uint64_t nr = r64(p);
                struct perf_branch_entry { uint64_t from, to, flags; };
                out_stack.reserve((size_t)nr);
                for (uint64_t i = 0; i < nr && p + sizeof(perf_branch_entry) <= end; ++i) {
                    perf_branch_entry be{};
                    std::memcpy(&be, p, sizeof(be)); p += sizeof(be);
                    if (be.to) out_stack.push_back(be.to);
                }
                if (!out_stack.empty()) { out_leaf_ip = out_stack.back(); return; }
            }

            if (sample_type & PERF_SAMPLE_CALLCHAIN) {
                uint64_t nr = r64(p);
                out_stack.reserve((size_t)nr);
                for (uint64_t i = 0; i < nr && p + 8 <= end; ++i) {
                    uint64_t addr = r64(p);
                    if (addr) out_stack.push_back(addr);
                }
                if (!out_stack.empty()) { out_leaf_ip = out_stack.front(); return; }
            }

            out_leaf_ip = ip;
        }
    };

    struct Stream {
        StreamKind kind;
        int fd{-1};
        PerfRB rb;
        SampleParser parser;

        bool open(StreamKind k, bool use_lbr, bool user_only, bool inherit, int freq_hz,
                  pid_t attach_pid, int attach_cpu, bool time_task_clock) {
            kind = k;
            perf_event_attr a{};
            a.size = sizeof(a);
            a.disabled = 1;
            a.freq = 1;
            a.sample_freq = freq_hz;
            a.wakeup_events = 64;
            a.exclude_kernel = user_only ? 1 : 0;
            a.exclude_hv = 1;
            a.inherit = inherit ? 1 : 0;

            if (kind == StreamKind::TimeNS) {
                a.type = PERF_TYPE_SOFTWARE;
                a.config = time_task_clock ? PERF_COUNT_SW_TASK_CLOCK : PERF_COUNT_SW_CPU_CLOCK;
                a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_PERIOD;
            } else {
                a.type = PERF_TYPE_HARDWARE;
                a.config = PERF_COUNT_HW_CPU_CYCLES;
                a.precise_ip = 2;
                a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_PERIOD;
            }

            if (use_lbr) {
                a.sample_type |= PERF_SAMPLE_BRANCH_STACK;
                a.branch_sample_type =
                    PERF_SAMPLE_BRANCH_USER |
                    PERF_SAMPLE_BRANCH_CALL_STACK |
                    PERF_SAMPLE_BRANCH_NO_FLAGS |
                    PERF_SAMPLE_BRANCH_NO_CYCLES;
            } else {
                a.sample_type |= PERF_SAMPLE_CALLCHAIN;
                a.sample_max_stack = 256;
            }

            fd = perf_event_open(&a, attach_pid, attach_cpu, -1, 0);
            if (fd < 0) return false;
            rb.fd = fd;
            if (!rb.map()) return false;

            parser.sample_type = a.sample_type;
            parser.branch_sample_type = a.branch_sample_type;
            parser.using_lbr = use_lbr;
            return true;
        }

        void enable()  { if (fd >= 0) ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }
        void disable() { if (fd >= 0) ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }

        template <class FnSample, class FnLost>
        void drain(FnSample&& on_sample, FnLost&& on_lost) {
            uint64_t head = rb.head();
            uint64_t tail = rb.meta->data_tail;

            while (tail < head) {
                uint64_t off = tail % rb.data_sz;
                auto* eh = reinterpret_cast<perf_event_header*>(rb.data + off);

                auto handle = [&](const uint8_t* rec, size_t sz) {
                    switch (eh->type) {
                        case PERF_RECORD_SAMPLE:
                            on_sample(parser, rec + sizeof(perf_event_header), sz - sizeof(perf_event_header));
                            break;
                        case PERF_RECORD_LOST: {
                            const uint8_t* p = rec + sizeof(perf_event_header);
                            uint64_t id, lost; std::memcpy(&id, p, 8); p += 8; std::memcpy(&lost, p, 8);
                            on_lost(lost);
                            break;
                        }
                        default: break;
                    }
                };

                if (off + eh->size <= rb.data_sz) {
                    handle(reinterpret_cast<const uint8_t*>(eh), eh->size);
                } else {
                    std::vector<uint8_t> tmp(eh->size);
                    size_t first = rb.data_sz - off;
                    std::memcpy(tmp.data(), eh, first);
                    std::memcpy(tmp.data() + first, rb.data, eh->size - first);
                    handle(tmp.data(), eh->size);
                }
                tail += eh->size;
            }
            rb.set_tail(tail);
        }

        void close_all() {
            rb.unmap();
            if (fd >= 0) { close(fd); fd = -1; }
        }
    };

    void drain_all_() {
        auto on_sample = [&](Stream& s, const SampleParser& parser,
                             const uint8_t* payload, size_t len) {
            std::vector<uint64_t> stack;
            uint64_t leaf = 0, w = 0;
            parser.parse_to_stack(payload, len, stack, leaf, w);
            if (w == 0) w = 1;

            const std::string fn = dwfl_.func_key(leaf);
            if (s.kind == StreamKind::TimeNS) {
                func_time_ns_[fn] += w;
                total_time_ns_    += w;
                if (!stack.empty()) stacks_time_[stack] += w;
            } else {
                func_cycles_[fn] += w;
                total_cycles_    += w;
            }
        };

        time_.drain(
            [&](const SampleParser& p, const uint8_t* rec, size_t sz){ on_sample(time_, p, rec, sz); },
            [&](uint64_t lost){ lost_time_ += lost; }
        );
        cycles_.drain(
            [&](const SampleParser& p, const uint8_t* rec, size_t sz){ on_sample(cycles_, p, rec, sz); },
            [&](uint64_t lost){ lost_cycles_ += lost; }
        );
    }

private:
    Options opt_;
    pid_t attach_pid_{0};
    int   attach_cpu_{-1};
    bool  inherit_{false};

    enum class StreamKind { TimeNS, Cycles };
    Stream time_{}, cycles_{};
    DwflSymbolizer dwfl_;

    std::unordered_map<std::string, __uint128_t> func_time_ns_;
    std::unordered_map<std::string, __uint128_t> func_cycles_;
    std::unordered_map<std::vector<uint64_t>, __uint128_t, HashVec, EqVec> stacks_time_;
    __uint128_t total_time_ns_{0}, total_cycles_{0};
    uint64_t    lost_time_{0},   lost_cycles_{0};
    std::chrono::steady_clock::time_point t0_{}, t1_{};
};

// =================== Demo workload + CLI ===================
static inline uint64_t hot_work(uint64_t n) {
    volatile uint64_t s = 0;
    for (uint64_t i = 0; i < n; ++i) {
        s += (i * 11400714819323198485ull) ^ (s + 0x9e3779b97f4a7c15ull);
    }
    return s;
}
static void mark_region() {
    uint64_t acc = 0;
    for (int r = 0; r < 40; ++r) acc ^= hot_work(120'000);
    (void)acc;
}

struct Args {
    XeonProfiler::Options::Scope scope = XeonProfiler::Options::Scope::Thread;
    int freq = 2000;
    std::string outfile = "stacks.collapsed";
    int top = 25;
    bool include_kernel = false;
    bool force_no_lbr = false;
    bool time_task_clock = true;
};
static void usage(const char* argv0) {
    std::cerr <<
      "Usage: " << argv0 << " [--scope thread|process] [--freq Hz] [--outfile path]\n"
      "                 [--top N] [--kernel] [--no-lbr] [--time-source task|cpu]\n";
}
static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string_view s(argv[i]);
        auto next = [&](int& i)->std::string { if (i+1 >= argc) { usage(argv[0]); std::exit(2);} return argv[++i]; };
        if (s == "--scope") {
            auto v = next(i);
            if (v == "thread") a.scope = XeonProfiler::Options::Scope::Thread;
            else if (v == "process") a.scope = XeonProfiler::Options::Scope::Process;
            else { std::cerr << "Unknown scope: " << v << "\n"; return false; }
        } else if (s == "--freq") {
            a.freq = std::stoi(next(i));
        } else if (s == "--outfile") {
            a.outfile = next(i);
        } else if (s == "--top") {
            a.top = std::stoi(next(i));
        } else if (s == "--kernel") {
            a.include_kernel = true;
        } else if (s == "--no-lbr") {
            a.force_no_lbr = true;
        } else if (s == "--time-source") {
            auto v = next(i);
            if (v == "task") a.time_task_clock = true;
            else if (v == "cpu") a.time_task_clock = false;
            else { std::cerr << "Unknown time-source: " << v << "\n"; return false; }
        } else if (s == "--help" || s == "-h") {
            usage(argv[0]); std::exit(0);
        } else {
            std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); return false;
        }
    }
    return true;
}

int main(int argc, char** argv) {
    Args a;
    if (!parse_args(argc, argv, a)) return 2;

    XeonProfiler::Options opt;
    opt.scope          = a.scope;
    opt.freq_hz        = a.freq;
    opt.collapsed_out  = a.outfile;
    opt.top_n          = a.top;
    opt.include_kernel = a.include_kernel;
    opt.force_no_lbr   = a.force_no_lbr;
    opt.time_task_clock= a.time_task_clock;

    XeonProfiler prof(opt);
    if (!prof.setup()) return 1;

    // Warm-up (not measured)
    hot_work(2'000'000);

    prof.start();
    mark_region();
    prof.stop();

    prof.report(std::cout);
    if (!opt.collapsed_out.empty()) {
        prof.write_collapsed(opt.collapsed_out);
        std::cout << "Collapsed stacks (time-weighted) written to: " << opt.collapsed_out
                  << "\nHint: perl flamegraph.pl --countname ns " << opt.collapsed_out << " > flame.svg\n";
    }
    return 0;
}
