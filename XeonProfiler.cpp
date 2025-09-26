// xeon_profiler_safe_symbols.cpp
// Perf-based profiler (Xeon-friendly) with crash-proof symbolization.
// Default: dladdr() only. Optional: --sym dwfl to try libdwfl guardedly.
// If DWFL misbehaves on your host, stay with the default (dladdr).

#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
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

#if defined(ENABLE_DWFL)
  #include <elfutils/libdwfl.h>
#endif

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
static inline bool is_bracketed_module(const char* name) { return name && name[0] == '['; }
static std::string hex_addr(uint64_t ip) { char b[32]; std::snprintf(b,sizeof(b),"0x%llx",(unsigned long long)ip); return b; }

// ---------------- Symbolizers ----------------
struct DladdrSymbolizer {
    std::string frame_label(uint64_t ip) const {
        Dl_info info{};
        if (dladdr(reinterpret_cast<void*>(ip), &info) && info.dli_fname) {
            std::string mod = basename_of(info.dli_fname);
            std::string fn;
            if (info.dli_sname) {
                fn = demangle(info.dli_sname);
                uintptr_t off = uintptr_t(ip) - uintptr_t(info.dli_saddr);
                if (off) { char b[32]; std::snprintf(b,sizeof(b),"+0x%zx", size_t(off)); fn += b; }
            }
            if (!fn.empty()) return mod.empty()? fn : (mod+"!"+fn);
            return mod.empty()? hex_addr(ip) : (mod+"!"+hex_addr(ip));
        }
        return hex_addr(ip);
    }
    std::string func_key(uint64_t ip) const {
        Dl_info info{};
        if (dladdr(reinterpret_cast<void*>(ip), &info) && info.dli_fname) {
            std::string mod = basename_of(info.dli_fname);
            if (info.dli_sname) {
                std::string fn = demangle(info.dli_sname);
                normalize(fn);
                return mod.empty()? fn : (mod+"!"+fn);
            }
            return mod.empty()? hex_addr(ip) : (mod+"!"+hex_addr(ip));
        }
        return hex_addr(ip);
    }
    static void normalize(std::string& s) {
        auto strip_after = [&](char ch){ auto p=s.find(ch); if(p!=std::string::npos) s.resize(p); };
        auto remove_all = [&](std::string_view what){
            for(;;){ auto p=s.find(what); if(p==std::string::npos) break; s.erase(p, what.size()); }
        };
        strip_after('+'); strip_after('@');
        static const std::string junk[] = { ".cold",".part",".clone",".plt","@plt",".isra.",".constprop.",".llvm.","._omp_fn",".__omp_outlined__" };
        for (auto& j: junk) remove_all(j);
        while(!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
    }
};

#if defined(ENABLE_DWFL)
struct DwflSafeSymbolizer {
    DwflSafeSymbolizer(): dwfl_(nullptr) {}
    ~DwflSafeSymbolizer(){ if(dwfl_) dwfl_end(dwfl_); }
    bool init() {
        Dwfl_Callbacks cb{}; cb.find_elf = dwfl_linux_proc_find_elf; cb.find_debuginfo = dwfl_standard_find_debuginfo;
        dwfl_ = dwfl_begin(&cb);
        if(!dwfl_) return false;
        if (dwfl_linux_proc_report(dwfl_, getpid()) != 0) return false;
        if (dwfl_report_end(dwfl_, nullptr, nullptr) != 0) return false;
        return true;
    }
    // Only uses addrname() and only on non-bracketed modules; otherwise falls back to dladdr
    std::string frame_label(uint64_t ip) const {
        Dl_info dli{};
        (void)dladdr(reinterpret_cast<void*>(ip), &dli);
        if (dli.dli_fname && !is_bracketed_module(dli.dli_fname)) {
            Dwfl_Module* mod = dwfl_addrmodule(dwfl_, (Dwarf_Addr)ip);
            if (mod) {
                const char* nm = dwfl_module_addrname(mod, (Dwarf_Addr)ip);
                if (nm && *nm) {
                    std::string fn = demangle(nm);
                    if (dli.dli_saddr) {
                        uintptr_t off = uintptr_t(ip) - uintptr_t(dli.dli_saddr);
                        if (off) { char b[32]; std::snprintf(b,sizeof(b),"+0x%zx", size_t(off)); fn += b; }
                    }
                    std::string modb = basename_of(dli.dli_fname);
                    return modb.empty()? fn : (modb+"!"+fn);
                }
            }
        }
        // fallback: dladdr
        return DladdrSymbolizer{}.frame_label(ip);
    }
    std::string func_key(uint64_t ip) const {
        Dl_info dli{};
        (void)dladdr(reinterpret_cast<void*>(ip), &dli);
        if (dli.dli_fname && !is_bracketed_module(dli.dli_fname)) {
            Dwfl_Module* mod = dwfl_addrmodule(dwfl_, (Dwarf_Addr)ip);
            if (mod) {
                const char* nm = dwfl_module_addrname(mod, (Dwarf_Addr)ip);
                if (nm && *nm) {
                    std::string fn = demangle(nm);
                    DladdrSymbolizer::normalize(fn);
                    std::string modb = basename_of(dli.dli_fname);
                    return modb.empty()? fn : (modb+"!"+fn);
                }
            }
        }
        return DladdrSymbolizer{}.func_key(ip);
    }
private:
    Dwfl* dwfl_;
};
#endif

// --------------- Perf ring buffer & sampler ---------------
struct PerfRB {
    int fd{-1};
    void* base{nullptr};
    size_t pg{size_t(sysconf(_SC_PAGESIZE))};
    size_t n_pages{512};
    perf_event_mmap_page* meta{nullptr};
    uint8_t* data{nullptr};
    size_t data_sz{0};
    bool map(){ size_t m=(n_pages+1)*pg; void* p=mmap(nullptr,m,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
        if(p==MAP_FAILED){perror("mmap");return false;} base=p; meta=(perf_event_mmap_page*)base;
        data=(uint8_t*)base+pg; data_sz=n_pages*pg; return true; }
    void unmap(){ if(!base) return; munmap(base,(n_pages+1)*pg); base=nullptr; meta=nullptr; data=nullptr; data_sz=0; }
    uint64_t head() const { uint64_t h=meta->data_head; __sync_synchronize(); return h; }
    void set_tail(uint64_t t){ __sync_synchronize(); meta->data_tail=t; }
};

struct HashVec { size_t operator()(const std::vector<uint64_t>& v) const {
    size_t h=1469598103934665603ull; for(auto x:v){ h^=x + 0x9e3779b97f4a7c15ull + (h<<6)+(h>>2);} return h; } };
struct EqVec { bool operator()(const std::vector<uint64_t>& a,const std::vector<uint64_t>& b) const { return a==b; } };

class XeonProfiler {
public:
    struct Options {
        enum class Scope { Thread, Process } scope = Scope::Thread;
        int   freq_hz = 2000;
        bool  include_kernel = false;
        bool  force_no_lbr = false;
        bool  time_task_clock = true;
        int   top_n = 25;
        std::string collapsed_out = "stacks.collapsed";
        enum class Sym { dladdr, dwfl } sym = Sym::dladdr; // default safe
    };

    explicit XeonProfiler(const Options& o): opt(o) {
#if defined(ENABLE_DWFL)
        if (opt.sym == Options::Sym::dwfl) {
            if (!dwfl.init()) {
                std::cerr << "[warn] DWFL init failed; falling back to dladdr.\n";
                opt.sym = Options::Sym::dladdr;
            }
        }
#else
        opt.sym = Options::Sym::dladdr;
#endif
    }

    bool setup() {
        attach_pid = (opt.scope==Options::Scope::Process ? getpid() : 0);
        inherit = (opt.scope==Options::Scope::Process);
        if (!open_stream(timeS, true)) {
            if (!open_stream(timeS, false)) { perror("perf_event_open(time)"); return false; }
            else std::cerr<<"[info] time: LBR unavailable; using CALLCHAIN.\n";
        }
        if (!open_stream(cycS, true)) {
            if (!open_stream(cycS, false))  { perror("perf_event_open(cycles)"); return false; }
            else std::cerr<<"[info] cycles: LBR unavailable; using CALLCHAIN.\n";
        }
        return true;
    }

    void start(){ t0=std::chrono::steady_clock::now(); enable(timeS); enable(cycS); }
    void stop(){  disable(cycS); disable(timeS); t1=std::chrono::steady_clock::now(); drain_all(); }

    void report(std::ostream& os) {
        struct Row { std::string fn; __uint128_t tns{0}, cyc{0}; };
        std::vector<Row> rows; rows.reserve(std::max(func_time.size(), func_cyc.size())+8);
        for (auto& kv: func_time) rows.push_back({kv.first, kv.second, 0});
        for (auto& kv: func_cyc) {
            auto it = std::find_if(rows.begin(),rows.end(),[&](const Row& r){return r.fn==kv.first;});
            if (it==rows.end()) rows.push_back({kv.first,0,kv.second}); else it->cyc += kv.second;
        }
        auto told=[](__uint128_t v){return (long double)v;};
        long double T = std::max<told(0)>(told(total_time)?told(total_time):1);
        long double C = std::max<told(0)>(told(total_cycles)?told(total_cycles):1);
        std::sort(rows.begin(),rows.end(),[](const Row& a,const Row& b){ if(a.tns!=b.tns) return a.tns>b.tns; return a.cyc>b.cyc; });

        auto wall_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count();
        os<<"========== Hot Functions (Top "<<opt.top_n<<") ==========\n";
        os<<"  time="<<(opt.time_task_clock?"TASK_CLOCK":"CPU_CLOCK")<<" (ns), cycles=HW CPU cycles\n";
        os<<"  scope: "<<(opt.scope==Options::Scope::Thread?"thread":"process")
          <<(opt.include_kernel?" (user+kernel)":" (user-only)")<<", freq="<<opt.freq_hz<<" Hz\n";
        os<<"  wall: "<<wall_ms<<" ms\n";
        if (lost_time || lost_cycles) os<<"  [warn] Lost records: time="<<lost_time<<", cycles="<<lost_cycles<<"\n";
        os<<"------------------------------------------------------------\n";
        os<<"  #      TIME(ns)    %        CYCLES    %     cycles/ns     Function\n";
        os<<"------------------------------------------------------------\n";
        auto u64=[](__uint128_t v){return (unsigned long long)v;};
        int shown=0;
        for (auto& r: rows) {
            if (shown++>=opt.top_n) break;
            long double pt=100.0L*((long double)r.tns/T), pc=100.0L*((long double)r.cyc/C);
            long double cpn = (r.tns? (long double)r.cyc/(long double)r.tns : 0.0L);
            char line[512];
            std::snprintf(line,sizeof(line),"  %2d  %12llu  %5.1f  %12llu  %5.1f  %12.3Lf   %s\n",
                          shown,u64(r.tns),(double)pt,u64(r.cyc),(double)pc,cpn,r.fn.c_str());
            os<<line;
        }
        os<<"------------------------------------------------------------\n";
        os<<"Totals: time_ns="<<(unsigned long long)total_time<<", cycles="<<(unsigned long long)total_cycles<<"\n\n";
    }

    bool write_collapsed(const std::string& path) {
        std::ofstream ofs(path); if(!ofs){ perror("open collapsed"); return false; }
        for (auto& kv : stacks_time) {
            const auto& stk=kv.first; if (stk.empty()) continue;
            for (size_t i=0;i<stk.size();++i){ if(i) ofs<<';'; ofs<<frame_label(stk[i]); }
            ofs<<' '<<(unsigned long long)kv.second<<"\n";
        }
        return true;
    }

private:
    enum class StreamKind { Time, Cycles };
    struct Stream {
        StreamKind kind; int fd{-1}; PerfRB rb; uint64_t sample_type{0}; uint64_t branch_sample_type{0}; bool using_lbr{false};
    };
    Options opt;
    pid_t attach_pid{0}; bool inherit{false};
    Stream timeS{StreamKind::Time}, cycS{StreamKind::Cycles};
    std::chrono::steady_clock::time_point t0{}, t1{};

#if defined(ENABLE_DWFL)
    DwflSafeSymbolizer dwfl;
#endif
    DladdrSymbolizer   dlsymb;

    // aggregation
    std::unordered_map<std::string,__uint128_t> func_time, func_cyc;
    std::unordered_map<std::vector<uint64_t>,__uint128_t,HashVec,EqVec> stacks_time;
    __uint128_t total_time{0}, total_cycles{0};
    uint64_t lost_time{0}, lost_cycles{0};

    // symbol helpers
    std::string frame_label(uint64_t ip) const {
#if defined(ENABLE_DWFL)
        if (opt.sym == Options::Sym::dwfl) return dwfl.frame_label(ip);
#endif
        return dlsymb.frame_label(ip);
    }
    std::string func_key(uint64_t ip) const {
#if defined(ENABLE_DWFL)
        if (opt.sym == Options::Sym::dwfl) return dwfl.func_key(ip);
#endif
        return dlsymb.func_key(ip);
    }

    // perf helpers
    bool open_stream(Stream& s, bool try_lbr) {
        perf_event_attr a{};
        a.size = sizeof(a); a.disabled=1; a.freq=1; a.sample_freq=opt.freq_hz; a.wakeup_events=64;
        a.exclude_kernel = opt.include_kernel?0:1; a.exclude_hv=1; a.inherit = inherit?1:0;
        if (s.kind==StreamKind::Time) { a.type=PERF_TYPE_SOFTWARE; a.config=opt.time_task_clock?PERF_COUNT_SW_TASK_CLOCK:PERF_COUNT_SW_CPU_CLOCK; }
        else { a.type=PERF_TYPE_HARDWARE; a.config=PERF_COUNT_HW_CPU_CYCLES; a.precise_ip=2; }
        a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_PERIOD;
        if (try_lbr && !opt.force_no_lbr) {
            a.sample_type |= PERF_SAMPLE_BRANCH_STACK;
            a.branch_sample_type = PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_CALL_STACK |
                                   PERF_SAMPLE_BRANCH_NO_FLAGS | PERF_SAMPLE_BRANCH_NO_CYCLES;
        } else {
            a.sample_type |= PERF_SAMPLE_CALLCHAIN;
            a.sample_max_stack = 256;
        }
        int pid = (opt.scope==Options::Scope::Process? getpid() : 0);
        s.fd = perf_event_open(&a, pid, -1, -1, 0); if (s.fd<0) return false;
        s.rb.fd = s.fd; if(!s.rb.map()) return false;
        s.sample_type = a.sample_type; s.branch_sample_type=a.branch_sample_type; s.using_lbr = (a.sample_type & PERF_SAMPLE_BRANCH_STACK);
        return true;
    }
    static void enable(Stream& s){ if(s.fd>=0) ioctl(s.fd, PERF_EVENT_IOC_ENABLE, 0); }
    static void disable(Stream& s){ if(s.fd>=0) ioctl(s.fd, PERF_EVENT_IOC_DISABLE, 0); }

    void drain_one(Stream& s, const uint8_t* rec, size_t sz) {
        auto r64=[&](const uint8_t*&p){ uint64_t v; std::memcpy(&v,p,8); p+=8; return v; };
        auto r32=[&](const uint8_t*&p){ uint32_t v; std::memcpy(&v,p,4); p+=4; return v; };

        const uint8_t* p = rec; const uint8_t* end = rec + sz;
        uint64_t ip=0, w=0; std::vector<uint64_t> stack;

        if (s.sample_type & PERF_SAMPLE_IP) ip=r64(p);
        if (s.sample_type & PERF_SAMPLE_TID) { (void)r32(p); (void)r32(p); }
        if (s.sample_type & PERF_SAMPLE_TIME) { (void)r64(p); }
        if (s.sample_type & PERF_SAMPLE_ADDR) { (void)r64(p); }
        if (s.sample_type & PERF_SAMPLE_ID) { (void)r64(p); }
        if (s.sample_type & PERF_SAMPLE_STREAM_ID) { (void)r64(p); }
        if (s.sample_type & PERF_SAMPLE_CPU) { (void)r32(p); (void)r32(p); }
        if (s.sample_type & PERF_SAMPLE_PERIOD) { w=r64(p); if (!w) w=1; }

        if ((s.sample_type & PERF_SAMPLE_BRANCH_STACK) && s.using_lbr) {
            uint64_t nr = r64(p);
            struct perf_branch_entry { uint64_t from,to,flags; };
            stack.reserve((size_t)nr);
            for (uint64_t i=0;i<nr && p+sizeof(perf_branch_entry)<=end; ++i) {
                perf_branch_entry be{}; std::memcpy(&be,p,sizeof(be)); p+=sizeof(be);
                if (be.to) stack.push_back(be.to);
            }
        } else if (s.sample_type & PERF_SAMPLE_CALLCHAIN) {
            uint64_t nr = r64(p);
            stack.reserve((size_t)nr);
            for (uint64_t i=0;i<nr && p+8<=end; ++i) { uint64_t a=r64(p); if (a) stack.push_back(a); }
        }

        // aggregate
        std::string key = func_key(stack.empty()? ip : ( (s.sample_type&PERF_SAMPLE_BRANCH_STACK) ? stack.back() : stack.front() ));
        if (s.kind==StreamKind::Time) {
            func_time[key]+=w; total_time+=w;
            if (!stack.empty()) stacks_time[stack]+=w;
        } else {
            func_cyc[key]+=w; total_cycles+=w;
        }
    }

    void drain_all() {
        auto drain=[&](Stream& s, uint64_t& lost_counter){
            uint64_t head=s.rb.head(), tail=s.rb.meta->data_tail;
            while (tail < head) {
                uint64_t off = tail % s.rb.data_sz;
                auto* eh = reinterpret_cast<perf_event_header*>(s.rb.data + off);
                auto handle = [&](const uint8_t* rec, size_t sz){
                    switch(eh->type){
                        case PERF_RECORD_SAMPLE: drain_one(s, rec + sizeof(*eh), sz - sizeof(*eh)); break;
                        case PERF_RECORD_LOST: {
                            const uint8_t* p = rec + sizeof(*eh);
                            uint64_t id, lost; std::memcpy(&id,p,8); p+=8; std::memcpy(&lost,p,8);
                            lost_counter += lost; break;
                        }
                        default: break;
                    }
                };
                if (off + eh->size <= s.rb.data_sz) handle((const uint8_t*)eh, eh->size);
                else {
                    std::vector<uint8_t> tmp(eh->size);
                    size_t first = s.rb.data_sz - off;
                    std::memcpy(tmp.data(), eh, first);
                    std::memcpy(tmp.data()+first, s.rb.data, eh->size-first);
                    handle(tmp.data(), eh->size);
                }
                tail += eh->size;
            }
            s.rb.set_tail(tail);
        };
        drain(timeS, lost_time);
        drain(cycS,  lost_cycles);
    }
};

// ---------------- Demo workload & CLI ----------------
static inline uint64_t hot_work(uint64_t n){ volatile uint64_t s=0; for(uint64_t i=0;i<n;++i) s += (i*11400714819323198485ull) ^ (s+0x9e3779b97f4a7c15ull); return s; }
static void mark_region(){ uint64_t a=0; for(int r=0;r<40;++r) a^=hot_work(120'000); (void)a; }

struct Args {
    XeonProfiler::Options::Scope scope = XeonProfiler::Options::Scope::Thread;
    int freq = 2000; std::string outfile="stacks.collapsed"; int top=25;
    bool include_kernel=false, force_no_lbr=false, time_task_clock=true;
    std::string sym = "dladdr"; // or "dwfl" (requires -DENABLE_DWFL and -ldw -lelf)
};

static void usage(const char* argv0){
    std::cerr<<"Usage: "<<argv0<<" [--scope thread|process] [--freq Hz] [--outfile path]\n"
                "                [--top N] [--kernel] [--no-lbr] [--time-source task|cpu]\n"
                "                [--sym dladdr|dwfl]\n";
}
static bool parse_args(int argc, char** argv, Args& a){
    for(int i=1;i<argc;++i){
        std::string_view s(argv[i]); auto next=[&](int& i){ if(i+1>=argc){usage(argv[0]); std::exit(2);} return std::string(argv[++i]); };
        if(s=="--scope"){ auto v=next(i); a.scope = (v=="process")?XeonProfiler::Options::Scope::Process:XeonProfiler::Options::Scope::Thread; }
        else if(s=="--freq"){ a.freq=std::stoi(next(i)); }
        else if(s=="--outfile"){ a.outfile=next(i); }
        else if(s=="--top"){ a.top=std::stoi(next(i)); }
        else if(s=="--kernel"){ a.include_kernel=true; }
        else if(s=="--no-lbr"){ a.force_no_lbr=true; }
        else if(s=="--time-source"){ auto v=next(i); a.time_task_clock=(v=="task"); }
        else if(s=="--sym"){ a.sym=next(i); }
        else if(s=="--help"||s=="-h"){ usage(argv[0]); std::exit(0); }
        else { std::cerr<<"Unknown arg: "<<s<<"\n"; usage(argv[0]); return false; }
    }
    return true;
}

int main(int argc, char** argv){
    Args a; if(!parse_args(argc,argv,a)) return 2;

    XeonProfiler::Options opt;
    opt.scope=a.scope; opt.freq_hz=a.freq; opt.collapsed_out=a.outfile; opt.top_n=a.top;
    opt.include_kernel=a.include_kernel; opt.force_no_lbr=a.force_no_lbr; opt.time_task_clock=a.time_task_clock;
#if defined(ENABLE_DWFL)
    opt.sym = (a.sym=="dwfl")? XeonProfiler::Options::Sym::dwfl : XeonProfiler::Options::Sym::dladdr;
#else
    if (a.sym=="dwfl") std::cerr<<"[warn] Built without DWFL; using dladdr.\n";
    opt.sym = XeonProfiler::Options::Sym::dladdr;
#endif

    XeonProfiler prof(opt);
    if(!prof.setup()) return 1;

    // Warm-up
    hot_work(2'000'000);

    prof.start();
    mark_region();
    prof.stop();

    prof.report(std::cout);
    if (!opt.collapsed_out.empty()) {
        prof.write_collapsed(opt.collapsed_out);
        std::cout<<"Collapsed stacks written to: "<<opt.collapsed_out<<"\n";
    }
    return 0;
}
