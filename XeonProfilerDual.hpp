// xeon_profiler_dual.hpp
// Single-TID dual-sampler (cycles + time) using perf_event_open + mmap rings.
// Build: g++ -std=c++17 -O2 -g -pthread your.cpp -o yourbin
//
// What we record (both samplers):
//   - PERF_RECORD_SAMPLE: IP, PID/TID, TIME, CPU, PERIOD, CALLCHAIN (user only)
//   - PERF_RECORD_LOST  : lost counters
//
// Outputs on dump:
//   - xeon_samples.csv   : "0xIP,count,sum_cycles,sum_time_ns"
//   - xeon_frames.txt    : unique addresses (IPs + all callchain frames)
//   - xeon_stats.txt     : records/loss per stream
//   - xeon_stacks.addr   : optional collapsed stacks by address from CYCLES stream
//   - resolve.gdb        : GDB batch to resolve *on this run*
//
// Usage sketch:
//   xeon::Profiler::init(/*freqHz=*/1000, /*ring_pages=*/4096, /*record_stacks=*/true);
//   {
//     XEON_SCOPE();   // enables sampling in this scope (and its callees) on THIS thread
//     hot_path();
//   }
//   xeon::Profiler::instance().dump_and_pause("xeon_samples.csv","xeon_frames.txt",
//                                             "xeon_stats.txt","xeon_stacks.addr","resolve.gdb");

#ifndef XEON_PROFILER_DUAL_HPP
#define XEON_PROFILER_DUAL_HPP

#include <atomic>
#include <cinttypes>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <fstream>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <string>

namespace xeon {

static inline int perf_event_open(struct perf_event_attr* hw_event,
                                  pid_t pid, int cpu, int group_fd,
                                  unsigned long flags) {
  return static_cast<int>(syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags));
}

struct Ring {
  size_t pg_sz{static_cast<size_t>(::sysconf(_SC_PAGESIZE))};
  size_t data_npg{4096}; // ~16MiB default; tune via init()
  void*  base{nullptr};
  perf_event_mmap_page* meta{nullptr};
  size_t data_sz{0};

  bool map_fd(int fd) {
    data_sz = data_npg * pg_sz;
    base = ::mmap(nullptr, (1 + data_npg) * pg_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { base = nullptr; return false; }
    meta = reinterpret_cast<perf_event_mmap_page*>(base);
    return true;
  }
  void unmap() {
    if (base) { ::munmap(base, (1 + data_npg) * pg_sz); base = nullptr; meta = nullptr; }
  }
  uint8_t* data() const { return reinterpret_cast<uint8_t*>(base) + pg_sz; }
};

enum class StreamKind { Cycles, Time };

struct Stream {
  int fd{-1};
  Ring ring;
  StreamKind kind{StreamKind::Cycles};

  // Stats
  std::atomic<uint64_t> rec_sample{0};
  std::atomic<uint64_t> rec_lost{0};
  std::atomic<uint64_t> lost_samples{0};

  void close_all() {
    ring.unmap();
    if (fd >= 0) { ::close(fd); fd = -1; }
  }
};

// Aggregates across streams
struct Agg {
  // Per-IP: count, sum of cycles, sum of time (ns)
  struct Tot { uint64_t cnt{0}, cyc{0}, ns{0}; };
  std::unordered_map<uint64_t, Tot> by_ip;
  std::unordered_set<uint64_t> frames_unique;

  // Optional collapsed stacks from cycles stream
  bool record_stacks{false};
  std::unordered_map<std::string, uint64_t> collapsed_cycles;

  void add_ip(StreamKind k, uint64_t ip, uint64_t period) {
    auto &t = by_ip[ip];
    t.cnt++;
    if (k == StreamKind::Cycles) t.cyc += period;
    else                          t.ns  += period;
    frames_unique.insert(ip);
  }
  void add_frame(uint64_t addr) {
    if (addr >= (uint64_t)-4096ULL || addr == 0) return; // skip special markers/zero
    frames_unique.insert(addr);
  }
};

class Profiler {
public:
  static Profiler& instance() {
    static Profiler inst;
    return inst;
  }

  static void init(uint32_t freq_hz = 1000, size_t ring_pages = 4096, bool record_stacks=false) {
    auto& I = instance();
    I.freq_hz_ = freq_hz;
    I.ring_pages_ = ring_pages;
    I.want_stacks_ = record_stacks;
  }

  class Scope {
  public:
    explicit Scope(Profiler& P) : prof_(P) {
      prof_.ensure();
      if (!prof_.disabled_) prof_.enable();
    }
    ~Scope() {
      if (!prof_.disabled_) prof_.disable();
    }
  private:
    Profiler& prof_;
  };

  // Dump, emit resolve.gdb, SIGSTOP for same-run GDB symbolization
  void dump_and_pause(const std::string& samples_csv,
                      const std::string& frames_txt,
                      const std::string& stats_txt,
                      const std::string& stacks_addr,  // optional ("" to skip)
                      const std::string& gdb_script,
                      bool pause=true)
  {
    if (!disabled_) {
      disable();
      stop_reader_ = true;
      if (reader_.joinable()) reader_.join();
      cycles_.close_all();
      time_.close_all();
    }

    // Snapshot aggregates
    Agg agg;
    {
      std::lock_guard<std::mutex> lk(mu_);
      agg = agg_;
    }

    // Write samples CSV
    {
      std::ofstream out(samples_csv);
      for (auto &kv : agg.by_ip) {
        const uint64_t ip = kv.first;
        const auto &t = kv.second;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ip);
        out << buf << "," << t.cnt << "," << t.cyc << "," << t.ns << "\n";
      }
    }

    // Write unique frames
    {
      std::vector<uint64_t> v(agg.frames_unique.begin(), agg.frames_unique.end());
      std::sort(v.begin(), v.end());
      std::ofstream out(frames_txt);
      for (auto a : v) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)a);
        out << buf << "\n";
      }
    }

    // Stats
    {
      std::ofstream out(stats_txt);
      out << "[cycles]\n";
      out << "records.sample=" << cycles_.rec_sample.load() << "\n";
      out << "records.lost="   << cycles_.rec_lost.load()   << "\n";
      out << "samples.lost="   << cycles_.lost_samples.load() << "\n";
      out << "[time]\n";
      out << "records.sample=" << time_.rec_sample.load() << "\n";
      out << "records.lost="   << time_.rec_lost.load()   << "\n";
      out << "samples.lost="   << time_.lost_samples.load() << "\n";
    }

    // Collapsed stacks (address form) from cycles stream
    if (!stacks_addr.empty() && agg.record_stacks && !agg.collapsed_cycles.empty()) {
      std::ofstream out(stacks_addr);
      for (auto &kv : agg.collapsed_cycles) {
        out << kv.first << " " << kv.second << "\n";
      }
    }

    // GDB batch script
    {
      std::ofstream out(gdb_script);
      out << "set pagination off\n";
      std::ifstream in(frames_txt);
      std::string addr;
      while (in >> addr) {
        out << "printf \"ADDR " << addr << " -> \"; info symbol " << addr << "\n";
        out << "info line *" << addr << "\n";
      }
    }

    std::cerr << "[XeonProfiler] wrote: " << samples_csv << ", " << frames_txt
              << ", " << stats_txt;
    if (!stacks_addr.empty() && agg.record_stacks) std::cerr << ", " << stacks_addr;
    std::cerr << ", " << gdb_script << "\n";

    if (pause) {
      pid_t pid = ::getpid();
      std::cerr << "[XeonProfiler] PID " << pid << " SIGSTOP. Resolve with:\n"
                << "  gdb -p " << pid << " --batch -x " << gdb_script << " > resolved_raw.txt\n";
      ::raise(SIGSTOP);
    }
  }

private:
  Profiler() = default;
  ~Profiler() = default;

  void ensure() {
    if (created_) return;
    created_ = true;

    // Open cycles sampler
    if (!open_sampler(cycles_, StreamKind::Cycles)) {
      std::cerr << "[XeonProfiler] perf_event_open(CYCLES) failed; profiler disabled.\n";
      disabled_ = true; return;
    }
    // Open time sampler
    if (!open_sampler(time_, StreamKind::Time)) {
      std::cerr << "[XeonProfiler] perf_event_open(TIME) failed; profiler disabled.\n";
      disabled_ = true; return;
    }

    agg_.record_stacks = want_stacks_;
    start_reader();
  }

  bool open_sampler(Stream& s, StreamKind kind) {
    s.kind = kind;

    struct perf_event_attr attr{};
    attr.size = sizeof(attr);
    if (kind == StreamKind::Cycles) {
      attr.type = PERF_TYPE_HARDWARE;
      attr.config = PERF_COUNT_HW_CPU_CYCLES;
    } else {
      attr.type = PERF_TYPE_SOFTWARE;
      attr.config = PERF_COUNT_SW_CPU_CLOCK; // ns on this CPU
    }

    attr.disabled = 1;            // start disabled; scopes will enable both
    attr.inherit = 0;             // single thread only
    attr.exclude_kernel = 1;      // user-space only
    attr.exclude_hv = 1;
    attr.exclude_idle = 1;

    attr.sample_type =
        PERF_SAMPLE_IP |
        PERF_SAMPLE_TID |
        PERF_SAMPLE_TIME |
        PERF_SAMPLE_CPU |
        PERF_SAMPLE_PERIOD |
        PERF_SAMPLE_CALLCHAIN;

    attr.freq = 1;
    attr.sample_freq = freq_hz_;      // e.g. 1000 Hz each stream (can tune)
    attr.precise_ip = 2;              // better attribution if supported
    attr.watermark = 0;

    s.ring.data_npg = ring_pages_;
    s.fd = perf_event_open(&attr, /*pid*/0, /*cpu*/-1, /*group*/-1, PERF_FLAG_FD_CLOEXEC);
    if (s.fd < 0) return false;
    if (!s.ring.map_fd(s.fd)) { ::close(s.fd); s.fd = -1; return false; }
    return true;
  }

  void start_reader() {
    stop_reader_ = false;
    // Initialize tails to current heads to skip any old data
    cycles_tail_ = cycles_.ring.meta->data_head;
    time_tail_   = time_.ring.meta->data_head;

    reader_ = std::thread([this]{
      while (!stop_reader_) {
        drain_stream(cycles_);
        drain_stream(time_);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
      }
      // final drain
      drain_stream(cycles_);
      drain_stream(time_);
    });
  }

  void drain_stream(Stream& s) {
    auto* meta = s.ring.meta;
    auto* data = s.ring.data();
    const size_t size = s.ring.data_sz;

    uint64_t &tail = (s.kind == StreamKind::Cycles) ? cycles_tail_ : time_tail_;

    __sync_synchronize();
    uint64_t head = meta->data_head;

    while (tail != head) {
      size_t off = tail % size;
      auto* hdr = reinterpret_cast<perf_event_header*>(data + off);

      // Copy-with-wrap if needed
      std::vector<uint8_t> tmp;
      const uint8_t* rec = data + off;
      if (off + hdr->size > size) {
        tmp.resize(hdr->size);
        size_t first = size - off;
        std::memcpy(tmp.data(), rec, first);
        std::memcpy(tmp.data() + first, data, hdr->size - first);
        rec = tmp.data();
      }

      if (hdr->type == PERF_RECORD_SAMPLE) {
        s.rec_sample++;
        parse_sample(s.kind, rec, hdr->size);
      } else if (hdr->type == PERF_RECORD_LOST) {
        s.rec_lost++;
        const uint8_t* p = rec + sizeof(perf_event_header);
        p += sizeof(uint64_t); // id
        uint64_t lost; std::memcpy(&lost, p, sizeof(lost));
        s.lost_samples += lost;
      }
      tail += hdr->size;
    }

    __sync_synchronize();
    meta->data_tail = tail;
  }

  void parse_sample(StreamKind kind, const uint8_t* rec, uint16_t /*size*/) {
    const uint8_t* p = rec + sizeof(perf_event_header);

    uint64_t ip;     std::memcpy(&ip, p, sizeof(ip));     p += sizeof(ip);
    uint32_t pid;    std::memcpy(&pid, p, sizeof(pid));   p += sizeof(pid);
    uint32_t tid;    std::memcpy(&tid, p, sizeof(tid));   p += sizeof(tid);
    uint64_t time;   std::memcpy(&time, p, sizeof(time)); p += sizeof(time);
    uint32_t cpu;    std::memcpy(&cpu, p, sizeof(cpu));   p += sizeof(cpu);
    uint32_t resv;   std::memcpy(&resv, p, sizeof(resv)); p += sizeof(resv);
    uint64_t period; std::memcpy(&period, p, sizeof(period)); p += sizeof(period);

    uint64_t nr; std::memcpy(&nr, p, sizeof(nr)); p += sizeof(nr);

    std::lock_guard<std::mutex> lk(mu_);

    // Top frame
    agg_.add_ip(kind, ip, period);

    // Collapsed stacks (from cycles stream only)
    if (want_stacks_ && kind == StreamKind::Cycles) {
      std::string line;
      char buf[32];
      std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ip);
      line.append(buf);

      for (uint64_t i = 0; i < nr; ++i) {
        uint64_t frame; std::memcpy(&frame, p, sizeof(frame)); p += sizeof(frame);
        if (frame >= (uint64_t)-4096ULL || frame == 0) continue;
        agg_.add_frame(frame);
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)frame);
        line.push_back(';');
        line.append(buf);
      }
      agg_.collapsed_cycles[line] += 1;
    } else {
      // Still advance and collect frames
      for (uint64_t i = 0; i < nr; ++i) {
        uint64_t frame; std::memcpy(&frame, p, sizeof(frame)); p += sizeof(frame);
        agg_.add_frame(frame);
      }
    }
  }

  void enable() {
    (void)::ioctl(cycles_.fd, PERF_EVENT_IOC_RESET, 0);
    (void)::ioctl(time_.fd,   PERF_EVENT_IOC_RESET, 0);
    (void)::ioctl(cycles_.fd, PERF_EVENT_IOC_ENABLE, 0);
    (void)::ioctl(time_.fd,   PERF_EVENT_IOC_ENABLE, 0);
    enable_depth_++;
  }
  void disable() {
    if (enable_depth_ == 0) return;
    enable_depth_--;
    if (enable_depth_ == 0) {
      (void)::ioctl(cycles_.fd, PERF_EVENT_IOC_DISABLE, 0);
      (void)::ioctl(time_.fd,   PERF_EVENT_IOC_DISABLE, 0);
    }
  }

private:
  uint32_t freq_hz_{1000};
  size_t   ring_pages_{4096};
  bool     want_stacks_{false};

  bool created_{false};
  bool disabled_{false};

  Stream cycles_{};
  Stream time_{};
  uint64_t cycles_tail_{0}, time_tail_{0};

  std::thread reader_;
  std::atomic<bool> stop_reader_{false};
  int enable_depth_{0};

  Agg agg_;
  std::mutex mu_;
};

} // namespace xeon

#define XEON_SCOPE() ::xeon::Profiler::Scope __xeon_scope__(::xeon::Profiler::instance())

#endif // XEON_PROFILER_DUAL_HPP
