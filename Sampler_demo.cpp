#define _GNU_SOURCE
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>

#include "perfctx/Regs.hpp"
#include "perfctx/DwflSession.hpp"
#include "perfctx/ThisExtractor.hpp"

using namespace perfctx;

static long perf_event_open(perf_event_attr* pea, pid_t pid, int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, pea, pid, cpu, group_fd, flags);
}

struct MMapRing {
  void* pg = nullptr; size_t pgcnt = 0; perf_event_mmap_page* meta = nullptr;
  bool open(int fd, size_t pages) {
    pgcnt = pages + 1;
    size_t sz = (pages+1) * getpagesize();
    pg = mmap(nullptr, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (pg == MAP_FAILED) { perror("mmap"); return false; }
    meta = (perf_event_mmap_page*)pg; return true;
  }
  void close() { if (pg) munmap(pg, (pgcnt)*getpagesize()); pg=nullptr; meta=nullptr; pgcnt=0; }
};

int main(int argc, char** argv) {
  if (argc < 2) { std::fprintf(stderr, "Usage: %s <pid>\n", argv[0]); return 1; }
  pid_t pid = (pid_t)std::atoi(argv[1]);

  perf_event_attr pea{}; pea.type = PERF_TYPE_HARDWARE; pea.size = sizeof(pea);
  pea.config = PERF_COUNT_HW_CPU_CYCLES;
  pea.sample_period = 100000; // tune
  pea.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER;
  pea.exclude_kernel = 1; pea.precise_ip = 2;
  // Capture a broad set of x86-64 regs (matches our Regs mapping)
  uint64_t regmask =
    (1ull<<PERF_REG_X86_IP)|(1ull<<PERF_REG_X86_SP)|(1ull<<PERF_REG_X86_BP)|
    (1ull<<PERF_REG_X86_AX)|(1ull<<PERF_REG_X86_BX)|(1ull<<PERF_REG_X86_CX)|(1ull<<PERF_REG_X86_DX)|
    (1ull<<PERF_REG_X86_SI)|(1ull<<PERF_REG_X86_DI)|
    (1ull<<PERF_REG_X86_R8)|(1ull<<PERF_REG_X86_R9)|(1ull<<PERF_REG_X86_R10)|(1ull<<PERF_REG_X86_R11)|
    (1ull<<PERF_REG_X86_R12)|(1ull<<PERF_REG_X86_R13)|(1ull<<PERF_REG_X86_R14)|(1ull<<PERF_REG_X86_R15);
  pea.sample_regs_user = regmask;

  int fd = perf_event_open(&pea, pid, -1, -1, 0);
  if (fd < 0) { perror("perf_event_open"); return 1; }

  MMapRing ring;
  if (!ring.open(fd, 1<<8)) return 1;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  uint8_t* data = (uint8_t*)ring.meta + ring.meta->data_offset;
  size_t data_size = ring.meta->data_size;
  uint64_t tail = 0;

  DwflSession dw(pid);
  if (!dw.ok()) { std::fprintf(stderr, "DWFL init failed\n"); return 1; }

  std::fprintf(stderr, "Sampling pid %d … Ctrl-C to stop\n", pid);

  while (true) {
    uint64_t head = ring.meta->data_head; __sync_synchronize();
    while (tail < head) {
      size_t off = tail % data_size;
      auto* h = (perf_event_header*)(data + off);
      if (h->type == PERF_RECORD_SAMPLE) {
        uint8_t* p = (uint8_t*)h + sizeof(*h);
        auto rd64=[&](){ uint64_t v; std::memcpy(&v,p,8); p+=8; return v; };
        auto rd32=[&](){ uint32_t v; std::memcpy(&v,p,4); p+=4; return v; };

        uint64_t ip = rd64();
        (void)rd32(); uint32_t tid = rd32();
        (void)rd64(); // time
        uint64_t nr = rd64();
        std::vector<uint64_t> chain; chain.reserve(nr);
        for (uint64_t i=0;i<nr;i++) chain.push_back(rd64());

        Regs regs{}; regs.mask = regmask;
        // perf compacts regs in enum order; we reconstruct by iterating enum and consuming:
        for (int r=0; r<=PERF_REG_X86_R15; ++r) {
          if (regmask & (1ull<<r)) regs.vals[r] = rd64();
        }

        // DWARF resolve `this` at this exact PC
        auto tr = resolve_this(dw, ip, regs, pid, /*fallback*/true);

        // We’ll only print lines for functions that look like Expression::evaluate
        std::string modfn = dw.mod_and_symbol(ip);
        if (modfn.find("Expression::evaluate") == std::string::npos) {
          tail += h->size; continue;
        }

        std::string ctx = tr.ok ? read_object_text_field(dw, pid, tr.this_ptr, tr.type_name, "src") : "<no-this>";

        std::printf("tid=%u ip=0x%llx %-50s  this=%p  from=%s  type=%s  src=\"%s\"\n",
                    tid, (unsigned long long)ip, modfn.c_str(), (void*)tr.this_ptr,
                    tr.from_dwarf ? "DWARF":"RDI",
                    tr.type_name.empty() ? "?" : tr.type_name.c_str(),
                    ctx.c_str());
      }
      tail += h->size;
    }
    ring.meta->data_tail = head; __sync_synchronize();
    usleep(5000);
  }
}
