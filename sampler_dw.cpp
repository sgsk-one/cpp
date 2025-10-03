// sampler_dw.cpp — build:
//   g++ -O2 -g -fno-omit-frame-pointer -std=c++17 sampler_dw.cpp -ldwfl -ldw -lelf -o sampler_dw
//
// Usage:
//   ./app &
//   APP_PID=$!
//   sudo ./sampler_dw $APP_PID Expression::evaluate src
//
// Notes:
// - Recovers `this` via DWARF param location (object pointer) when possible.
// - Supports DW_OP_regx, DW_OP_bregx, DW_OP_fbreg (with frame base == RBP for -fno-omit-frame-pointer).
// - Falls back to RDI when DWARF is ambiguous.
// - Reads object field (e.g., "src") via DWARF member offset and prints the string.
//
// This is intentionally compact but complete. For production, add robust error checks and caching.

#define _GNU_SOURCE
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>
#include <optional>

#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>

// ---------- perf plumbing ----------
static long perf_event_open(perf_event_attr* pea, pid_t pid, int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, pea, pid, cpu, group_fd, flags);
}

struct MMapRing {
  void* pg = nullptr;
  size_t pgcnt = 0;
  perf_event_mmap_page* meta = nullptr;
  bool open(int fd, size_t pages) {
    pgcnt = pages + 1;
    size_t sz = pgcnt * getpagesize();
    pg = mmap(nullptr, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (pg == MAP_FAILED) { perror("mmap"); return false; }
    meta = (perf_event_mmap_page*)pg;
    return true;
  }
  void close() {
    if (pg) munmap(pg, pgcnt * getpagesize());
    pg = nullptr; meta = nullptr; pgcnt = 0;
  }
};

static inline uint64_t rb_read_head(const perf_event_mmap_page* m) {
  __sync_synchronize();
  return m->data_head;
}
static inline void rb_write_tail(perf_event_mmap_page* m, uint64_t tail) {
  m->data_tail = tail;
  __sync_synchronize();
}

// ---------- DWARF helpers ----------

// Initialize a Dwfl session for a live PID.
static Dwfl* init_dwfl_for_pid(pid_t pid) {
  static const Dwfl_Callbacks CB = {
    .find_elf = dwfl_linux_proc_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .debuginfo_path = nullptr
  };
  Dwfl* dwfl = dwfl_begin(&CB);
  if (!dwfl) { fprintf(stderr, "dwfl_begin failed: %s\n", dwfl_errmsg(-1)); return nullptr; }
  if (dwfl_linux_proc_report(dwfl, pid) != 0) {
    fprintf(stderr, "dwfl_linux_proc_report failed: %s\n", dwfl_errmsg(-1));
    dwfl_end(dwfl);
    return nullptr;
  }
  if (dwfl_report_end(dwfl, nullptr, nullptr) != 0) {
    fprintf(stderr, "dwfl_report_end failed: %s\n", dwfl_errmsg(-1));
    dwfl_end(dwfl);
    return nullptr;
  }
  return dwfl;
}

// Get DIE for IP (bias-adjusted).
static Dwarf_Die* die_for_ip(Dwfl* dwfl, uint64_t ip, Dwarf_Addr* bias_out, Dwfl_Module** mod_out) {
  if (!dwfl) return nullptr;
  Dwfl_Module* mod = dwfl_addrmodule(dwfl, (Dwarf_Addr)ip);
  if (!mod) return nullptr;
  if (mod_out) *mod_out = mod;
  Dwarf_Addr bias = 0;
  Dwarf_Die* die = dwfl_module_addrdie(mod, (Dwarf_Addr)ip, &bias);
  if (!die) return nullptr;
  if (bias_out) *bias_out = bias;
  return die;
}

// Find the DIE of the object pointer parameter for a function DIE.
// Prefer DW_AT_object_pointer; otherwise, find the artificial param named "this".
static Dwarf_Die* find_object_pointer_die(Dwarf_Die* func_die) {
  if (!func_die) return nullptr;

  // 1) DW_AT_object_pointer → reference to the param DIE
  Dwarf_Attribute attr_mem;
  Dwarf_Attribute* objp = dwarf_attr(func_die, DW_AT_object_pointer, &attr_mem);
  if (objp) {
    Dwarf_Die* ref = dwarf_formref_die(objp, nullptr);
    if (ref) return ref;
  }
  // 2) Iterate children for params; pick artificial "this"
  Dwarf_Die child;
  if (dwarf_child(func_die, &child) != 0) return nullptr;
  do {
    int tag = dwarf_tag(&child);
    if (tag == DW_TAG_formal_parameter) {
      // artificial?
      Dwarf_Attribute a;
      Dwarf_Attribute* art = dwarf_attr(&child, DW_AT_artificial, &a);
      bool is_art = false;
      if (art) {
        Dwarf_Word val;
        if (dwarf_formudata(art, &val) == 0) is_art = (val != 0);
      }
      const char* name = dwarf_diename(&child);
      if (is_art || (name && strcmp(name, "this") == 0)) {
        return &child;
      }
    }
  } while (dwarf_siblingof(&child, &child) == 0);

  return nullptr;
}

// Evaluate a very common subset of DWARF location expressions for parameters,
// using captured user regs and frame pointer as frame base.
// Supports: DW_OP_regx, DW_OP_bregx (reg + sconst), DW_OP_fbreg (frame base + sconst).
// Frame base is assumed to be RBP (since we built with -fno-omit-frame-pointer).
static std::optional<uint64_t> eval_param_location(Dwarf_Attribute* loc_attr,
                                                   uint64_t pc,
                                                   const uint64_t regs[PERF_REG_X86_MAX]) {
  if (!loc_attr) return std::nullopt;

  // For location lists: pick entry matching current PC.
  Dwarf_Op* expr = nullptr;
  size_t exprlen = 0;
  int r = dwarf_getlocation_addr(loc_attr, (Dwarf_Addr)pc, &expr, &exprlen, 1);
  if (r <= 0 || exprlen == 0 || !expr) return std::nullopt;

  // Evaluate tiny subset.
  // Stack-based evaluation, but we only expect single result.
  int i = 0;
  uint64_t stack[4]; int sp = 0;

  auto push = [&](uint64_t v){ if (sp < 4) stack[sp++] = v; };
  auto pop = [&](){ return (sp>0)?stack[--sp]:0; };

  while (i < (int)exprlen) {
    Dwarf_Op op = expr[i++];
    switch (op.atom) {
      case DW_OP_reg0: case DW_OP_reg1: case DW_OP_reg2: case DW_OP_reg3:
      case DW_OP_reg4: case DW_OP_reg5: case DW_OP_reg6: case DW_OP_reg7:
      case DW_OP_reg8: case DW_OP_reg9: case DW_OP_reg10: case DW_OP_reg11:
      case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
      {
        // Map DWARF reg → perf/x86 reg index. DWARF reg numbers on x86-64:
        // 0..15 -> rax, rdx, rcx, rbx, rsi, rdi, rbp, rsp, r8..r15
        static const int dwarf_to_perf[16] = {
          PERF_REG_X86_AX, // rax
          PERF_REG_X86_DX, // rdx
          PERF_REG_X86_CX, // rcx
          PERF_REG_X86_BX, // rbx
          PERF_REG_X86_SI, // rsi
          PERF_REG_X86_DI, // rdi
          PERF_REG_X86_BP, // rbp
          PERF_REG_X86_SP, // rsp
          PERF_REG_X86_R8,
          PERF_REG_X86_R9,
          PERF_REG_X86_R10,
          PERF_REG_X86_R11,
          PERF_REG_X86_R12,
          PERF_REG_X86_R13,
          PERF_REG_X86_R14,
          PERF_REG_X86_R15
        };
        int dwreg = op.atom - DW_OP_reg0;
        if (dwreg >=0 && dwreg < 16) {
          push(regs[dwarf_to_perf[dwreg]]);
        }
        break;
      }
      case DW_OP_regx: {
        // op.number gives DWARF reg number
        Dwarf_Word dwreg = op.number;
        // Map a few; generalizing beyond 0..15 left out for brevity
        if (dwreg <= 15) {
          static const int dwarf_to_perf[16] = {
            PERF_REG_X86_AX, PERF_REG_X86_DX, PERF_REG_X86_CX, PERF_REG_X86_BX,
            PERF_REG_X86_SI, PERF_REG_X86_DI, PERF_REG_X86_BP, PERF_REG_X86_SP,
            PERF_REG_X86_R8, PERF_REG_X86_R9, PERF_REG_X86_R10, PERF_REG_X86_R11,
            PERF_REG_X86_R12, PERF_REG_X86_R13, PERF_REG_X86_R14, PERF_REG_X86_R15
          };
          push(regs[dwarf_to_perf[dwreg]]);
        } else {
          return std::nullopt;
        }
        break;
      }
      case DW_OP_bregx: {
        Dwarf_Word dwreg = op.number;     // base register
        Dwarf_Sword off = op.number2.s;   // signed offset
        if (dwreg <= 15) {
          static const int dwarf_to_perf[16] = {
            PERF_REG_X86_AX, PERF_REG_X86_DX, PERF_REG_X86_CX, PERF_REG_X86_BX,
            PERF_REG_X86_SI, PERF_REG_X86_DI, PERF_REG_X86_BP, PERF_REG_X86_SP,
            PERF_REG_X86_R8, PERF_REG_X86_R9, PERF_REG_X86_R10, PERF_REG_X86_R11,
            PERF_REG_X86_R12, PERF_REG_X86_R13, PERF_REG_X86_R14, PERF_REG_X86_R15
          };
          uint64_t base = regs[dwarf_to_perf[dwreg]];
          push((uint64_t)((int64_t)base + off));
        } else {
          return std::nullopt;
        }
        break;
      }
      case DW_OP_fbreg: {
        // frame base + sconst
        // With -fno-omit-frame-pointer, many functions use RBP as frame base.
        Dwarf_Sword off = op.number;
        uint64_t rbp = regs[PERF_REG_X86_BP];
        push((uint64_t)((int64_t)rbp + off));
        break;
      }
      case DW_OP_stack_value: {
        // means the top of stack is the value itself, not an address (rare for `this`)
        // For object pointer we expect an address, so accept it as value.
        break;
      }
      default:
        // Unsupported opcodes (DW_OP_piece, etc.)
        return std::nullopt;
    }
  }

  if (sp == 0) return std::nullopt;
  return stack[sp-1];
}

// Find a member offset (in bytes) in a class/struct type by member name.
static std::optional<uint64_t> find_member_offset(Dwarf_Die* type_die, const char* member_name) {
  if (!type_die || !member_name) return std::nullopt;

  // If we were handed a typedef, peel to underlying type.
  if (dwarf_tag(type_die) == DW_TAG_typedef) {
    Dwarf_Attribute a;
    Dwarf_Die* to = dwarf_formref_die(dwarf_attr(type_die, DW_AT_type, &a), nullptr);
    if (to) type_die = to;
  }

  Dwarf_Die child;
  if (dwarf_child(type_die, &child) != 0) return std::nullopt;

  do {
    if (dwarf_tag(&child) == DW_TAG_member) {
      const char* nm = dwarf_diename(&child);
      if (nm && strcmp(nm, member_name) == 0) {
        Dwarf_Attribute loc_attr;
        Dwarf_Attribute* loc = dwarf_attr(&child, DW_AT_data_member_location, &loc_attr);
        if (!loc) return std::nullopt;
        Dwarf_Word off = 0;
        // Most compilers encode this as constant.
        if (dwarf_formudata(loc, &off) == 0) return (uint64_t)off;
        // (Expression form is possible but rare; omitted for brevity.)
      }
    }
  } while (dwarf_siblingof(&child, &child) == 0);

  return std::nullopt;
}

// Demangle (best effort) using libdwfl’s module API, else print raw.
static std::string mod_and_func(Dwfl_Module* mod, uint64_t ip) {
  const char* modname = dwfl_module_info(mod, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) ? dwfl_module_info(mod, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) : "?";
  const char* fname = nullptr;
  const char* sym = dwfl_module_addrname(mod, ip);
  if (sym) fname = sym;
  char buf[512];
  snprintf(buf, sizeof(buf), "%s!%s", modname ? modname : "?", fname ? fname : "?");
  return std::string(buf);
}

// ---------- sampler main ----------

static const uint64_t REG_MASK =
  (1ULL<<PERF_REG_X86_IP) |
  (1ULL<<PERF_REG_X86_SP) |
  (1ULL<<PERF_REG_X86_BP) |
  (1ULL<<PERF_REG_X86_AX) |
  (1ULL<<PERF_REG_X86_BX) |
  (1ULL<<PERF_REG_X86_CX) |
  (1ULL<<PERF_REG_X86_DX) |
  (1ULL<<PERF_REG_X86_SI) |
  (1ULL<<PERF_REG_X86_DI) |
  (1ULL<<PERF_REG_X86_R8) |
  (1ULL<<PERF_REG_X86_R9) |
  (1ULL<<PERF_REG_X86_R10) |
  (1ULL<<PERF_REG_X86_R11) |
  (1ULL<<PERF_REG_X86_R12) |
  (1ULL<<PERF_REG_X86_R13) |
  (1ULL<<PERF_REG_X86_R14) |
  (1ULL<<PERF_REG_X86_R15);

int main(int argc, char** argv) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <pid> <function-name-fragment> <member-name>\n", argv[0]);
    fprintf(stderr, "Example: %s 12345 Expression::evaluate src\n", argv[0]);
    return 1;
  }
  pid_t pid = (pid_t)atoi(argv[1]);
  const char* func_fragment = argv[2];   // e.g., "Expression::evaluate"
  const char* member_name   = argv[3];   // e.g., "src"

  // Open /proc/<pid>/mem once
  char mempath[64]; snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pid);
  int memfd = open(mempath, O_RDONLY);
  if (memfd < 0) { perror("open mem"); return 1; }

  // Start DWARF session for this PID
  Dwfl* dwfl = init_dwfl_for_pid(pid);
  if (!dwfl) { close(memfd); return 1; }

  struct perf_event_attr pea{};
  pea.type = PERF_TYPE_HARDWARE;
  pea.size = sizeof(pea);
  pea.config = PERF_COUNT_HW_CPU_CYCLES;
  pea.sample_period = 100000; // tune
  pea.sample_type =
    PERF_SAMPLE_IP |
    PERF_SAMPLE_TID |
    PERF_SAMPLE_TIME |
    PERF_SAMPLE_CALLCHAIN |
    PERF_SAMPLE_REGS_USER;
  pea.exclude_kernel = 1;
  pea.disabled = 1;
  pea.precise_ip = 2; // request better skid if possible
  pea.sample_regs_user = REG_MASK;

  int fd = perf_event_open(&pea, pid, -1, -1, 0);
  if (fd < 0) { perror("perf_event_open"); dwfl_end(dwfl); close(memfd); return 1; }

  MMapRing ring;
  if (!ring.open(fd, 1<<8)) { close(fd); dwfl_end(dwfl); close(memfd); return 1; }

  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  uint8_t* data = (uint8_t*)ring.meta + ring.meta->data_offset;
  size_t data_size = ring.meta->data_size;

  fprintf(stderr, "Sampling pid %d (function contains \"%s\", member \"%s\")… Ctrl-C to stop\n",
          pid, func_fragment, member_name);

  uint64_t tail = 0;

  while (1) {
    uint64_t head = rb_read_head(ring.meta);
    while (tail < head) {
      size_t off = tail % data_size;
      auto* h = (perf_event_header*)(data + off);
      if (h->type == PERF_RECORD_SAMPLE) {
        uint8_t* p = (uint8_t*)h + sizeof(*h);
        auto rd64=[&](){ uint64_t v; memcpy(&v,p,8); p+=8; return v; };
        auto rd32=[&](){ uint32_t v; memcpy(&v,p,4); p+=4; return v; };

        uint64_t ip = rd64();
        uint32_t pid_u = rd32(); (void)pid_u;
        uint32_t tid_u = rd32();
        uint64_t time = rd64(); (void)time;

        uint64_t nr = rd64();
        std::vector<uint64_t> chain; chain.reserve(nr);
        for (uint64_t i=0;i<nr;i++) chain.push_back(rd64());

        uint64_t regs[PERF_REG_X86_MAX]={0};
        uint64_t mask = pea.sample_regs_user;
        for (int r=0;r<PERF_REG_X86_MAX;r++) {
          if (mask & (1ull<<r)) regs[r] = rd64();
        }

        // Map to DIE for IP
        Dwarf_Addr bias = 0;
        Dwfl_Module* mod = nullptr;
        Dwarf_Die* die = die_for_ip(dwfl, ip, &bias, &mod);
        std::string modfn = mod ? mod_and_func(mod, ip - bias) : std::string("?");

        // Filter to the function(s) you care about (simple substring match on symbol name).
        if (modfn.find(func_fragment) == std::string::npos) {
          tail += h->size;
          continue;
        }

        // Locate the object pointer param DIE
        Dwarf_Die* objparam = die ? find_object_pointer_die(die) : nullptr;

        // Evaluate its location at this PC → address of `this` (or value)
        std::optional<uint64_t> this_addr_opt;
        if (objparam) {
          Dwarf_Attribute loc_attr;
          Dwarf_Attribute* loc = dwarf_attr(objparam, DW_AT_location, &loc_attr);
          if (loc) {
            this_addr_opt = eval_param_location(loc, ip - bias, regs);
          }
        }

        // Fallback: if unknown, try RDI (x86-64 SysV) — often correct near entry
        uint64_t this_ptr = 0;
        if (this_addr_opt.has_value()) {
          this_ptr = *this_addr_opt;
        } else {
          this_ptr = regs[PERF_REG_X86_DI];
        }

        // From the param's type, find the class/struct DIE, then member offset
        uint64_t member_off = 0;
        bool got_off = false;
        if (objparam) {
          Dwarf_Attribute ta;
          Dwarf_Die* type_die = dwarf_formref_die(dwarf_attr(objparam, DW_AT_type, &ta), nullptr);
          if (type_die) {
            // Peel typedefs
            if (dwarf_tag(type_die) == DW_TAG_pointer_type) {
              Dwarf_Attribute pta;
              Dwarf_Die* tgt = dwarf_formref_die(dwarf_attr(type_die, DW_AT_type, &pta), nullptr);
              if (tgt) type_die = tgt;
            }
            auto offopt = find_member_offset(type_die, member_name);
            if (offopt.has_value()) {
              member_off = *offopt;
              got_off = true;
            }
          }
        }

        // Read member address (e.g., const char* src) and then the string
        std::string ctx = "<n/a>";
        if (this_ptr && got_off) {
          uint64_t field_addr = this_ptr + member_off;
          uint64_t ptrval = 0;
          if (pread(memfd, &ptrval, sizeof(ptrval), (off_t)field_addr) == (ssize_t)sizeof(ptrval) && ptrval) {
            char buf[256] = {0};
            pread(memfd, buf, sizeof(buf)-1, (off_t)ptrval);
            ctx = buf;
          }
        }

        printf("tid=%u ip=0x%llx %s this=%p %s=\"%s\"\n",
               tid_u,
               (unsigned long long)ip,
               modfn.c_str(),
               (void*)this_ptr,
               member_name,
               ctx.c_str());
      }
      tail += h->size;
    }
    rb_write_tail(ring.meta, head);
    usleep(10000);
  }

  ring.close();
  close(fd);
  dwfl_end(dwfl);
  close(memfd);
  return 0;
}
