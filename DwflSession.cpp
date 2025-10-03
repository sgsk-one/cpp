#include "perfctx/DwflSession.hpp"
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

using namespace perfctx;

static const Dwfl_Callbacks CB = {
  .find_elf = dwfl_linux_proc_find_elf,
  .find_debuginfo = dwfl_standard_find_debuginfo,
  .debuginfo_path = nullptr
};

DwflSession::DwflSession(pid_t pid) : pid_(pid) {
  dwfl_ = dwfl_begin(&CB);
  if (!dwfl_) {
    std::fprintf(stderr, "dwfl_begin failed: %s\n", dwfl_errmsg(-1));
    return;
  }
  if (dwfl_linux_proc_report(dwfl_, pid_) != 0) {
    std::fprintf(stderr, "dwfl_linux_proc_report failed: %s\n", dwfl_errmsg(-1));
    dwfl_end(dwfl_); dwfl_ = nullptr; return;
  }
  if (dwfl_report_end(dwfl_, nullptr, nullptr) != 0) {
    std::fprintf(stderr, "dwfl_report_end failed: %s\n", dwfl_errmsg(-1));
    dwfl_end(dwfl_); dwfl_ = nullptr; return;
  }
  char mempath[64]; std::snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pid_);
  memfd_ = ::open(mempath, O_RDONLY);
  if (memfd_ < 0) {
    std::perror("open /proc/pid/mem");
    dwfl_end(dwfl_); dwfl_ = nullptr;
  }
}

DwflSession::~DwflSession() {
  if (memfd_ >= 0) ::close(memfd_);
  if (dwfl_) dwfl_end(dwfl_);
}

std::optional<DwflSession::IpDie> DwflSession::ip_to_die(uint64_t ip) {
  if (!dwfl_) return std::nullopt;
  Dwfl_Module* mod = dwfl_addrmodule(dwfl_, (Dwarf_Addr)ip);
  if (!mod) return std::nullopt;
  Dwarf_Addr bias = 0;
  Dwarf_Die* f = dwfl_module_addrdie(mod, (Dwarf_Addr)ip, &bias);
  if (!f) return std::nullopt;
  IpDie out; out.mod = mod; out.bias = bias; out.die = &out.die_mem; *out.die = *f;
  return out;
}

std::string DwflSession::mod_and_symbol(uint64_t ip) {
  if (!dwfl_) return "?";
  Dwfl_Module* mod = dwfl_addrmodule(dwfl_, (Dwarf_Addr)ip);
  if (!mod) return "?";
  const char* name = dwfl_module_addrname(mod, (Dwarf_Addr)ip);
  const char* modname = nullptr;
  (void)dwfl_module_info(mod, &modname, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
  char buf[512];
  std::snprintf(buf, sizeof(buf), "%s!%s", modname ? modname : "?", name ? name : "?");
  return std::string(buf);
}

std::optional<uint64_t> DwflSession::cached_member_offset(Dwarf_Die* type_die, const std::string& member) {
  if (!type_die) return std::nullopt;
  Dwarf_Off off = dwarf_dieoffset(type_die);
  // Normalize to CU-relative to be stable across ASLR.
  Dwarf_Die cu;
  if (!dwarf_diecu(type_die, &cu, nullptr, nullptr)) return std::nullopt;
  Dwarf_Off cuoff = dwarf_dieoffset(&cu);
  OffsetKey k{off - cuoff, member};
  auto it = offset_cache_.find(k);
  if (it != offset_cache_.end()) return it->second;
  return std::nullopt;
}

void DwflSession::put_member_offset(Dwarf_Die* type_die, const std::string& member, uint64_t off) {
  if (!type_die) return;
  Dwarf_Off doff = dwarf_dieoffset(type_die);
  Dwarf_Die cu;
  if (!dwarf_diecu(type_die, &cu, nullptr, nullptr)) return;
  Dwarf_Off cuoff = dwarf_dieoffset(&cu);
  OffsetKey k{doff - cuoff, member};
  offset_cache_.emplace(k, off);
}

Dwarf_Die* DwflSession::find_object_param_die(Dwarf_Die* func_die, Dwarf_Die& out_param) {
  if (!func_die) return nullptr;

  Dwarf_Attribute attr;
  if (Dwarf_Attribute* objp = dwarf_attr(func_die, DW_AT_object_pointer, &attr)) {
    Dwarf_Die* ref = dwarf_formref_die(objp, &out_param);
    if (ref) return &out_param;
  }

  // Iterate children: pick artificial "this"
  Dwarf_Die child;
  if (dwarf_child(func_die, &child) != 0) return nullptr;
  do {
    if (dwarf_tag(&child) == DW_TAG_formal_parameter) {
      bool is_art = false;
      if (Dwarf_Attribute* a = dwarf_attr(&child, DW_AT_artificial, &attr)) {
        Dwarf_Word v; if (dwarf_formudata(a, &v) == 0) is_art = (v != 0);
      }
      const char* nm = dwarf_diename(&child);
      if (is_art || (nm && std::strcmp(nm, "this") == 0)) {
        out_param = child;
        return &out_param;
      }
    }
  } while (dwarf_siblingof(&child, &child) == 0);

  return nullptr;
}

Dwarf_Die* DwflSession::peel_typedefs_and_pointers(Dwarf_Die* die, Dwarf_Die& tmp) {
  if (!die) return nullptr;
  int tag = dwarf_tag(die);
  if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type || tag == DW_TAG_rvalue_reference_type || tag == DW_TAG_typedef) {
    Dwarf_Attribute a;
    Dwarf_Die* to = dwarf_formref_die(dwarf_attr(die, DW_AT_type, &a), &tmp);
    if (!to) return die;
    return peel_typedefs_and_pointers(to, tmp);
  }
  return die;
}

std::optional<uint64_t> DwflSession::member_offset_of(Dwarf_Die* class_die, const std::string& name) {
  if (!class_die) return std::nullopt;

  if (auto c = cached_member_offset(class_die, name)) return c;

  // Walk members; handle single inheritance (DW_TAG_inheritance) by recursing.
  Dwarf_Die child;
  if (dwarf_child(class_die, &child) == 0) {
    do {
      int tag = dwarf_tag(&child);
      if (tag == DW_TAG_member) {
        const char* nm = dwarf_diename(&child);
        if (nm && name == nm) {
          Dwarf_Attribute la;
          if (Dwarf_Attribute* a = dwarf_attr(&child, DW_AT_data_member_location, &la)) {
            // Usually constant; expression form omitted for brevity
            Dwarf_Word off = 0;
            if (dwarf_formudata(a, &off) == 0) {
              put_member_offset(class_die, name, (uint64_t)off);
              return (uint64_t)off;
            }
          }
        }
      } else if (tag == DW_TAG_inheritance) {
        // Base subobject offset + recurse in base type.
        Dwarf_Attribute la;
        Dwarf_Word base_off = 0;
        if (Dwarf_Attribute* a = dwarf_attr(&child, DW_AT_data_member_location, &la)) {
          (void)dwarf_formudata(a, &base_off);
        }
        Dwarf_Attribute ta;
        Dwarf_Die base_type_mem;
        Dwarf_Die* base_ptr = dwarf_formref_die(dwarf_attr(&child, DW_AT_type, &ta), &base_type_mem);
        if (base_ptr) {
          Dwarf_Die peeled_mem; Dwarf_Die* base_cls = peel_typedefs_and_pointers(base_ptr, peeled_mem);
          if (auto sub = member_offset_of(base_cls, name)) {
            uint64_t total = base_off + *sub;
            put_member_offset(class_die, name, total);
            return total;
          }
        }
      }
    } while (dwarf_siblingof(&child, &child) == 0);
  }

  return std::nullopt;
}

ssize_t DwflSession::pread_user(void* dst, size_t n, uint64_t addr) const {
  if (memfd_ < 0) return -1;
  // SAFETY CAP: never read > 4096 bytes per request
  size_t cap = n > 4096 ? 4096 : n;
  return ::pread(memfd_, dst, cap, (off_t)addr);
}
