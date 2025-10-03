#include "perfctx/ThisExtractor.hpp"
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <cxxabi.h>
#include <vector>
#include <string>
#include <cstdio>
#include <cstring>

using namespace perfctx;

// Demangle helper
static std::string demangle(const char* s) {
  if (!s) return {};
  int st = 0;
  char* d = abi::__cxa_demangle(s, nullptr, nullptr, &st);
  if (st == 0 && d) { std::string out(d); std::free(d); return out; }
  if (d) std::free(d);
  return std::string(s);
}

// Evaluate full DWARF expression using dwarf_expr_eval (supports complex cases).
// Returns a value (address or scalar). For parameters, it typically yields an ADDRESS of `this`.
static std::optional<uint64_t> eval_loc_with_expr_eval(Dwarf_Attribute* loc,
                                                       Dwarf_Addr pc_bias_adj,
                                                       const Regs& regs) {
  if (!loc) return std::nullopt;

  Dwarf_Op* expr = nullptr; size_t exprlen = 0;
  // For location lists, pick the entry that covers this PC:
  int r = dwarf_getlocation_addr(loc, pc_bias_adj, &expr, &exprlen, 1);
  if (r <= 0 || !expr || exprlen == 0) return std::nullopt;

  // Create expression evaluator
  Dwarf_Op* expr_copy = expr; // dwarf_expr_eval accepts the array directly
  Dwarf_Addr result = 0;
  Dwarf_Word nresults = 0;

  // Provide register and CFA callbacks. For simplicity we supply a map for 0..15 DWARF regs.
  // DWARF reg nums 0..15 → rax, rdx, rcx, rbx, rsi, rdi, rbp, rsp, r8..r15 (System V AMD64 psABI)
  auto reg_cb = [](Dwarf_Op* /*op*/, unsigned regnum, Dwarf_Word* val, void* arg) -> int {
    const Regs* r = static_cast<const Regs*>(arg);
    static const int map16[16] = {
      X86RegIndex::RAX, X86RegIndex::RDX, X86RegIndex::RCX, X86RegIndex::RBX,
      X86RegIndex::RSI, X86RegIndex::RDI, X86RegIndex::RBP, X86RegIndex::RSP,
      X86RegIndex::R8,  X86RegIndex::R9,  X86RegIndex::R10, X86RegIndex::R11,
      X86RegIndex::R12, X86RegIndex::R13, X86RegIndex::R14, X86RegIndex::R15
    };
    if (regnum < 16) {
      int idx = map16[regnum];
      *val = get_reg(*r, idx);
      return 0;
    }
    // Unknown reg → fail this path
    return -1;
  };

  // Compute CFA (Canonical Frame Address) using CFI if available at this PC.
  // dwarf_expr_eval can also call our cfa_cb; we implement a simple rbp+offset fallback if CFI unavailable.
  auto cfa_cb = [](Dwarf_Op* /*op*/, Dwarf_Addr* cfa, void* arg) -> int {
    const Regs* r = static_cast<const Regs*>(arg);
    // Fallback CFA ≈ RSP at call site. Better: compute via CFI outside and stash in arg.
    *cfa = get_reg(*r, X86RegIndex::RSP);
    return 0;
  };

  // Provide a “frame base” as RBP (this improves DW_OP_fbreg if expression uses it).
  Dwarf_Addr frame_base = get_reg(regs, X86RegIndex::RBP);

  // Evaluate
  int er = dwarf_expr_eval(expr_copy, exprlen,
                           /*addr size*/ sizeof(void*),
                           /*offset size*/ sizeof(void*),
                           /*pc*/ pc_bias_adj,
                           /*frame base*/ frame_base,
                           reg_cb, cfa_cb,
                           (void*)&regs,
                           &result, &nresults);
  if (er == 0 && nresults >= 1) {
    return (uint64_t)result;
  }
  return std::nullopt;
}

ThisResult perfctx::resolve_this(DwflSession& session,
                                 uint64_t ip,
                                 const Regs& regs,
                                 pid_t /*pid*/,
                                 bool allow_fallback_rdi) {
  ThisResult out;

  // 1) Map IP → function DIE
  auto ipdie = session.ip_to_die(ip);
  if (!ipdie) return out;

  // 2) Identify object parameter DIE (DW_AT_object_pointer or artificial "this")
  Dwarf_Die param_mem;
  Dwarf_Die* param_die = session.find_object_param_die(ipdie->die, param_mem);

  // 3) Evaluate DWARF location for that param at this PC
  if (param_die) {
    Dwarf_Attribute la;
    if (Dwarf_Attribute* loc = dwarf_attr(param_die, DW_AT_location, &la)) {
      auto this_val = eval_loc_with_expr_eval(loc, (Dwarf_Addr)(ip - ipdie->bias), regs);
      if (this_val) {
        out.ok = true;
        out.from_dwarf = true;
        out.this_ptr = *this_val;
      }
    }
    // Grab the static type name (best effort)
    Dwarf_Attribute ta;
    Dwarf_Die type_mem;
    if (Dwarf_Die* ptr = dwarf_formref_die(dwarf_attr(param_die, DW_AT_type, &ta), &type_mem)) {
      Dwarf_Die peeled;
      Dwarf_Die* base = session.peel_typedefs_and_pointers(ptr, peeled);
      const char* nm = dwarf_diename(base);
      if (nm) out.type_name = demangle(nm);
    }
  }

  // 4) Fallback: if DWARF path failed, try ABI (RDI for SysV x86-64) — usually correct near entry
  if (!out.ok && allow_fallback_rdi) {
    out.ok = true;
    out.this_ptr = get_reg(regs, X86RegIndex::RDI);
    out.from_dwarf = false;
  }

  return out;
}

std::string perfctx::read_object_text_field(DwflSession& session,
                                            pid_t /*pid*/,
                                            uint64_t this_ptr,
                                            const std::string& type_name_hint,
                                            const std::string& field_name) {
  if (!this_ptr) return "<null this>";
  // 1) IP is unknown here; we need the type DIE. We’ll discover it via any CU where the type exists.
  //    Practical approach: walk the DIE we found during resolve_this (caller can pass a hint type name),
  //    but since we don’t have the DIE here, we use the function’s param DIE caches.
  //    Simpler: find any CU with a type that matches the hint (best effort). For demo, we skip CU search
  //    and just read at offset 0 assuming `const char*` lives there if offset lookup fails.

  // The *robust* path: When you call read_object_text_field right after resolve_this,
  // you ALSO pass back the type DIE handle (or stash it in your frame data). To keep this file
  // header-only and independent, we infer only by member scan using the last resolved module.
  // Here we attempt: use dwfl_addrmodule on the object address (not ideal), so fallback is common.

  // Better: we try to find the member offset through DWARF using the object param DIE from resolve_this.
  // Since we don't have it here, we'll try to pick *some* type DIE by name. For simplicity, we iterate
  // all modules and look up a DIE named `type_name_hint`, then get the member offset.

  Dwarf_Die found_type{};
  bool have_type = false;

  if (!type_name_hint.empty()) {
    // Walk modules, search by name (linear search; acceptable with caching in real profiler).
    dwfl_report_begin_add(session.dwfl());
    Dwfl_Module* m = nullptr;
    while ((m = dwfl_nextmodule(session.dwfl(), m)) != nullptr) {
      Dwarf_Addr bias = 0;
      Dwarf_CU* cu = nullptr;
      while ((cu = dwfl_module_nextcu(m, cu, &bias)) != nullptr) {
        Dwarf_Die cudie_mem;
        Dwarf_Die* cudie = dwfl_module_cudie(m);
        if (!cudie) continue;
        // DFS through DIEs for a type with this name.
        Dwarf_Die it = *cudie;
        if (dwarf_child(&it, &it) != 0) continue;
        do {
          int tag = dwarf_tag(&it);
          if (tag == DW_TAG_class_type || tag == DW_TAG_structure_type || tag == DW_TAG_typedef) {
            const char* nm = dwarf_diename(&it);
            if (nm && std::string(nm).find(type_name_hint) != std::string::npos) {
              found_type = it; have_type = true; break;
            }
          }
        } while (!have_type && dwarf_siblingof(&it, &it) == 0);
        if (have_type) break;
      }
      if (have_type) break;
    }
    dwfl_report_end(session.dwfl(), nullptr, nullptr);
  }

  uint64_t member_off = 0;
  bool have_off = false;

  if (have_type) {
    Dwarf_Die peeled;
    Dwarf_Die* cls = session.peel_typedefs_and_pointers(&found_type, peeled);
    if (auto off = session.member_offset_of(cls, field_name)) {
      member_off = *off;
      have_off = true;
    }
  }

  // If we didn’t find the member offset, two options:
  //  - Return a short hex of the first 16 bytes (safe).
  //  - Assume field at offset 0 is `const char*` (demo-friendly).
  if (!have_off) {
    // Demo: assume const char* at offset 0
    member_off = 0;
  }

  uint64_t ptrval = 0;
  if (session.pread_user(&ptrval, sizeof(ptrval), this_ptr + member_off) != (ssize_t)sizeof(ptrval) || !ptrval) {
    // hex dump fallback
    unsigned char buf[16] = {0};
    session.pread_user(buf, sizeof(buf), this_ptr);
    char hex[64] = {0};
    std::snprintf(hex, sizeof(hex), "hex:%02x%02x%02x%02x...", buf[0], buf[1], buf[2], buf[3]);
    return std::string(hex);
  }

  // Read C string (cap length).
  char s[512] = {};
  session.pread_user(s, sizeof(s)-1, ptrval);
  return std::string(s);
}
