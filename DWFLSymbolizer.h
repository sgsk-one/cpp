#pragma once

#include <cstdint>
#include <string>
#include <mutex>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <elfutils/libelf.h>
#include <cxxabi.h>
#include <unistd.h>

// -----------------------------------------------------------------------------
// DWFLSymbolizer
// -----------------------------------------------------------------------------
//
// A robust perf-style symbolizer built on elfutils (libdwfl).
//
// Provides:
//   - func_key(ip)        → "module!function" (leaf only, stable key for aggregation)
//   - symbolize_frame(ip) → "module!function (file:line)" for the *outermost inline*
//                          (or the leaf if not inlined)
//
// Why libdwfl?
//   * Handles debug symbols in separate .dbg files via .gnu_debuglink or build-id
//   * Supports debuginfod lookups automatically if configured
//   * Integrates ELF symtab and DWARF line info
//   * This is the same library `perf` uses internally
//
// Notes:
//   * Matches perf: subtracts 1 from IP unless it’s a branch target
//   * Uses ELF symtab first, then DWARF DIEs, then range-scan fallback
//   * Uses /proc/<pid>/maps to discover loaded modules
//   * Thread-safe via mutex (libdwfl itself is not thread-safe)
// -----------------------------------------------------------------------------

class DWFLSymbolizer {
public:
    explicit DWFLSymbolizer(pid_t pid = getpid())
        : pid_(pid) {
        init_dwfl_();
    }

    ~DWFLSymbolizer() {
        std::lock_guard<std::mutex> g(m_);
        if (dwfl_) {
            // Frees all resources associated with the Dwfl session
            dwfl_end(dwfl_);
            dwfl_ = nullptr;
        }
    }

    // Refresh the module list (call if shared libraries are loaded/unloaded at runtime)
    void refresh() {
        std::lock_guard<std::mutex> g(m_);
        maps_ok_ = report_locked_();
    }

    // Leaf-only stable key, used for aggregation in flamegraphs or counters
    // Example: "libc.so!malloc"
    std::string func_key(uint64_t ip, bool is_branch_target = false) {
        std::lock_guard<std::mutex> g(m_);
        return func_key_locked_(ip, is_branch_target);
    }

    // Outermost inline (or leaf if no inline), with file:line if available
    // Example: "myapp!Foo::bar (foo.cpp:42)"
    std::string symbolize_frame(uint64_t ip, bool is_branch_target = false) {
        std::lock_guard<std::mutex> g(m_);
        return symbolize_frame_locked_(ip, is_branch_target);
    }

private:
    // -------------------------------------------------------------------------
    // Utility helpers
    // -------------------------------------------------------------------------

    static inline uint64_t adjust_pc_(uint64_t ip, bool branch_target) {
        // Convention: IPs recorded by perf usually point *after* the instruction.
        // Subtract 1 so symbolization lands inside the correct function body.
        return (!ip || branch_target) ? ip : ip - 1;
    }

    static inline const char* base_name_(const char* path) {
        if (!path || !*path) return "";
        const char* s = strrchr(path, '/');
        return s ? s + 1 : path;
    }

    static inline std::string hex_addr_(uint64_t x) {
        char b[24]; std::snprintf(b, sizeof(b), "0x%llx", (unsigned long long)x);
        return std::string(b);
    }

    static inline std::string hex_off_(uint64_t x) {
        char b[24]; std::snprintf(b, sizeof(b), "0x%llx", (unsigned long long)x);
        return std::string(b);
    }

    static inline std::string demangle_(const char* m) {
        if (!m) return {};
        int st = 0;
        char* d = abi::__cxa_demangle(m, nullptr, nullptr, &st);
        std::string out = (st == 0 && d) ? d : m;
        std::free(d);
        return out;
    }

    // Resolve function name from DWARF DIE, handling inlines/templates
    static const char* canonical_die_name_(Dwarf_Die* die) {
        if (!die) return nullptr;

        // DWARF spec: DW_AT_name is the canonical name
        if (const char* n = dwarf_diename(die)) if (*n) return n;

        // DW_AT_abstract_origin: refers back to original subprogram DIE (inlined functions)
        if (dwarf_hasattr(die, DW_AT_abstract_origin)) {
            Dwarf_Attribute a;
            if (dwarf_attr(die, DW_AT_abstract_origin, &a)) {
                static thread_local Dwarf_Die origin;
                if (dwarf_formref_die(&a, &origin)) {
                    if (const char* n = dwarf_diename(&origin)) if (*n) return n;
                }
            }
        }

        // DW_AT_specification: refers to the declaration (common in C++ templates)
        if (dwarf_hasattr(die, DW_AT_specification)) {
            Dwarf_Attribute s;
            if (dwarf_attr(die, DW_AT_specification, &s)) {
                static thread_local Dwarf_Die spec;
                if (dwarf_formref_die(&s, &spec)) {
                    if (const char* n = dwarf_diename(&spec)) if (*n) return n;
                }
            }
        }

        return nullptr;
    }

    // Manual ELF symbol table search, fallback if fast lookup fails
    static std::string best_symtab_match_(Dwfl_Module* mod, Dwarf_Addr pc_abs) {
        // dwfl_module_getsymtab → ensure symtab is loaded, return # of entries
        int n = dwfl_module_getsymtab(mod);
        if (n <= 0) return {};
        Dwarf_Addr base = dwfl_module_getbase(mod);
        std::string best;
        Dwarf_Addr best_start = 0;

        // Walk all ELF symbols
        for (int i = 1; i < n; ++i) {
            GElf_Sym s; GElf_Word shndx;
            const char* nm = dwfl_module_getsym(mod, i, &s, &shndx);
            if (!nm) continue;

            unsigned type = GELF_ST_TYPE(s.st_info);
            if (type != STT_FUNC && type != STT_GNU_IFUNC) continue;

            Dwarf_Addr start = base + s.st_value;
            Dwarf_Addr end   = s.st_size ? start + s.st_size : start + 1;

            if (pc_abs >= start && pc_abs < end) return demangle_(nm);

            // If size == 0, keep closest preceding symbol
            if (!s.st_size && pc_abs >= start && start >= best_start) {
                best_start = start;
                best = demangle_(nm);
            }
        }
        return best;
    }

    // Map file index (from line table) to actual source path
    static std::string file_from_index_(Dwarf_Die* cu, int idx) {
        if (!cu || idx <= 0) return {};

        // dwarf_getsrcfiles → retrieve source files for a compilation unit
        Dwarf_Files* files = nullptr;
        size_t nfiles = 0;
        if (dwarf_getsrcfiles(cu, &files, &nfiles) != 0 || !files) return {};
        if ((size_t)idx > nfiles) return {};

        // dwarf_filesrc → get file path by index
        const char* path = dwarf_filesrc(files, idx, nullptr, nullptr);
        return path ? std::string(path) : std::string();
    }

    // -------------------------------------------------------------------------
    // Core: leaf-only func_key
    // -------------------------------------------------------------------------
    std::string func_key_locked_(uint64_t raw_ip, bool branch_target) {
        if (!dwfl_) return hex_addr_(raw_ip);
        if (!maps_ok_) { maps_ok_ = report_locked_(); }

        const uint64_t pc = adjust_pc_(raw_ip, branch_target);
        if (!pc) return hex_addr_(raw_ip);

        // dwfl_addrmodule → find the module containing this PC
        Dwfl_Module* mod = dwfl_addrmodule(dwfl_, (Dwarf_Addr)pc);
        if (!mod) return hex_addr_(pc);

        // dwfl_module_info → retrieve module info (path, base, etc.)
        const char* mod_path = dwfl_module_info(mod, nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr);
        const char* mod_name = base_name_(mod_path);
        const Dwarf_Addr mod_base = dwfl_module_getbase(mod);

        std::string fn;

        // dwfl_module_addrname → fast symbol name lookup via ELF symtab
        if (const char* s = dwfl_module_addrname(mod, (Dwarf_Addr)pc)) {
            if (*s) fn = demangle_(s);
        }

        // dwfl_module_addrdie → map PC to DWARF DIE (handles inlines, templates)
        if (fn.empty()) {
            Dwarf_Addr bias = 0;
            if (Dwarf_Die* die = dwfl_module_addrdie(mod, (Dwarf_Addr)pc, &bias)) {
                if (const char* nm = canonical_die_name_(die)) fn = demangle_(nm);
            }
        }

        // fallback: manual symtab walk
        if (fn.empty()) {
            fn = best_symtab_match_(mod, (Dwarf_Addr)pc);
        }

        if (!fn.empty()) {
            return (mod_name && *mod_name)
                 ? std::string(mod_name).append("!").append(fn)
                 : fn;
        } else {
            // Last resort: module+offset or absolute addr
            uint64_t off = (pc >= mod_base) ? (pc - mod_base) : 0;
            return (mod_name && *mod_name)
                 ? std::string(mod_name).append("!+").append(hex_off_(off))
                 : hex_addr_(pc);
        }
    }

    // -------------------------------------------------------------------------
    // Core: outermost inline (for reporting)
    // -------------------------------------------------------------------------
    std::string symbolize_frame_locked_(uint64_t raw_ip, bool branch_target) {
        if (!dwfl_) return hex_addr_(raw_ip);
        if (!maps_ok_) { maps_ok_ = report_locked_(); }

        const uint64_t pc = adjust_pc_(raw_ip, branch_target);
        if (!pc) return hex_addr_(raw_ip);

        // dwfl_addrmodule → locate module containing PC
        Dwfl_Module* mod = dwfl_addrmodule(dwfl_, (Dwarf_Addr)pc);
        if (!mod) return hex_addr_(pc);

        const char* mod_path = dwfl_module_info(mod, nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr);
        const char* mod_name = base_name_(mod_path);

        // dwfl_module_getsrc → map PC to source line
        std::string leaf_file;
        int leaf_line = 0;
        if (Dwfl_Line* ln = dwfl_module_getsrc(mod, (Dwarf_Addr)pc)) {
            Dwarf_Addr a=0; int col=0; const char* src=nullptr;
            if (dwfl_lineinfo(ln, &a, &src, &leaf_line, &col, nullptr, nullptr) && src) {
                leaf_file = src;
            }
        }

        // dwfl_module_addrdie → get DIE covering PC
        Dwarf_Addr bias = 0;
        Dwarf_Die* die  = dwfl_module_addrdie(mod, (Dwarf_Addr)pc, &bias);

        std::string outer_name;
        std::string outer_file;
        int outer_line = 0;

        if (die) {
            // climb to outermost inline
            Dwarf_Die cur = *die;
            while (dwarf_tag(&cur) == DW_TAG_inlined_subroutine) {
                // DW_AT_call_file / DW_AT_call_line → where it was inlined
                Dwarf_Attribute a_cf, a_cl;
                if (dwarf_attr(&cur, DW_AT_call_file, &a_cf) &&
                    dwarf_attr(&cur, DW_AT_call_line, &a_cl)) {
                    Dwarf_Word cf = 0, cl = 0;
                    if (dwarf_formudata(&a_cf, &cf) == 0 &&
                        dwarf_formudata(&a_cl, &cl) == 0) {
                        Dwarf_Die cu_mem;
                        Dwarf_Die* cu = dwarf_diecu(&cur, &cu_mem, nullptr, nullptr);
                        outer_file = file_from_index_(cu, static_cast<int>(cf));
                        outer_line = static_cast<int>(cl);
                    }
                }
                // step to parent DIE
                Dwarf_Die parent;
                if (!dwarf_parent(&cur, &parent)) break;
                cur = parent;
            }
            if (const char* nm = canonical_die_name_(&cur)) outer_name = demangle_(nm);
        }

        if (outer_name.empty()) {
            // fallback: leaf-only
            return func_key_locked_(raw_ip, branch_target);
        }

        std::string out = (mod_name && *mod_name)
                        ? std::string(mod_name).append("!").append(outer_name)
                        : outer_name;

        // attach file:line if available
        if (!outer_file.empty() || !leaf_file.empty()) {
            out.append(" (").append(!outer_file.empty() ? outer_file : leaf_file);
            int lno = outer_line ? outer_line : leaf_line;
            if (lno > 0) {
                char ln[32]; std::snprintf(ln, sizeof(ln), ":%d", lno);
                out.append(ln);
            }
            out.push_back(')');
        }

        return out;
    }

    // -------------------------------------------------------------------------
    // DWFL session setup
    // -------------------------------------------------------------------------
    void init_dwfl_() {
        std::lock_guard<std::mutex> g(m_);
        if (dwfl_) return;

        static Dwfl_Callbacks cb;

        // find_elf: how to resolve ELF objects from /proc/<pid>/maps entries
        cb.find_elf        = dwfl_linux_proc_find_elf;

        // find_debuginfo: how to resolve debug info (separate .dbg, build-id, debuginfod)
        cb.find_debuginfo  = dwfl_standard_find_debuginfo;

        // section_address: maps ELF section offsets to memory addresses
        cb.section_address = dwfl_offline_section_address;

        // dwfl_begin: create a new libdwfl session
        dwfl_ = dwfl_begin(&cb);

        // Populate module list immediately
        maps_ok_ = report_locked_();
    }

    bool report_locked_() {
        if (!dwfl_) return false;

        // dwfl_linux_proc_report:
        //   Parse /proc/<pid>/maps, register each loaded ELF module into the session
        if (dwfl_linux_proc_report(dwfl_, pid_) != 0) return false;

        // dwfl_report_end:
        //   Signal that module list is complete (no more additions).
        if (dwfl_report_end(dwfl_, nullptr, nullptr) != 0) return false;

        return true;
    }

private:
    pid_t   pid_;
    Dwfl*   dwfl_    = nullptr;
    bool    maps_ok_ = false;
    std::mutex m_;
};
