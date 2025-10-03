#pragma once
#include "Regs.hpp"
#include "DwflSession.hpp"
#include <string>
#include <optional>

namespace perfctx {

struct ThisResult {
  bool ok = false;
  uint64_t this_ptr = 0;
  bool from_dwarf = false;
  std::string type_name; // best-effort demangled
};

// Core: resolve `this` using DWARF location at IP.
// Falls back to ABI (RDI) if requested.
ThisResult resolve_this(DwflSession& session,
                        uint64_t ip,
                        const Regs& regs,
                        pid_t pid,
                        bool allow_fallback_rdi);

// Read a textual field from the object (e.g., char* or string-like).
// For char* we read pointed C string; for other types return a short hex dump string.
std::string read_object_text_field(DwflSession& session,
                                   pid_t pid,
                                   uint64_t this_ptr,
                                   const std::string& type_name_hint,
                                   const std::string& field_name);

} // namespace perfctx
