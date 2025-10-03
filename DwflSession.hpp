#pragma once
#include <string>
#include <unordered_map>
#include <optional>
#include <elfutils/libdwfl.h>
#include <unistd.h>

namespace perfctx {

// RAII wrapper + caches around a live DWFL session for a PID.
class DwflSession {
public:
  explicit DwflSession(pid_t pid);
  ~DwflSession();
  DwflSession(const DwflSession&) = delete;
  DwflSession& operator=(const DwflSession&) = delete;

  bool ok() const { return dwfl_ != nullptr && memfd_ >= 0; }
  int  memfd() const { return memfd_; }
  pid_t pid() const { return pid_; }
  Dwfl* dwfl() const { return dwfl_; }

  // Map IP → (module, bias, DIE at PC)
  struct IpDie {
    Dwfl_Module* mod = nullptr;
    Dwarf_Die    die_mem{};
    Dwarf_Die*   die = nullptr;
    Dwarf_Addr   bias = 0;
  };
  std::optional<IpDie> ip_to_die(uint64_t ip);

  // Demangle & format module!symbol for display (best effort).
  std::string mod_and_symbol(uint64_t ip);

  // Cache a resolved offset for (type_die, member_name) → byte offset
  std::optional<uint64_t> cached_member_offset(Dwarf_Die* type_die, const std::string& member);
  void put_member_offset(Dwarf_Die* type_die, const std::string& member, uint64_t off);

  // Find the pointed-to class/struct DIE for a function's object pointer parameter.
  Dwarf_Die* find_object_param_die(Dwarf_Die* func_die, Dwarf_Die& out_param);
  // Given a type DIE, peel pointer/typedef layers to underlying class/struct
  Dwarf_Die* peel_typedefs_and_pointers(Dwarf_Die* die, Dwarf_Die& tmp);

  // Find a member offset by name in a class/struct (walks members; basic inheritance support).
  std::optional<uint64_t> member_offset_of(Dwarf_Die* class_die, const std::string& name);

  // Read user memory safely with cap
  ssize_t pread_user(void* dst, size_t n, uint64_t addr) const;

private:
  pid_t pid_;
  Dwfl* dwfl_ = nullptr;
  int   memfd_ = -1;

  struct OffsetKey {
    uint64_t cu_off; // CU-relative offset of type
    std::string member;
    bool operator==(const OffsetKey& o) const noexcept { return cu_off==o.cu_off && member==o.member; }
  };
  struct OffsetKeyHash {
    size_t operator()(OffsetKey const& k) const noexcept {
      return std::hash<uint64_t>{}(k.cu_off) ^ (std::hash<std::string>{}(k.member)<<1);
    }
  };
  std::unordered_map<OffsetKey, uint64_t, OffsetKeyHash> offset_cache_;
};

} // namespace perfctx
