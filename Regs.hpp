#pragma once
#include <cstdint>

// Minimal register snapshot to pass in from your perf SAMPLE_REGS_USER.
// Map perf's compacted array into this struct once per sample.
namespace perfctx {

struct Regs {
  // For x86-64, we store by perf register enum index.
  // If you want portable code: add an enum + map per arch.
  uint64_t vals[32] = {0};
  uint64_t mask = 0; // bitmask of which indices are valid (same as sample_regs_user)
};

// Helpers for x86-64 perf register indices.
// These constants match linux/perf_event.h's PERF_REG_X86_* ordering.
enum X86RegIndex {
  RAX=0, RBX=3, RCX=2, RDX=1, RSI=4, RDI=5, RBP=6, RSP=7,
  R8=8, R9=9, R10=10, R11=11, R12=12, R13=13, R14=14, R15=15,
  RIP=16,
};

inline uint64_t get_reg(const Regs& r, int idx) {
  return (r.mask & (1ull<<idx)) ? r.vals[idx] : 0;
}

} // namespace perfctx
