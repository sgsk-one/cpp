// example_dual.cpp
#include "xeon_profiler_dual.hpp"
#include <cmath>

static void worker() {
  XEON_SCOPE();
  volatile double s=0;
  for (int i=0; i<600000; ++i) s += std::sin(i);
}

static void hot_path() {
  XEON_SCOPE();
  for (int r=0; r<50; ++r) worker();
}

int main() {
  // 1000 Hz per stream, 4096 pages ring, also record collapsed stacks
  xeon::Profiler::init(1000, 4096, true);
  hot_path();
  xeon::Profiler::instance().dump_and_pause(
      "xeon_samples.csv", "xeon_frames.txt", "xeon_stats.txt",
      "xeon_stacks.addr", "resolve.gdb");
  return 0;
}
