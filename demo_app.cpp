#include <atomic>
#include <cmath>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

struct Expression {
  const char* src; // kept at offset 0 to make demo obvious

  __attribute__((noinline))
  double evaluate(int iters) {
    volatile double acc = 0;
    for (int i = 0; i < iters; ++i) acc += std::sin(i * 0.01);
    return acc;
  }
};

int main() {
  std::vector<Expression> exprs{
    {"a + b * c"},
    {"(x^2 + y^2)^(1/2)"},
    {"sin(t) + cos(2t)"},
    {"IF(price > avg, buy, sell)"}
  };
  std::atomic<bool> stop{false};
  double sink = 0;
  while (!stop.load()) {
    for (auto& e : exprs) sink += e.evaluate(6000);
  }
  std::fprintf(stderr, "sink=%f\n", sink);
}
