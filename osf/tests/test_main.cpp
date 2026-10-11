// Minimal self-contained test harness (no external dependencies).
// Swap this out for Catch2/GoogleTest in a real deployment if you want
// richer assertions/output; the TEST_CASE/REQUIRE macros below are just
// enough to keep the skeleton dependency-free and easy to build offline.
#include "test_harness.hpp"
#include <iostream>

namespace testing {
std::vector<TestCase>& registry() {
    static std::vector<TestCase> cases;
    return cases;
}
}

int main() {
    int failed = 0;
    for (auto& tc : testing::registry()) {
        try {
            tc.fn();
            std::cout << "[PASS] " << tc.name << "\n";
        } catch (const std::exception& e) {
            std::cout << "[FAIL] " << tc.name << ": " << e.what() << "\n";
            ++failed;
        }
    }
    std::cout << (testing::registry().size() - failed) << "/" << testing::registry().size()
              << " tests passed\n";
    return failed == 0 ? 0 : 1;
}
