#pragma once
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <sstream>

namespace testing {

struct TestCase { std::string name; std::function<void()> fn; };
std::vector<TestCase>& registry();

struct Registrar {
    Registrar(const std::string& name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

} // namespace testing

#define TEST_CASE(Name) \
    void Name(); \
    static ::testing::Registrar _reg_##Name(#Name, Name); \
    void Name()

#define REQUIRE(cond) \
    do { if (!(cond)) { \
        std::ostringstream _ss; _ss << "REQUIRE failed: " #cond " at " __FILE__ ":" << __LINE__; \
        throw std::runtime_error(_ss.str()); \
    } } while (0)

#define REQUIRE_FALSE(cond) REQUIRE(!(cond))
