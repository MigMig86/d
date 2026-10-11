#include "test_harness.hpp"
#include "osf/target.hpp"

using namespace osf;

TEST_CASE(ExactAddressInScope) {
    ScopeValidator scope;
    std::string err;
    REQUIRE(scope.addRule("203.0.113.10", err));
    auto t = validateAddress("203.0.113.10");
    REQUIRE(t.has_value());
    REQUIRE(scope.isInScope(*t));
}

TEST_CASE(AddressOutsideExactRuleIsRejected) {
    ScopeValidator scope;
    std::string err;
    REQUIRE(scope.addRule("203.0.113.10", err));
    auto t = validateAddress("203.0.113.11");
    REQUIRE(t.has_value());
    REQUIRE_FALSE(scope.isInScope(*t));
}

TEST_CASE(CidrRangeMatchesContainedAddress) {
    ScopeValidator scope;
    std::string err;
    REQUIRE(scope.addRule("203.0.113.0/24", err));
    auto inside = validateAddress("203.0.113.200");
    auto outside = validateAddress("203.0.114.1");
    REQUIRE(inside.has_value());
    REQUIRE(outside.has_value());
    REQUIRE(scope.isInScope(*inside));
    REQUIRE_FALSE(scope.isInScope(*outside));
}

TEST_CASE(Ipv6CidrRangeWorks) {
    ScopeValidator scope;
    std::string err;
    REQUIRE(scope.addRule("2001:db8::/32", err));
    auto inside = validateAddress("2001:db8::abcd");
    auto outside = validateAddress("2001:db9::1");
    REQUIRE(inside.has_value());
    REQUIRE(outside.has_value());
    REQUIRE(scope.isInScope(*inside));
    REQUIRE_FALSE(scope.isInScope(*outside));
}

TEST_CASE(EmptyScopeRejectsEverything) {
    ScopeValidator scope;
    auto t = validateAddress("203.0.113.10");
    REQUIRE(t.has_value());
    REQUIRE_FALSE(scope.isInScope(*t));
}

TEST_CASE(InvalidRuleTextIsRejected) {
    ScopeValidator scope;
    std::string err;
    REQUIRE_FALSE(scope.addRule("not-a-cidr", err));
    REQUIRE_FALSE(err.empty());
}
