#include "test_harness.hpp"
#include "osf/target.hpp"

using namespace osf;

TEST_CASE(ValidatesIpv4) {
    auto t = validateAddress("192.0.2.10");
    REQUIRE(t.has_value());
    REQUIRE(t->family == AddressFamily::IPv4);
    REQUIRE(t->normalized == "192.0.2.10");
}

TEST_CASE(ValidatesIpv6) {
    auto t = validateAddress("2001:db8::1");
    REQUIRE(t.has_value());
    REQUIRE(t->family == AddressFamily::IPv6);
}

TEST_CASE(RejectsGarbage) {
    REQUIRE_FALSE(validateAddress("not-an-ip").has_value());
    REQUIRE_FALSE(validateAddress("999.999.999.999").has_value());
    REQUIRE_FALSE(validateAddress("").has_value());
}

TEST_CASE(RejectsNetworkAsTarget) {
    // A bare target must be a host address, not a CIDR network.
    REQUIRE_FALSE(validateAddress("192.0.2.0/24").has_value());
}
