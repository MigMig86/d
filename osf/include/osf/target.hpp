#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace osf {

enum class AddressFamily { IPv4, IPv6 };

struct Target {
    std::string raw;        // as given by the user
    std::string normalized; // canonical textual form
    AddressFamily family;
};

// Validates a textual IPv4/IPv6 address and returns a normalized Target.
// Returns std::nullopt if the string is not a syntactically valid address.
// Does NOT resolve hostnames on purpose: scope enforcement must operate on
// concrete addresses, not names that could change under the operator.
std::optional<Target> validateAddress(const std::string& address);

// A single scope rule: either an exact address or a CIDR network
// (e.g. "203.0.113.10" or "203.0.113.0/24" or "2001:db8::/32").
struct ScopeRule {
    std::string text;
    AddressFamily family;
    std::vector<uint8_t> networkBytes; // address bytes, masked
    int prefixLen;
};

// Holds the explicit, operator-approved list of addresses/ranges a test run
// is permitted to touch. Every recon/analysis/attack action must be checked
// against this before it executes.
class ScopeValidator {
public:
    // Loads one rule per line from a text file (blank lines and lines
    // starting with '#' are ignored).
    bool loadFromFile(const std::string& path, std::string& errorOut);

    // Adds a single rule programmatically (e.g. from --scope on the CLI).
    bool addRule(const std::string& ruleText, std::string& errorOut);

    bool isInScope(const Target& target) const;

    size_t ruleCount() const { return rules_.size(); }

private:
    std::vector<ScopeRule> rules_;
};

} // namespace osf
