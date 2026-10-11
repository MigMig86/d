#include "osf/target.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>
#include <sstream>
#include <fstream>
#include <algorithm>

namespace osf {

namespace {

// Parses "addr" or "addr/prefix" into raw bytes + prefix length.
// Returns false if the address portion doesn't parse.
bool parseAddrAndPrefix(const std::string& text, AddressFamily& familyOut,
                         std::vector<uint8_t>& bytesOut, int& prefixOut) {
    std::string addrPart = text;
    int prefix = -1;

    auto slash = text.find('/');
    if (slash != std::string::npos) {
        addrPart = text.substr(0, slash);
        try {
            prefix = std::stoi(text.substr(slash + 1));
        } catch (...) {
            return false;
        }
    }

    unsigned char buf4[sizeof(in_addr)];
    unsigned char buf6[sizeof(in6_addr)];

    if (inet_pton(AF_INET, addrPart.c_str(), buf4) == 1) {
        familyOut = AddressFamily::IPv4;
        bytesOut.assign(buf4, buf4 + sizeof(buf4));
        prefixOut = (prefix < 0) ? 32 : prefix;
        return prefixOut >= 0 && prefixOut <= 32;
    }
    if (inet_pton(AF_INET6, addrPart.c_str(), buf6) == 1) {
        familyOut = AddressFamily::IPv6;
        bytesOut.assign(buf6, buf6 + sizeof(buf6));
        prefixOut = (prefix < 0) ? 128 : prefix;
        return prefixOut >= 0 && prefixOut <= 128;
    }
    return false;
}

void applyMask(std::vector<uint8_t>& bytes, int prefixLen) {
    int fullBytes = prefixLen / 8;
    int remBits = prefixLen % 8;
    for (size_t i = static_cast<size_t>(fullBytes); i < bytes.size(); ++i) {
        if (static_cast<int>(i) == fullBytes && remBits > 0) {
            uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remBits));
            bytes[i] &= mask;
        } else if (static_cast<int>(i) >= fullBytes) {
            bytes[i] = 0;
        }
    }
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

} // namespace

std::optional<Target> validateAddress(const std::string& address) {
    AddressFamily family;
    std::vector<uint8_t> bytes;
    int prefix;
    if (!parseAddrAndPrefix(address, family, bytes, prefix)) return std::nullopt;

    // A bare target must be a host address, not a network.
    if ((family == AddressFamily::IPv4 && prefix != 32) ||
        (family == AddressFamily::IPv6 && prefix != 128)) {
        return std::nullopt;
    }

    char normBuf[INET6_ADDRSTRLEN] = {0};
    if (family == AddressFamily::IPv4) {
        inet_ntop(AF_INET, bytes.data(), normBuf, sizeof(normBuf));
    } else {
        inet_ntop(AF_INET6, bytes.data(), normBuf, sizeof(normBuf));
    }

    Target t;
    t.raw = address;
    t.normalized = normBuf;
    t.family = family;
    return t;
}

bool ScopeValidator::addRule(const std::string& ruleText, std::string& errorOut) {
    AddressFamily family;
    std::vector<uint8_t> bytes;
    int prefix;
    if (!parseAddrAndPrefix(ruleText, family, bytes, prefix)) {
        errorOut = "invalid scope rule: '" + ruleText + "'";
        return false;
    }
    applyMask(bytes, prefix);

    ScopeRule rule;
    rule.text = ruleText;
    rule.family = family;
    rule.networkBytes = bytes;
    rule.prefixLen = prefix;
    rules_.push_back(std::move(rule));
    return true;
}

bool ScopeValidator::loadFromFile(const std::string& path, std::string& errorOut) {
    std::ifstream in(path);
    if (!in) {
        errorOut = "cannot open scope file: " + path;
        return false;
    }
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        std::string err;
        if (!addRule(t, err)) {
            errorOut = "scope file " + path + " line " + std::to_string(lineNo) + ": " + err;
            return false;
        }
    }
    return true;
}

bool ScopeValidator::isInScope(const Target& target) const {
    AddressFamily family;
    std::vector<uint8_t> bytes;
    int prefix;
    if (!parseAddrAndPrefix(target.normalized, family, bytes, prefix)) return false;

    for (const auto& rule : rules_) {
        if (rule.family != family) continue;
        std::vector<uint8_t> masked = bytes;
        applyMask(masked, rule.prefixLen);
        if (masked == rule.networkBytes) return true;
    }
    return false;
}

} // namespace osf
