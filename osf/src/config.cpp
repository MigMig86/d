#include "osf/config.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace osf {

namespace {
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
}

bool Config::loadFromFile(const std::string& path, std::string& errorOut) {
    std::ifstream in(path);
    if (!in) {
        errorOut = "cannot open config file: " + path;
        return false;
    }
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        auto eq = t.find('=');
        if (eq == std::string::npos) {
            errorOut = path + ":" + std::to_string(lineNo) + ": expected key=value";
            return false;
        }
        std::string key = trim(t.substr(0, eq));
        std::string val = trim(t.substr(eq + 1));
        values_[key] = val;
    }
    return true;
}

void Config::setOverride(const std::string& key, const std::string& value) {
    values_[key] = value;
}

bool Config::has(const std::string& key) const {
    return values_.find(key) != values_.end();
}

std::string Config::getString(const std::string& key, const std::string& def) const {
    auto it = values_.find(key);
    return it == values_.end() ? def : it->second;
}

int Config::getInt(const std::string& key, int def) const {
    auto it = values_.find(key);
    if (it == values_.end()) return def;
    try { return std::stoi(it->second); } catch (...) { return def; }
}

bool Config::getBool(const std::string& key, bool def) const {
    auto it = values_.find(key);
    if (it == values_.end()) return def;
    std::string v = it->second;
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c){ return std::tolower(c); });
    if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    return def;
}

std::vector<std::string> Config::getList(const std::string& key) const {
    std::vector<std::string> out;
    std::string raw = getString(key, "");
    if (raw.empty()) return out;
    std::stringstream ss(raw);
    std::string item;
    while (std::getline(ss, item, ',')) {
        std::string t = trim(item);
        if (!t.empty()) out.push_back(t);
    }
    return out;
}

} // namespace osf
