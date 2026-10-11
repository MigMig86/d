#pragma once
#include <string>
#include <map>
#include <vector>
#include <optional>

namespace osf {

// Minimal key=value configuration (one setting per line, '#' comments).
// Deliberately simple — swap in a real TOML/YAML/JSON library if your
// deployment needs richer config; the rest of the framework only talks
// to this interface, not to the file format.
class Config {
public:
    bool loadFromFile(const std::string& path, std::string& errorOut);
    void setOverride(const std::string& key, const std::string& value);

    std::string getString(const std::string& key, const std::string& def = "") const;
    int getInt(const std::string& key, int def = 0) const;
    bool getBool(const std::string& key, bool def = false) const;

    // Comma-separated list, e.g. enabled_modules = example_noop,another_mod
    std::vector<std::string> getList(const std::string& key) const;

    bool has(const std::string& key) const;

private:
    std::map<std::string, std::string> values_;
};

} // namespace osf
