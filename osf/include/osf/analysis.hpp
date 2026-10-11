#pragma once
#include "osf/recon.hpp"
#include <string>
#include <vector>

namespace osf {

enum class Severity { Info, Low, Medium, High, Critical };

struct VulnDbEntry {
    std::string serviceMatch;   // substring match against ServiceInfo.service
    std::string versionMatch;   // substring match against ServiceInfo.version ("" = any)
    std::string identifier;     // e.g. a CVE ID or internal finding ID
    std::string description;
    Severity severity = Severity::Info;
    std::string remediation;
};

struct Finding {
    ServiceInfo service;
    VulnDbEntry matchedEntry;
};

// Loads a small local correlation database and matches it against recon
// results. This is substring/heuristic correlation, not a live CVE feed —
// point it at NVD/OSV exports or your own curated data as needed.
class AnalysisEngine {
public:
    bool loadDatabase(const std::string& path, std::string& errorOut);
    std::vector<Finding> correlate(const ReconResult& recon) const;

    size_t entryCount() const { return entries_.size(); }

private:
    std::vector<VulnDbEntry> entries_;
};

const char* severityToString(Severity s);

} // namespace osf
