#include "osf/analysis.hpp"
#include "osf/logging.hpp"
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

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

Severity parseSeverity(const std::string& s) {
    std::string v = toLower(s);
    if (v == "critical") return Severity::Critical;
    if (v == "high") return Severity::High;
    if (v == "medium") return Severity::Medium;
    if (v == "low") return Severity::Low;
    return Severity::Info;
}
}

const char* severityToString(Severity s) {
    switch (s) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
        case Severity::Info: return "INFO";
    }
    return "INFO";
}

// DB format: one entry per line, pipe-delimited:
//   service|version_substring|identifier|severity|description|remediation
// version_substring may be empty to match any version of that service.
bool AnalysisEngine::loadDatabase(const std::string& path, std::string& errorOut) {
    std::ifstream in(path);
    if (!in) {
        errorOut = "cannot open vuln database: " + path;
        return false;
    }
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        std::vector<std::string> fields;
        std::stringstream ss(t);
        std::string field;
        while (std::getline(ss, field, '|')) fields.push_back(field);

        if (fields.size() < 6) {
            errorOut = path + ":" + std::to_string(lineNo) + ": expected 6 pipe-delimited fields";
            return false;
        }

        VulnDbEntry entry;
        entry.serviceMatch = trim(fields[0]);
        entry.versionMatch = trim(fields[1]);
        entry.identifier = trim(fields[2]);
        entry.severity = parseSeverity(trim(fields[3]));
        entry.description = trim(fields[4]);
        entry.remediation = trim(fields[5]);
        entries_.push_back(std::move(entry));
    }
    return true;
}

std::vector<Finding> AnalysisEngine::correlate(const ReconResult& recon) const {
    std::vector<Finding> findings;
    for (const auto& svc : recon.services) {
        if (svc.state != "open") continue;
        std::string svcLower = toLower(svc.service);
        std::string verLower = toLower(svc.version);

        for (const auto& entry : entries_) {
            if (svcLower.find(toLower(entry.serviceMatch)) == std::string::npos) continue;
            if (!entry.versionMatch.empty() &&
                verLower.find(toLower(entry.versionMatch)) == std::string::npos) continue;

            Finding f;
            f.service = svc;
            f.matchedEntry = entry;
            findings.push_back(std::move(f));
        }
    }
    Logger::instance().info("analysis", "correlated " + std::to_string(findings.size()) + " findings");
    return findings;
}

} // namespace osf
