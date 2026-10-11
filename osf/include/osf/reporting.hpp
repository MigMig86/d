#pragma once
#include "osf/target.hpp"
#include "osf/recon.hpp"
#include "osf/analysis.hpp"
#include "osf/attack_module.hpp"
#include <string>
#include <vector>

namespace osf {

struct EngagementReport {
    Target target;
    std::string timestampUtc;
    ReconResult recon;
    std::vector<Finding> findings;
    std::vector<ModuleResult> moduleResults;
};

class ReportGenerator {
public:
    static bool writeJson(const EngagementReport& report, const std::string& path, std::string& errorOut);
    static bool writeMarkdown(const EngagementReport& report, const std::string& path, std::string& errorOut);
};

} // namespace osf
