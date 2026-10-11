#include "osf/reporting.hpp"
#include <fstream>
#include <sstream>

namespace osf {

namespace {

std::string jsonEscape(const std::string& s) {
    std::ostringstream out;
    for (char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out << buf;
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

std::string jstr(const std::string& s) { return "\"" + jsonEscape(s) + "\""; }

} // namespace

bool ReportGenerator::writeJson(const EngagementReport& report, const std::string& path, std::string& errorOut) {
    std::ofstream out(path);
    if (!out) { errorOut = "cannot open " + path + " for writing"; return false; }

    out << "{\n";
    out << "  \"timestamp_utc\": " << jstr(report.timestampUtc) << ",\n";
    out << "  \"target\": {\n";
    out << "    \"raw\": " << jstr(report.target.raw) << ",\n";
    out << "    \"normalized\": " << jstr(report.target.normalized) << ",\n";
    out << "    \"family\": " << jstr(report.target.family == AddressFamily::IPv4 ? "IPv4" : "IPv6") << "\n";
    out << "  },\n";

    out << "  \"recon\": {\n";
    out << "    \"success\": " << (report.recon.success ? "true" : "false") << ",\n";
    out << "    \"error\": " << jstr(report.recon.errorMessage) << ",\n";
    out << "    \"raw_output_path\": " << jstr(report.recon.rawToolOutputPath) << ",\n";
    out << "    \"services\": [\n";
    for (size_t i = 0; i < report.recon.services.size(); ++i) {
        const auto& s = report.recon.services[i];
        out << "      {\"port\": " << s.port
            << ", \"protocol\": " << jstr(s.protocol)
            << ", \"state\": " << jstr(s.state)
            << ", \"service\": " << jstr(s.service)
            << ", \"version\": " << jstr(s.version) << "}";
        out << (i + 1 < report.recon.services.size() ? ",\n" : "\n");
    }
    out << "    ]\n";
    out << "  },\n";

    out << "  \"findings\": [\n";
    for (size_t i = 0; i < report.findings.size(); ++i) {
        const auto& f = report.findings[i];
        out << "    {\"port\": " << f.service.port
            << ", \"service\": " << jstr(f.service.service)
            << ", \"version\": " << jstr(f.service.version)
            << ", \"identifier\": " << jstr(f.matchedEntry.identifier)
            << ", \"severity\": " << jstr(severityToString(f.matchedEntry.severity))
            << ", \"description\": " << jstr(f.matchedEntry.description)
            << ", \"remediation\": " << jstr(f.matchedEntry.remediation) << "}";
        out << (i + 1 < report.findings.size() ? ",\n" : "\n");
    }
    out << "  ],\n";

    out << "  \"module_results\": [\n";
    for (size_t i = 0; i < report.moduleResults.size(); ++i) {
        const auto& m = report.moduleResults[i];
        out << "    {\"module\": " << jstr(m.moduleName)
            << ", \"executed\": " << (m.executed ? "true" : "false")
            << ", \"outcome_positive\": " << (m.outcomePositive ? "true" : "false")
            << ", \"summary\": " << jstr(m.summary)
            << ", \"error\": " << jstr(m.errorMessage)
            << ", \"evidence\": [";
        for (size_t j = 0; j < m.evidence.size(); ++j) {
            out << jstr(m.evidence[j]) << (j + 1 < m.evidence.size() ? ", " : "");
        }
        out << "]}";
        out << (i + 1 < report.moduleResults.size() ? ",\n" : "\n");
    }
    out << "  ]\n";
    out << "}\n";
    return true;
}

bool ReportGenerator::writeMarkdown(const EngagementReport& report, const std::string& path, std::string& errorOut) {
    std::ofstream out(path);
    if (!out) { errorOut = "cannot open " + path + " for writing"; return false; }

    out << "# Engagement Report\n\n";
    out << "- **Timestamp (UTC):** " << report.timestampUtc << "\n";
    out << "- **Target:** " << report.target.normalized
        << " (" << (report.target.family == AddressFamily::IPv4 ? "IPv4" : "IPv6") << ")\n\n";

    out << "## Reconnaissance\n\n";
    if (!report.recon.success) {
        out << "Recon failed: " << report.recon.errorMessage << "\n\n";
    } else {
        out << "| Port | Proto | State | Service | Version |\n";
        out << "|---|---|---|---|---|\n";
        for (const auto& s : report.recon.services) {
            out << "| " << s.port << " | " << s.protocol << " | " << s.state << " | "
                << s.service << " | " << s.version << " |\n";
        }
        out << "\n";
    }

    out << "## Findings (attack-surface correlation)\n\n";
    if (report.findings.empty()) {
        out << "No correlated findings.\n\n";
    } else {
        out << "| Port | Service | Severity | Identifier | Description | Remediation |\n";
        out << "|---|---|---|---|---|---|\n";
        for (const auto& f : report.findings) {
            out << "| " << f.service.port << " | " << f.service.service << " | "
                << severityToString(f.matchedEntry.severity) << " | "
                << f.matchedEntry.identifier << " | " << f.matchedEntry.description << " | "
                << f.matchedEntry.remediation << " |\n";
        }
        out << "\n";
    }

    out << "## Module Results\n\n";
    if (report.moduleResults.empty()) {
        out << "No modules were run.\n\n";
    } else {
        for (const auto& m : report.moduleResults) {
            out << "### " << m.moduleName << "\n\n";
            out << "- Executed: " << (m.executed ? "yes" : "no") << "\n";
            out << "- Outcome positive: " << (m.outcomePositive ? "yes" : "no") << "\n";
            if (!m.errorMessage.empty()) out << "- Error: " << m.errorMessage << "\n";
            out << "- Summary: " << m.summary << "\n";
            if (!m.evidence.empty()) {
                out << "- Evidence:\n";
                for (const auto& e : m.evidence) out << "  - " << e << "\n";
            }
            out << "\n";
        }
    }
    return true;
}

} // namespace osf
