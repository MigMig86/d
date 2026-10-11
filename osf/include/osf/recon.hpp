#pragma once
#include "osf/target.hpp"
#include <string>
#include <vector>
#include <chrono>

namespace osf {

struct ServiceInfo {
    int port = 0;
    std::string protocol;   // "tcp" / "udp"
    std::string state;      // "open", "closed", "filtered"
    std::string service;    // nmap's service guess, e.g. "http"
    std::string version;    // nmap's version string, if detected
};

struct ReconResult {
    std::string targetNormalized;
    bool success = false;
    std::string errorMessage;
    std::vector<ServiceInfo> services;
    std::string rawToolOutputPath; // path to saved nmap XML, for evidence
};

struct ReconOptions {
    std::string portRange = "1-1000";
    bool serviceVersionDetection = true;   // nmap -sV
    std::chrono::seconds timeout{120};
    int maxRatePps = 100;                  // passed to nmap --max-rate
    std::string nmapBinary = "nmap";
};

// Thin orchestration layer around nmap: builds a scoped command line,
// enforces a timeout, captures XML output to disk for the report/evidence
// trail, and parses the ports/services/versions out of it.
//
// This class performs reconnaissance only. It never sends exploit
// payloads and never shells out to anything other than nmap.
class ReconEngine {
public:
    explicit ReconEngine(std::string workDir);

    ReconResult run(const Target& target, const ReconOptions& options) const;

private:
    std::string workDir_;
    std::string buildCommand(const Target& target, const ReconOptions& options,
                              const std::string& xmlOutPath) const;
    bool parseNmapXml(const std::string& xmlPath, ReconResult& result) const;
};

} // namespace osf
