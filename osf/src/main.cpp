#include "osf/config.hpp"
#include "osf/logging.hpp"
#include "osf/target.hpp"
#include "osf/recon.hpp"
#include "osf/analysis.hpp"
#include "osf/module_registry.hpp"
#include "osf/reporting.hpp"

#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;
using namespace osf;

namespace {

void printUsage(const char* argv0) {
    std::cout <<
        "Usage: " << argv0 << " --target <ip> --scope-file <path> [options]\n\n"
        "Required:\n"
        "  --target <ip>          Target IPv4/IPv6 address to assess.\n"
        "  --scope-file <path>    File listing authorized addresses/CIDRs (one per line).\n\n"
        "Optional:\n"
        "  --config <path>        Config file (key=value).\n"
        "  --vuln-db <path>       Correlation database (see data/example_vuln_db.txt).\n"
        "  --enable-module <name> Enable a registered attack module (repeatable).\n"
        "  --module-opt <k=v>     Pass an option to the most recently named --enable-module.\n"
        "  --confirm-destructive  Required to run modules that self-report as destructive.\n"
        "  --out-dir <path>       Directory for reports and evidence (default: ./osf_out).\n"
        "  --port-range <range>   nmap port range (default: 1-1000).\n"
        "  --timeout <seconds>    Recon timeout (default: 120).\n"
        "  --list-modules         List registered attack modules and exit.\n"
        "  --log-level <lvl>      debug|info|warn|error (default: info).\n"
        "  -h, --help             Show this help.\n";
}

std::string nowUtcIso8601() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

LogLevel parseLogLevel(const std::string& s) {
    if (s == "debug") return LogLevel::Debug;
    if (s == "warn") return LogLevel::Warn;
    if (s == "error") return LogLevel::Error;
    return LogLevel::Info;
}

} // namespace

int main(int argc, char** argv) {
    std::string targetArg, scopeFile, configFile, vulnDbPath, outDir = "osf_out";
    std::string portRange = "1-1000";
    int timeoutSeconds = 120;
    bool confirmDestructive = false;
    bool listModulesOnly = false;
    std::string logLevelStr = "info";

    struct ModuleRequest { std::string name; std::map<std::string, std::string> options; };
    std::vector<ModuleRequest> moduleRequests;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) { std::cerr << "missing value for " << flag << "\n"; std::exit(2); }
            return argv[++i];
        };

        if (arg == "-h" || arg == "--help") { printUsage(argv[0]); return 0; }
        else if (arg == "--target") targetArg = next("--target");
        else if (arg == "--scope-file") scopeFile = next("--scope-file");
        else if (arg == "--config") configFile = next("--config");
        else if (arg == "--vuln-db") vulnDbPath = next("--vuln-db");
        else if (arg == "--out-dir") outDir = next("--out-dir");
        else if (arg == "--port-range") portRange = next("--port-range");
        else if (arg == "--timeout") timeoutSeconds = std::stoi(next("--timeout"));
        else if (arg == "--confirm-destructive") confirmDestructive = true;
        else if (arg == "--list-modules") listModulesOnly = true;
        else if (arg == "--log-level") logLevelStr = next("--log-level");
        else if (arg == "--enable-module") {
            moduleRequests.push_back({next("--enable-module"), {}});
        } else if (arg == "--module-opt") {
            std::string kv = next("--module-opt");
            auto eq = kv.find('=');
            if (eq == std::string::npos || moduleRequests.empty()) {
                std::cerr << "--module-opt must follow --enable-module and be key=value\n";
                return 2;
            }
            moduleRequests.back().options[kv.substr(0, eq)] = kv.substr(eq + 1);
        } else {
            std::cerr << "unknown argument: " << arg << "\n";
            printUsage(argv[0]);
            return 2;
        }
    }

    Logger::instance().setLevel(parseLogLevel(logLevelStr));

    if (listModulesOnly) {
        std::cout << "Registered attack modules:\n";
        for (const auto& n : ModuleRegistry::instance().listNames()) {
            auto mod = ModuleRegistry::instance().create(n);
            std::cout << "  " << n << " - " << (mod ? mod->description() : "") << "\n";
        }
        return 0;
    }

    if (targetArg.empty() || scopeFile.empty()) {
        std::cerr << "error: --target and --scope-file are required\n\n";
        printUsage(argv[0]);
        return 2;
    }

    fs::create_directories(outDir);
    Logger::instance().setLogFile(outDir + "/run.log");

    Config config;
    if (!configFile.empty()) {
        std::string err;
        if (!config.loadFromFile(configFile, err)) {
            Logger::instance().error("main", err);
            return 1;
        }
    }

    // ---- 1. Target acquisition and validation ----
    auto targetOpt = validateAddress(targetArg);
    if (!targetOpt) {
        Logger::instance().error("main", "invalid IPv4/IPv6 address: " + targetArg);
        return 1;
    }
    Target target = *targetOpt;

    // ---- Scope enforcement (must pass before ANYTHING else happens) ----
    ScopeValidator scope;
    {
        std::string err;
        if (!scope.loadFromFile(scopeFile, err)) {
            Logger::instance().error("main", err);
            return 1;
        }
    }
    if (!scope.isInScope(target)) {
        Logger::instance().error("main",
            "REFUSING TO PROCEED: target " + target.normalized +
            " is not covered by any rule in " + scopeFile);
        return 1;
    }
    Logger::instance().info("main", "target " + target.normalized + " is in authorized scope ("
                             + std::to_string(scope.ruleCount()) + " rule(s) loaded)");

    // ---- 2. Reconnaissance and enumeration ----
    ReconEngine recon(outDir + "/evidence");
    ReconOptions reconOpts;
    reconOpts.portRange = portRange;
    reconOpts.timeout = std::chrono::seconds(timeoutSeconds);
    ReconResult reconResult = recon.run(target, reconOpts);

    // ---- 3. Attack-surface analysis ----
    AnalysisEngine analysis;
    std::vector<Finding> findings;
    if (!vulnDbPath.empty()) {
        std::string err;
        if (!analysis.loadDatabase(vulnDbPath, err)) {
            Logger::instance().warn("main", "vuln DB not loaded: " + err);
        } else if (reconResult.success) {
            findings = analysis.correlate(reconResult);
        }
    }

    // ---- 4/5/6. Attack-module execution (the plugin boundary) ----
    std::vector<ModuleResult> moduleResults;
    for (const auto& req : moduleRequests) {
        auto mod = ModuleRegistry::instance().create(req.name);
        if (!mod) {
            Logger::instance().error("main", "unknown module: " + req.name);
            continue;
        }
        if (mod->requiresExplicitConfirmation() && !confirmDestructive) {
            Logger::instance().warn("main", "module '" + req.name +
                "' requires --confirm-destructive; skipping");
            continue;
        }
        mod->configure(req.options);
        ModuleResult r = mod->run(target, scope, reconResult, findings);
        moduleResults.push_back(std::move(r));
    }

    // ---- 8. Reporting ----
    EngagementReport report;
    report.target = target;
    report.timestampUtc = nowUtcIso8601();
    report.recon = reconResult;
    report.findings = findings;
    report.moduleResults = moduleResults;

    std::string jsonPath = outDir + "/report.json";
    std::string mdPath = outDir + "/report.md";
    std::string err;
    if (!ReportGenerator::writeJson(report, jsonPath, err)) Logger::instance().error("main", err);
    if (!ReportGenerator::writeMarkdown(report, mdPath, err)) Logger::instance().error("main", err);

    std::cout << "Done. Reports written to:\n  " << jsonPath << "\n  " << mdPath << "\n";
    return 0;
}
