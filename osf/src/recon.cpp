#include "osf/recon.hpp"
#include "osf/logging.hpp"
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <filesystem>
#include <regex>

namespace fs = std::filesystem;

namespace osf {

ReconEngine::ReconEngine(std::string workDir) : workDir_(std::move(workDir)) {
    fs::create_directories(workDir_);
}

std::string ReconEngine::buildCommand(const Target&, const ReconOptions&,
                                       const std::string&) const {
    // Kept for documentation purposes; actual invocation uses an argv
    // vector (see run()) rather than a shell string, specifically to avoid
    // any shell-injection risk from target/option values.
    return "";
}

namespace {

// Runs argv via fork/exec (no shell), enforcing a wall-clock timeout.
// Returns the child's exit code, or -1 on internal failure / timeout.
int runWithTimeout(const std::vector<std::string>& argv, std::chrono::seconds timeout) {
    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        // Child: redirect stdout/stderr to /dev/null; XML output goes to -oX file.
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execvp(cargv[0], cargv.data());
        _exit(127); // exec failed
    }

    // Parent: watchdog thread sends SIGTERM/SIGKILL if we exceed the timeout.
    std::atomic<bool> finished{false};
    std::thread watchdog([&]() {
        auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!finished.load() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!finished.load()) {
            kill(pid, SIGTERM);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            kill(pid, SIGKILL);
        }
    });

    int status = 0;
    waitpid(pid, &status, 0);
    finished.store(true);
    watchdog.join();

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

// Extremely small, purpose-built extractor for the subset of nmap's XML
// we need (port/state/service/version). This is not a general XML parser;
// it is intentionally scoped to recon parsing only.
void parsePortsFromXml(const std::string& xml, std::vector<ServiceInfo>& out) {
    std::regex portBlockRe(R"re(<port protocol="([^"]+)" portid="(\d+)">([\s\S]*?)</port>)re");
    std::regex stateRe(R"re(<state state="([^"]+)")re");
    std::regex serviceRe(R"re(<service name="([^"]*)"(?:[^/]*product="([^"]*)")?(?:[^/]*version="([^"]*)")?)re");

    auto begin = std::sregex_iterator(xml.begin(), xml.end(), portBlockRe);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::smatch m = *it;
        ServiceInfo info;
        info.protocol = m[1].str();
        info.port = std::stoi(m[2].str());
        std::string block = m[3].str();

        std::smatch sm;
        if (std::regex_search(block, sm, stateRe)) info.state = sm[1].str();
        if (std::regex_search(block, sm, serviceRe)) {
            info.service = sm[1].str();
            std::string product = sm[2].matched ? sm[2].str() : "";
            std::string version = sm[3].matched ? sm[3].str() : "";
            if (!product.empty() || !version.empty()) {
                info.version = (product + " " + version);
                // trim trailing space
                while (!info.version.empty() && info.version.back() == ' ') info.version.pop_back();
            }
        }
        out.push_back(std::move(info));
    }
}

} // namespace

bool ReconEngine::parseNmapXml(const std::string& xmlPath, ReconResult& result) const {
    std::ifstream in(xmlPath);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    parsePortsFromXml(ss.str(), result.services);
    return true;
}

ReconResult ReconEngine::run(const Target& target, const ReconOptions& options) const {
    ReconResult result;
    result.targetNormalized = target.normalized;

    std::string xmlOut = workDir_ + "/recon_" + target.normalized + ".xml";
    for (auto& c : xmlOut) if (c == ':') c = '_'; // IPv6-safe filename

    std::vector<std::string> argv = {
        options.nmapBinary,
        "-p", options.portRange,
        "--max-rate", std::to_string(options.maxRatePps),
        "-oX", xmlOut,
        target.normalized
    };
    if (options.serviceVersionDetection) {
        argv.insert(argv.begin() + 1, "-sV");
    }
    if (target.family == AddressFamily::IPv6) {
        argv.insert(argv.begin() + 1, "-6");
    }

    Logger::instance().info("recon", "running nmap against " + target.normalized);
    int rc = runWithTimeout(argv, options.timeout);

    if (rc != 0) {
        result.success = false;
        result.errorMessage = "nmap exited with code " + std::to_string(rc) +
                               " (binary='" + options.nmapBinary + "', is it installed and on PATH?)";
        Logger::instance().warn("recon", result.errorMessage);
        return result;
    }

    if (!fs::exists(xmlOut) || !parseNmapXml(xmlOut, result)) {
        result.success = false;
        result.errorMessage = "failed to parse nmap XML output at " + xmlOut;
        return result;
    }

    result.success = true;
    result.rawToolOutputPath = xmlOut;
    Logger::instance().info("recon", "found " + std::to_string(result.services.size()) + " port entries");
    return result;
}

} // namespace osf
