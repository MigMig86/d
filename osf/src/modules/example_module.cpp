// example_module.cpp
//
// Demonstration attack module. This is a template, not a technique: it
// performs NO network requests and NO exploitation. It only shows how a
// real module plugs into the harness — reading its own config, checking
// scope, reading the recon/analysis context it's handed, and returning a
// ModuleResult that the reporting layer can render.
//
// To implement a real, authorized module:
//   - Copy this file (e.g. to check_http_header_poc.cpp)
//   - Add it to the `osf_core` sources in CMakeLists.txt
//   - Implement run() to do ONE narrow, non-destructive check — e.g. call
//     out to Metasploit's RPC API and run a single auxiliary/scanner
//     module, or send one crafted-but-harmless request and inspect the
//     response — against hosts you have explicit authorization to test.
//   - Always check requiresExplicitConfirmation() semantics: if your
//     module could have ANY disruptive side effect, return true there.

#include "osf/attack_module.hpp"
#include "osf/module_registry.hpp"
#include "osf/logging.hpp"

namespace osf {

class ExampleNoOpModule : public AttackModule {
public:
    std::string name() const override { return "example_noop"; }

    std::string description() const override {
        return "Demonstration module: reports what it WOULD check, "
               "performs no network activity. Template for real modules.";
    }

    bool requiresExplicitConfirmation() const override { return false; }

    void configure(const std::map<std::string, std::string>& options) override {
        auto it = options.find("note");
        note_ = (it != options.end()) ? it->second : "";
    }

    ModuleResult run(const Target& target,
                      const ScopeValidator& scope,
                      const ReconResult& recon,
                      const std::vector<Finding>& findings) override {
        ModuleResult result;
        result.moduleName = name();

        // Every module must verify scope for itself, even though the
        // harness already checked before calling run().
        if (!scope.isInScope(target)) {
            result.executed = false;
            result.errorMessage = "target not in authorized scope; refusing to run";
            Logger::instance().error("module:" + name(), result.errorMessage);
            return result;
        }

        result.executed = true;
        result.outcomePositive = !findings.empty();
        result.summary = "No-op demo module ran against " + target.normalized +
                          ". Recon reported " + std::to_string(recon.services.size()) +
                          " port entries; analysis correlated " +
                          std::to_string(findings.size()) + " findings. " +
                          (note_.empty() ? "" : ("note=" + note_));
        result.evidence.push_back("source=recon.rawToolOutputPath:" + recon.rawToolOutputPath);

        Logger::instance().info("module:" + name(), result.summary);
        return result;
    }

private:
    std::string note_;
};

REGISTER_ATTACK_MODULE(ExampleNoOpModule);

} // namespace osf
