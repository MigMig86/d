#pragma once
#include "osf/target.hpp"
#include "osf/recon.hpp"
#include "osf/analysis.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace osf {

struct ModuleResult {
    std::string moduleName;
    bool executed = false;       // did the module actually run (vs. skip)?
    bool outcomePositive = false; // did it conclude the condition it checks for is present?
    std::string summary;
    std::vector<std::string> evidence; // file paths, log excerpts, timestamps, etc.
    std::string errorMessage;
};

// ---------------------------------------------------------------------
// THE PLUGIN BOUNDARY
//
// This is the seam where actual security-test logic belongs. Nothing in
// this framework implements exploitation, credential attacks, payload
// delivery, or denial-of-service behavior — that is deliberately left to
// you to implement per-module, under your own authorization and scope
// controls, for each specific authorized engagement.
//
// Two realistic ways to implement a module:
//   1. Wrap an existing, vetted tool: shell out to Metasploit's
//      msfconsole/msfrpcd (RPC API), Nuclei, or another established
//      tool, parse its output, and translate it into a ModuleResult.
//   2. Implement a narrow, non-destructive PoC check yourself (e.g.
//      "does this HTTP server return the headers that indicate
//      unpatched version X") against systems you are explicitly
//      authorized to test — most commonly deliberately vulnerable lab
//      targets.
//
// Every module MUST call validateScope() and respect the result before
// doing anything that touches the network. The harness calls this for
// you before run(), but modules performing multi-target or follow-up
// actions internally must re-check it themselves.
// ---------------------------------------------------------------------
class AttackModule {
public:
    virtual ~AttackModule() = default;

    virtual std::string name() const = 0;
    virtual std::string description() const = 0;

    // Modules that could have any destructive/disruptive side effect
    // (even a "mostly safe" one) should return true here, and the CLI
    // will refuse to run them without an explicit --confirm-destructive
    // flag on top of being in scope. Default: false (safe/informational).
    virtual bool requiresExplicitConfirmation() const { return false; }

    // Called once before run(). Receives whatever key=value options were
    // configured for this module (from the config file / CLI).
    virtual void configure(const std::map<std::string, std::string>& options) = 0;

    // Executes the module's check/technique against `target`, given the
    // recon and analysis context already gathered for this engagement.
    // Implementations MUST confirm `scope.isInScope(target)` is true
    // (the harness already checks this before calling run(), but modules
    // that branch out to additional hosts must check again themselves).
    virtual ModuleResult run(const Target& target,
                              const ScopeValidator& scope,
                              const ReconResult& recon,
                              const std::vector<Finding>& findings) = 0;
};

using AttackModulePtr = std::shared_ptr<AttackModule>;

} // namespace osf
