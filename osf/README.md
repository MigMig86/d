# Offensive Security Framework — Skeleton

A C++20/CMake scaffold for authorized security testing work: target/scope
validation, recon orchestration, finding correlation, a plugin boundary for
attack modules, and JSON/Markdown reporting.

**This skeleton ships with zero exploitation logic.** The one included
module (`example_noop`) performs no network activity — it exists purely to
show how the plugin interface is wired up. Real attack techniques are
something you implement yourself, per authorized engagement, in the module
layer described below.

## Legal / ethical notice

Only point this at systems you have explicit, documented authorization to
test (your own lab VMs, a signed pentest engagement, a CTF you're entitled
to attack, etc.). The scope file (`--scope-file`) is enforced before any
recon or module runs — out-of-scope targets are refused — but that is a
safety rail, not a substitute for actually having authorization.

## Architecture

```
include/osf/            Public headers (the component interfaces)
  target.hpp             IPv4/IPv6 validation, ScopeValidator (CIDR-aware)
  config.hpp              key=value config file parsing
  logging.hpp             thread-safe leveled logger
  recon.hpp               nmap orchestration -> ReconResult
  analysis.hpp             ReconResult -> correlated Finding list
  attack_module.hpp       *** the plugin interface ***
  module_registry.hpp      self-registration registry for modules
  reporting.hpp             ReconResult+Findings+ModuleResults -> JSON/MD

src/                     Implementations of the above
src/modules/              Attack-module .cpp files live here (one per module)
  example_module.cpp       demonstration/template module (no network I/O)

tests/                   Minimal dependency-free unit test harness + tests
data/example_vuln_db.txt  Sample correlation database (pipe-delimited)
config/                  Sample scope file and config file
```

### Pipeline (src/main.cpp)

1. **Target validation** — parses/normalizes the `--target` IPv4/IPv6 address.
2. **Scope enforcement** — loads `--scope-file` (exact addresses and/or CIDR
   ranges, one per line) and refuses to proceed if the target isn't covered.
   This check happens before recon, analysis, or any module runs.
3. **Recon** — shells out to `nmap` (via `fork`/`execvp`, not a shell string,
   to avoid injection risk) with a bounded timeout and rate limit, saves the
   raw XML as evidence, and parses open ports/service/version info.
4. **Analysis** — correlates recon results against a local database
   (`--vuln-db`) of service/version → finding mappings.
5. **Attack modules** — runs any `--enable-module NAME` modules registered
   via the plugin interface, each re-checking scope itself before doing
   anything.
6. **Reporting** — writes `report.json` and `report.md` to `--out-dir`,
   including recon data, correlated findings, and module results/evidence.

## Building

Requirements: CMake ≥ 3.20, a C++20 compiler (GCC ≥ 10 or Clang ≥ 12),
pthreads. `nmap` must be installed and on `PATH` for the recon stage to do
anything (the tool degrades gracefully — with a clear error in the report —
if it isn't).

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

This produces:
- `build/osf` — the CLI
- `build/osf_tests` — the unit test binary (`ctest --test-dir build` also works)

## Running

```bash
# See what's registered
./build/osf --list-modules

# Define scope (required) — one address or CIDR per line
echo "192.168.56.101" > scope.txt

# Full run against an authorized lab target
./build/osf \
  --target 192.168.56.101 \
  --scope-file scope.txt \
  --vuln-db data/example_vuln_db.txt \
  --enable-module example_noop \
  --port-range 1-1000 \
  --timeout 120 \
  --out-dir ./osf_out

cat osf_out/report.md
```

An out-of-scope target is refused immediately:

```bash
./build/osf --target 8.8.8.8 --scope-file scope.txt
# -> ERROR: REFUSING TO PROCEED: target 8.8.8.8 is not covered by any rule in scope.txt
```

## Writing a real attack module

This is the part you own. Copy `src/modules/example_module.cpp` to a new
file, implement `AttackModule` (declared in `include/osf/attack_module.hpp`),
add the new `.cpp` to the `osf_core` sources in `CMakeLists.txt`, and
rebuild — `REGISTER_ATTACK_MODULE(YourClass)` handles registration, so
nothing else in the framework needs to change.

Two realistic implementation strategies:

1. **Wrap an established tool.** Shell out to Metasploit's `msfconsole`/
   `msfrpcd` RPC API (or Nuclei, or another vetted scanner), parse its
   output, and translate the result into a `ModuleResult`. This gets you a
   maintained, widely-reviewed exploit/check library instead of hand-rolled
   attack code, while this framework still handles scope enforcement,
   logging, and reporting around it.
2. **Implement a narrow, non-destructive PoC check yourself** — e.g.
   "does this service's banner/response match the signature of an unpatched
   version" — against systems you're explicitly authorized to test, most
   commonly deliberately-vulnerable lab targets (Metasploitable, VulnHub
   boxes, etc.).

Guidelines enforced/expected by the interface:
- `configure()` receives the module's options from `--module-opt key=value`.
- `run()` is handed the already-validated `Target`, the `ScopeValidator` (so
  multi-host or follow-up actions can re-check scope), and the recon/analysis
  context already gathered — modules shouldn't need to re-scan from scratch.
- `requiresExplicitConfirmation()` — return `true` for anything with a
  disruptive side effect; the CLI refuses to run such a module unless
  `--confirm-destructive` is also passed.
- Populate `ModuleResult.evidence` with file paths, timestamps, or log
  excerpts — this is what ends up in the report as your proof.

## Testing

```bash
cmake --build build -j
./build/osf_tests
# or
ctest --test-dir build --output-on-failure
```

The included harness (`tests/test_harness.hpp`) is a ~40-line dependency-free
`TEST_CASE`/`REQUIRE` shim, chosen so the skeleton builds offline with no
package manager. Swap in Catch2 or GoogleTest via `FetchContent` if you want
richer assertions/output — nothing else in the project depends on the choice.

## Extending the correlation database

`data/example_vuln_db.txt` is placeholder/illustrative data for a lab
environment, not a real feed. Format is pipe-delimited:

```
service|version_substring|identifier|severity|description|remediation
```

Generate real entries from NVD/OSV exports or vendor advisories for the
software actually present in your authorized target environment, or write a
small script to convert a CVE feed into this format (or extend
`AnalysisEngine::loadDatabase` to parse JSON directly if you'd rather not
pre-convert).

## What's intentionally NOT here

- No exploitation, payload delivery, or credential-attack code.
- No denial-of-service / flooding logic.
- No persistence or data-exfiltration logic.
- No hostname resolution in the scope path (scope is enforced against
  concrete addresses only, so it can't be bypassed by DNS changes).

These are excluded by design, per the stated constraints — add them only
inside your own modules, under your own authorization, for engagements
where they're explicitly in scope.
