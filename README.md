# v4scan

> **Scan MCP servers and AI-agent skill packages *before* you install them. Block suspicious install-time behavior — deterministically.**

`v4scan` is a small, zero-dependency Rust CLI that reads a package's install scripts,
manifest, and source *before* `npm install` / `pip install` runs — and tells you, with
**no model in the loop**, whether something risky is about to execute.

```bash
# Point it at any package directory you're about to install:
v4scan ./my-mcp-server --explain

# Or fail the build in CI on any High/Critical finding:
v4scan . --sarif        # exit code 1 => block the merge
```

## What it catches

| Signal | Severity | Catches |
|--------|----------|---------|
| `V4-INSTALL-EXEC` | **High** | Risky commands run during `preinstall`/`install`/`postinstall` (`curl\|sh`, `eval`, `base64`, `rm -rf`, `npm i`, …) |
| `V4-TYPOSQUAT`    | **High** | Package name within edit-distance 1–2 of a popular package |
| `V4-OBF-EVAL`     | **High** | Decode-**then**-execute only: `eval(atob(...))`, `eval(base64...)`, `new Function(atob...)` / `new Function(base64...)` |
| `V4-OBF-DECODE`   | Low | Benign decode primitives used alone (`atob(`, `buffer.from(`, `base64.b64decode`, `new Function(`). Informational — does **not** gate CI |
| `V4-NET-EGRESS`   | Medium | Network calls during install (exfiltration / second-stage pull) |
| `V4-OBF-ENTROPY`  | Medium | High-Shannon-entropy blocks (packed/encoded payloads), first-party code only |
| `V4-OBF-B64`      | Medium | Long base64-style runs, first-party code only |
| `V4-NO-PROVENANCE`| Medium | No SLSA / sigstore / in-toto attestation present |
| `V4-THIN-META`    | Low | Manifest missing `repository` / `license` |

## Why "deterministic"?

The block / allow decision is **fully auditable and reproducible**: the same input always
yields the same verdict. No model guesses. That is the whole point of a *firewall* for
supply-chain risk — when something malicious executes at install time, you need to be able
to prove *why* you missed it (or caught it), not argue about a model's mood.

## Install / build

```bash
# Standard (any machine with a Rust toolchain)
cargo build --release
# or install the binary
cargo install --path .

# On a box without the MSVC linker (some CI/sandbox images),
# use the gnu toolchain + MinGW gcc:
#   cargo +stable-x86_64-pc-windows-gnu build --release
```

## Wire it into CI / pre-commit

- **GitHub Action:** `.github/workflows/v4-scan.yml` — scans on every PR/push and uploads the SARIF report. Fails the build on any High/Critical.
- **pre-commit:** `.pre-commit-hooks.yaml` — add this repo as a hook to scan before commit.

## Examples

See [`examples/`](./examples) for five real packages and exactly what `v4scan` reports for
each — including the marquee `postinstall → curl | sh → payload` case.

## Limitations (what this is NOT)

- A **first-pass static heuristic**, not a substitute for `npm audit`, `pip-audit`,
  Sigstore verification, or a runtime sandbox.
- Thresholds (entropy `> 4.6`, base64 run `>= 24`) are starting points and need tuning
  against real packages to drive false positives down.
- It does **not** execute anything. It reads files and reports.

---

`v4scan` is the validation instrument for the **V4 hypothesis**: an install-time firewall
for the MCP / AI-agent-skill ecosystem that is cheap to run, deterministic, and
forwardable into existing security tooling.
