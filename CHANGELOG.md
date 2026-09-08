# Changelog

## v0.1.0 — 2026-09-08

First public release. `v4scan` is a **deterministic install-time supply-chain scanner** for MCP
servers and AI-agent skill packages.

### What it does

Reads a package's install scripts, manifest, and source **before** `npm install` / `pip install`
runs, and reports what would execute during installation. Exits `1` on any High/Critical finding so
it can gate a pipeline.

### Detection signals

| Signal | Severity | Catches |
|---|---|---|
| `V4-INSTALL-EXEC` | High | Risky commands in `preinstall`/`install`/`postinstall` |
| `V4-TYPOSQUAT` | High | Name within edit-distance 1–2 of a popular package |
| `V4-OBF-EVAL` | High | Decode-**then**-execute (`eval(atob(...))`, `new Function(base64...)`) |
| `V4-NET-EGRESS` | Medium | Network calls during install |
| `V4-OBF-ENTROPY` | Medium | High-entropy blocks (first-party code only) |
| `V4-OBF-B64` | Medium | Long base64-style runs (first-party code only) |
| `V4-NO-PROVENANCE` | Medium | No SLSA / sigstore / in-toto attestation |
| `V4-OBF-DECODE` | Low | Benign decode primitives alone — informational, does **not** gate CI |
| `V4-THIN-META` | Low | Manifest missing `repository` / `license` |

Precision note: `V4-OBF-DECODE` exists specifically so ordinary `atob` / `Buffer.from` usage does
**not** produce a blocking High. Only decode-**then**-execute does.

### Output

- JSON (default), human-readable with `--explain`
- SARIF 2.1.0 with `--sarif`, including full `rules` metadata so each `ruleId` resolves in
  consumers such as GitHub code scanning

### Distribution

- Single binary: `cargo build --release` (or `cargo install --path .`)
- GitHub Action: `.github/workflows/v4-scan.yml`
- pre-commit hook: `.pre-commit-hooks.yaml`

### Verified behaviour (not asserted — executed)

- `cargo test --release`: **9 / 9 pass**
- Six fixtures: `01` `curl | sh`, `02` typosquat, `03` decode-exec, `04` install exfil all
  **exit 1** with a High; `05` benign-thin and `06` benign-decode both **exit 0** with no High
- SARIF validated: parses as 2.1.0, `ruleIndex` resolves to the correct rule for every result

### Known limitations

- A first-pass static heuristic — not a substitute for `npm audit`, `pip-audit`, Sigstore
  verification, or a runtime sandbox. It executes nothing.
- Coverage is intentionally narrow: **MCP servers and AI-agent skill packages first**, not all of
  npm/PyPI.
- Thresholds (entropy `> 4.6`, base64 run `>= 24`) were tuned against ~170 real packages and will
  need further tuning against a broader corpus.
- No novel malicious artifact has been caught yet — see `VALIDATION.md`, Condition #3
  (currently **INCONCLUSIVE**, not failed).
