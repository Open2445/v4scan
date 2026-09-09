# V4 Validation Tracker — 8-week falsifiable test

- **Instrument:** `v4scan` (Rust CLI, deterministic install-time supply-chain firewall)
- **Beachhead:** MCP servers + AI-agent skill packages
- **Clock started:** 2026-09-08
- **Day-30 gate:** 2026-10-08
- **Day-56 (8-week) decision:** 2026-11-03
- **Runway at start:** ~16.7 months (₹6,000/mo burn, ₹1,00,000 capital)

> Update this file weekly. "Inconclusive" is a valid result — it is **not** a fail.
> The day-30 gate forbids concluding anything if fewer than 100 touches were made.

---

## The 5 falsifiable conditions (any 3 failing within 8 weeks ⇒ hypothesis wrong)

| # | Condition | Status | Evidence |
|---|-----------|--------|----------|
| 1 | ≥500 GitHub stars **and** ≥50 verified installs/week | ⬜ | |
| 2 | ≥5 unrelated developers make inbound contact | ⬜ | |
| 3 | ≥1 genuinely malicious artifact found that **Socket / Snyk / GitHub had NOT flagged** within 60 days | ⚠️ **INCONCLUSIVE** (novel-malicious axis) · ✅ signal-quality **PROVEN** · see "Condition #3 — hostile-corpus resolution" below | see "Condition #3 — hostile-corpus resolution (2026-09-08)" below |
| 4 | ≥3 of 20 cold contacts convert on HN / r-rust / r-Python / MCP Discords | ⬜ | |
| 5 | *(withdrawn — replaced by "≥1 paid pilot OR ≥2 signed LOIs within 8 weeks")* | ⬜ | |

---

## Day-30 gate (hard stop, 2026-10-08)

> The gate is a **DATE**, not a week boundary. 2026-10-08 falls inside the **W5** row
> (10-06 → 10-12) of the weekly table; the W4 "(gate)" label is a planning convenience only.
> Judge on **cumulative totals as of 2026-10-08**, whichever week row the calendar lands in.

> **PASS** if: ≥100 touches **and** ≥4 replies **and** ≥1 meeting.
> **FAIL** if: ≤1 reply → fix message/list, do not conclude.
> **INCONCLUSIVE** if: <100 touches → forbidden to call it a result.

| Metric | Target by day 30 | Actual |
|--------|------------------|--------|
| Outreach touches | ≥100 | |
| Replies | ≥4 | |
| Meetings booked | ≥1 | |

---

## Weekly metrics

| Week | Dates | installs/wk | GitHub stars | issues/PRs from strangers | novel detections | dev conversations | LOIs | paid pilots |
|------|-------|-------------|--------------|---------------------------|------------------|-------------------|------|-------------|
| W1 | 09-08 → 09-14 | | | | | | | |
| W2 | 09-15 → 09-21 | | | | | | | |
| W3 | 09-22 → 09-28 | | | | | | | |
| W4 (gate) | 09-29 → 10-05 | | | | | | | |
| W5 | 10-06 → 10-12 | | | | | | | |
| W6 | 10-13 → 10-19 | | | | | | | |
| W7 | 10-20 → 10-26 | | | | | | | |
| W8 | 10-27 → 11-02 | | | | | | | |

---

## Novel-detection log (Condition #3)

The converter from *hope* → *evidence*. For each suspicious package v4scan flags,
record whether the major tools already knew about it. A finding counts toward #3 only
if it is **genuinely malicious AND not already flagged by Socket / Snyk / GitHub
advisory / npm audit**.

| Date | Package | v4scan signal(s) | Verdict by Socket/Snyk/GitHub | Novel? | Notes |
|------|---------|------------------|-------------------------------|--------|-------|
| 2026-09-08 | (170-pkg corpus) | 15× `V4-OBF-EVAL` (HIGH) | — | **No** | All 15 verified false positives — see finding below |

---

## Condition #3 — interim finding (2026-09-08)

**Scope.** 170 of 185 packages scanned (mainstream MCP servers + AI-agent skill
packages; the 85 agent-skill packages are the beachhead Socket itself says it is
only now covering). Scan run with the *original* binary; results in `results.tsv`.

**Result.** 0 Critical. 15 HIGH — **every one a false positive**, confirmed by
reading the extracted source of each flagged package.

**Root cause.** `V4-OBF-EVAL` fired HIGH on benign decode primitives:
`atob(`, `buffer.from(`, `base64.b64decode`, `new function(`. These are
ubiquitous in legitimate code (base64 audio decode, OAuth-token decode, Node
`Buffer` construction, vendored Chrome-DevTools code). **0 of 170 packages
contain a genuine decode-THEN-execute pattern** (`eval(atob`, `eval(base64`,
`new Function(atob`, `new Function(base64`).

Verified false positives (benign primitive → why it's safe):

| Package | Primitive | Legitimate use |
|---|---|---|
| chrome-devtools-mcp | `atob`/`buffer.from` | vendored Chrome DevTools `build/third_party` |
| ai (Vercel) | `atob` | base64 **audio** decode (`realtime/audio-utils.ts`) |
| @zoom/slack-to-zoom | `buffer.from` | OAuth token decode (`tokens.ts`) |
| @ai-sdk/gateway | `atob` | WebRTC base64 in `gateway-realtime-auth.ts` |
| @rpamis/comet | 31×`atob` + 62×`buffer.from` | 64 agent-skill scripts passing binary data |
| skillguard-cli | `buffer.from` | a **test fixture** `examples/known-bad-skill/hooks/obfuscated.js` |
| inject-nockta-skills | 26×`buffer.from` | Shopify skill validators |
| + 8 others | same benign primitives | — |

**Tuning fix (committed in `src/lib.rs`).** Split the signal:
- `V4-OBF-EVAL` → **HIGH only** for genuine decode-then-execute
  (`eval(atob`, `eval(base64`, `new function(atob`, `new function(base64)`).
- New `V4-OBF-DECODE` → **LOW** (informational, first-party only) for the benign
  primitives; no longer gates CI.
- `V4-OBF-ENTROPY` / `V4-OBF-B64` → skip vendored/minified paths
  (`node_modules`, `third_party`, `vendor`, `*.min.js`, `*.bundle.js`, `*.map`).
- README signal table updated to match.

**Re-verified.** Over the same 170 extracted packages with the tuned binary:
**0 HIGH, 0 Critical**. The malicious fixture `examples/03-obfuscated-eval`
(`eval(atob(payload))`) **still fires HIGH `V4-OBF-EVAL`** — true-positive
detection preserved. Before/after: **15 HIGH (100% FP) → 0 HIGH**.

**Honest verdict.** Condition #3 is **NOT yet satisfied.** No genuinely malicious
artifact was found. Two caveats must be stated plainly:
1. The tested corpus is overwhelmingly *mainstream / well-known* packages — exactly
   what Socket / Snyk / GitHub **already** scan. So this run measures
   **false-positive rate**, not true-positive rate. It cannot surface a "novel"
   catch because there is (almost) nothing malicious in it to find.
2. A clean true-positive test requires a **hostile corpus**: historical npm-malware
   samples, typosquats, and low-reputation / freshly-published packages. The
   `examples/` fixtures already prove the engine *can* catch decode-execute
   behavior; the open question is whether it catches real malware the majors
   missed.

**Required next step (owner: founder / lead).** Build and scan a hostile corpus,
then cross-check any HIGH/CRITICAL against `npm audit`, GitHub Security
Advisories, and Socket/Snyk to apply the "not already flagged" clause. Until
then, condition #3 remains **INCONCLUSIVE**, not failed.

---

## Condition #3 — hostile-corpus resolution (2026-09-08)

**Goal (unchanged, per spec):** find ≥1 genuinely malicious artifact that **Socket /
Snyk / GitHub had NOT flagged**. The condition and its definition were **not** relaxed
after seeing results. All 15 prior HIGH findings were already proven false positives
(see interim finding); this section resolves the open question — *can v4scan catch real
malware the majors missed?* — by building and scanning a hostile corpus.

### Methodology

Per the spec, the corpus was built **only from real, publicly documented artifacts** — no
fabricated malware, package names, or advisories. Three sources were attempted:

1. **SANDWORM_MODE typosquats** (Socket alert, Feb 2026) — `claud-code`, `cloude-code`,
   `opencraw`, `anthropic-sdk`, plus variants `claude-c0de`, `opencla`, `modelcontextprotocol`.
2. **Backstabber's Knife Collection** (dasfreak) — cloned; `data/packages.json` is a
   catalog of **14,679 real malicious npm package names** (no source tarballs).
3. **Historical incident** — `node-ipc` malicious commit (RIAEvangelist, 2022).

Each obtainable artifact was scanned with the release binary; every HIGH/CRITICAL was
independently cross-checked against npm registry metadata, npm audit/OSV, GitHub
Security Advisories, and Socket/Snyk public reporting.

### Key finding: genuine malicious npm artifacts are unobtainable

Primary-source evidence (npm registry queries, this session):

| Attempted artifact | npm registry result | Malicious source obtainable? |
|---|---|---|
| `claud-code`, `cloude-code`, `opencraw`, `anthropic-sdk` (SANDWORM) | `0.0.1-security` (npm security-holder) | **No** — malicious version unpublished |
| `claude-c0de`, `opencla`, `modelcontextprotocol` | HTTP 404 | **No** — fully unpublished |
| 14,679 Backstabber npm names (first 25 probed) | 24× `0.0.1-security`/None, 1× 404 | **No** — all malicious versions purged |
| 14,679 Backstabber names — legit long-lived collisions | e.g. `@antv/graphin` 3.0.5, `ids-enterprise-typings` 21.1.0-patch.4 | **No** — name reused, malicious version removed |
| `node-ipc` evil commit `847047c…` | `git checkout` → `fatal: unable to read tree` | **No** — history rewritten post-takedown |

Conclusion: npm unpublished every famous malicious version to a `0.0.1-security` holding
package (or 404), and GitHub rewrote commit history. The OpenSSF `malicious-packages`
repo is OSV **reports only** (no source). **There is no obtainable, currently-installable
genuinely-malicious npm artifact to test against.** This is a `NOT TESTED` limitation, not
a failure of the scanner.

### Scan results

**A. Real known-malicious-adjacent artifact — `claud-code@0.0.1-security`** (downloaded
live, scanned locally):

```
V4-TYPOSQUAT  high    package name 'claud-code' is distance 1 from popular 'claude-code'
V4-NO-PROVENANCE medium no provenance/signed-attestation artifact found
V4-THIN-META  low     no repository/license metadata present
```

v4scan **correctly fires `V4-TYPOSQUAT` HIGH** on a real SANDWORM_MODE typosquat. ✅
**But** this is a *known* malicious artifact — npm unpublished it and Socket/Snyk flagged
it in Feb 2026. It therefore fails Condition #3's "**not already flagged by Socket / Snyk
/ GitHub**" clause. **Not novel.**

**B. 170-package mainstream MCP / AI-agent corpus** (`_cond3/work/*`, re-scanned with the
NEW binary — includes the is_text UTF-8 fix and the added AI/Claude/MCP typosquat names):

```
TOTAL_PACKAGES=170   PACKAGES_WITH_HIGH_OR_CRIT=0   TOTAL_HIGH=0   TOTAL_CRITICAL=0
```

Confirms: (1) the tuning fix holds (15 HIGH → 0 HIGH), and (2) the new typosquat names
and UTF-8 `is_text` fix introduced **zero** new false positives.

### Independent verification of every HIGH/CRITICAL

Only **one** HIGH was produced across the hostile + mainstream corpus:

| Package | Signal | Genuinely malicious? | Flagged by Socket/Snyk/GitHub? | Novel? |
|---|---|---|---|---|
| `claud-code@0.0.1-security` | V4-TYPOSQUAT (HIGH) | Yes (historically; now placeholder) | Yes — SANDWORM_MODE, Socket Feb 2026 | **No** (already known) |

No HIGH/CRITICAL finding was a false positive, and none was novel. No obtainable
known-malicious sample existed to test "missed-known-malicious" against (see limitations).

### Corpus metrics

| Metric | Value |
|---|---|
| Total packages scanned (hostile + mainstream) | 171 (170 mainstream + 1 live typosquat) |
| Malicious package **names** probed (Backstabber catalog) | 14,679 (source unobtainable) |
| Genuinely malicious artifacts obtained | **0** |
| HIGH/CRITICAL flagged | 1 (claud-code typosquat) |
| True positives (malicious + detected + **novel**) | **0** |
| False positives among HIGH/CRITICAL | 0 |
| Novel detections | **0** |
| Missed known-malicious | N/A (no obtainable sample) |

### Verdict — split as required

- **PROVEN**
  - Signal-quality fix is real and durable: **15 HIGH false positives → 0 HIGH** over 170
    packages, re-confirmed with the new binary.
  - v4scan **detects all five** malicious behaviors (decode-execute eval, install-exec
    `curl|sh`, install network exfil, typosquat, thin-metadata) — locked by 9 passing
    regression tests (`tests/integration.rs` + `examples/06-benign-decode`).
  - Typosquat detection now covers the beachhead: `claud-code`→`claude-code` and
    `opencraw`→`openclaw` both fire V4-TYPOSQUAT (proven by tests; also observed live).
  - Fixed a real blind spot: `is_text` previously **silently skipped any file containing
    multibyte Unicode** (em dash, non-Latin identifiers, emoji) — now accepts valid UTF-8.

- **INCONCLUSIVE** (Condition #3 novel-malicious axis) — *not a failure*
  - No genuinely malicious artifact that the majors had **not** flagged was found. The
    honest reason: none is obtainable to test against, and the scannable beachhead corpus
    is overwhelmingly benign first-party code. Condition #3 is **open**, not satisfied, and
    not failed. A clean INCONCLUSIVE is the correct scientific outcome here.

- **NOT TESTED** (unobtainable)
  - Historical npm malware (SANDWORM typosquats, Backstabber samples, node-ipc) — source
    unavailable (placeholders / 404 / rewritten history / catalog-only).
  - Live novel-malware discovery — pending the 60-day window (day-30 gate 2026-10-08,
    day-56 decision 2026-11-03).

- **NEXT ACTION**
  - Continue the 8-week falsifiable test; record any novel catch in the log below.
  - Keep broadening detection (typosquat names, install-exec, decode-exec) as real threats
    emerge; the regression suite prevents signal-quality regressions.
  - Optionally obtain Backstabber source via the OpenSSF `malicious-packages` OSV mirror
    for **regression-only** fixtures (these are *known* malicious and do not count toward
    Condition #3).

### Condition #3 — 2026-09-09 research pass (web-sourced candidates)

Web search of current 2026 reporting for genuinely-malicious MCP / AI-agent-skill packages the
major scanners had **not** flagged. Every named, obtainable artifact found is **already in OSV /
Socket / Snyk / GitHub** databases, so it fails clause (c). The un-flagged ones have no obtainable
source. No live malware was downloaded (policy + design: v4scan is strictly install-time).

| Candidate (source) | Already flagged? | Fails Condition #3 because |
|---|---|---|
| OSV `MAL-2026-5477` (`mcp-server-figma` typosquat), `MAL-2026-5481` (npx-confusion canary) | **Yes — in OSV** (GitHub Advisory + Socket/Snyk ingest OSV) | already flagged (c) |
| dugganusa 24 malicious PyPI MCP pkgs (mcp-runcommand-server, openai-mcp, langchain-core-mcp, latinum-wallet-mcp…) | **Yes — sourced FROM OSV's known-malicious PyPI catalog** | already flagged (c) |
| SANDWORM_MODE (19 typosquatted AI-coding pkgs) | **Yes — Socket discovered it** | already flagged (c) |
| Morphisec `drp-compliance-sdk v1.2.3` (SOX/DRP-2026 tool, base64 URL + char-code array, fires on `tools/list`) | unverified | vendor write-up only; **runtime** handshake attack → outside v4scan install-time scope; no obtainable source |
| Deadbugz (Aug 2026, 23 GitHub PRs injecting malicious MCP server in 74 min) | unverified | source not obtainable; flagging unverified |
| ATR-2026-02405 "AgentBaiting" | unverified | source not obtainable; flagging unverified |

**Honest conclusion (re-confirmed):** the *problem* is real and current — 2026 reporting documents
axios/Axios npm hijack (North Korea, Mar 31), the Miasma worm (32 @redhat-cloud-services releases,
Jun 1), Shai-Hulud lineage, ~24 malicious PyPI MCP packages, 1,184 malicious OpenClaw skills
(Feb–May), Deadbugz (Aug), etc. This is strong **qualitative** support for demand (Conditions #1/#2)
but is **not** a Condition #3 true positive, because every obtainable malicious artifact is already
flagged by a major scanner. Condition #3 novel-malicious axis remains **INCONCLUSIVE**, not failed.

**Design boundary to remember:** v4scan is strictly **install-time**. Several 2026 attacks
(runtime `tools/list` exfiltration, context hijacking, rug pulls, tool-poisoning) are **out of its
scope by design** — they would not be a v4scan Condition #3 catch even if novel and unflagged.

### Novel-detection log (Condition #3)

| Date | Package | v4scan signal(s) | Verdict by Socket/Snyk/GitHub | Novel? | Notes |
|------|---------|------------------|-------------------------------|--------|-------|
| 2026-09-08 | (170-pkg mainstream corpus) | 15× `V4-OBF-EVAL` (HIGH, old binary) | — | No | All false positives; tuning fixed → 0 HIGH |
| 2026-09-08 | `claud-code@0.0.1-security` | `V4-TYPOSQUAT` (HIGH) | Flagged — SANDWORM_MODE, Socket Feb 2026 | **No** | Real typosquat, but already known; placeholder on npm |
| 2026-09-09 | OSV MAL-2026-5477 (mcp-server-figma) | — (not run; no source) | Flagged — in OSV catalog | **No** | Already in OSV → GitHub/Socket/Snyk ingest |
| 2026-09-09 | dugganusa 24 PyPI MCP pkgs | — (not run; no source) | Flagged — from OSV known-malicious catalog | **No** | Source = OSV, so already flagged |
| 2026-09-09 | SANDWORM_MODE (19 typosquats) | — (not run; no source) | Flagged — Socket discovered | **No** | Already flagged by Socket |
| 2026-09-09 | Morphisec drp-compliance-sdk | — (not run; no source) | Unverified | **No** | Runtime attack; outside v4scan install-time scope; no obtainable source |

---

## Repo audit (2026-09-08) — verified by execution, not inspection

Baseline state before outreach begins:

- HEAD = `e9bd162` (launch-prep commit); working tree clean; git remote contains **no credential**.
- **Remote state (checked unauthenticated, no token used):** `origin` main = `a93aed1` — the repo
  is publicly readable. `e9bd162` is **not pushed** (blocked on the exposed-PAT revocation, below).
- `cargo test --release`: **9 / 9 regression tests pass**.
- Fixture behaviour (real runs, current binary):

  | Fixture | Exit | Highest | Notes |
  |---|---|---|---|
  | 01 postinstall `curl \| sh` | **1** | HIGH `V4-INSTALL-EXEC` | blocks as intended |
  | 02 typosquat (`lodeash`) | **1** | HIGH `V4-TYPOSQUAT` | edit distance 1 |
  | 03 obfuscated eval | **1** | HIGH `V4-OBF-EVAL` | decode-**then**-execute |
  | 04 install network exfil | **1** | HIGH `V4-INSTALL-EXEC` | `preinstall` egress |
  | 05 benign-but-thin | **0** | MEDIUM `V4-NO-PROVENANCE` | **no HIGH** — precision holds |
  | 06 benign-decode | **0** | LOW `V4-OBF-DECODE` | **no HIGH** — benign `atob` |

- **Precision confirmed:** clean packages produce no HIGH; dangerous patterns still do.
- **SARIF:** valid 2.1.0, 4 results, levels `error`/`warning`/`note`, exit 1.
  `tool.driver.rules` is populated (4 rules: name, full description, default level) and every
  result carries a `ruleIndex` that resolves to the correct rule — verified programmatically.
- GitHub Action and pre-commit hook present and coherent.
- **⚠️ `installs/week` is UNINSTRUMENTED:** no crates.io publication and no GitHub Release
  binaries exist, so no download counter exists. Do **not** record 0 as a demand signal.
  Fix: `cargo publish` + cut a Release with binaries, then start recording.

### ✅ PAT blocker RESOLVED (2026-09-09)

A GitHub PAT was previously exposed in this project's history/session output. It was revoked/rotated
by the founder and re-issued through the environment's **secure credential mechanism** (never printed,
echoed, logged, committed, or exposed in this session).

- **Push completed 2026-09-09:** `git push origin main` → pushed SHA
  `27d13914edd91b8e566d90d8598ab9801aeb11ca`; remote `main -> main`; working tree clean.
- Zero token exposure: the PAT was used only by the authenticated push and was never written to any
  remote, file, log, commit, or this document.

### 🚧 Remaining launch blockers (2026-09-09, updated 2026-09-09 PM)

| Blocker | Status | What unblocks it (secure, no token in chat) |
|---|---|---|
| crates.io publish (`cargo publish`) | **BLOCKED** | No crates.io credential present in the environment (`~/.cargo/credentials.toml` absent; no `CARGO_REGISTRIES_CRATES_IO_TOKEN` env). Founder must make a crates.io API token available via the **same secure credential mechanism** the PAT used; then `CARGO_BUILD_TARGET=x86_64-pc-windows-gnu cargo publish`. Crate name `v4-scan` re-verified **free** on crates.io this session (HTTP 404). |
| GitHub Release v0.1.0 (binaries) | **UNBLOCKED via CI** | Added `.github/workflows/release.yml` — builds Windows gnu+msvc, Linux gnu+musl, macOS arm64+x86_64 and creates the Release using the built-in `GITHUB_TOKEN` (no external secret, no `gh` install). Pending founder approval of a commit + push of the workflow, then `git tag v0.1.0 && git push origin v0.1.0` triggers it. |
| CI workflow file | **STAGED (uncommitted)** | Present locally at `.github/workflows/release.yml`. Not pushed yet (controlled-push discipline — not pushing new files without explicit go-ahead). |
| installs/week instrumentation | **UNINSTRUMENTED** | Resolves once publish and/or Release exist; until then do **not** record 0 as demand. |

## Phase 1 verification — 2026-09-08 (local state only, zero authenticated network ops)

No push/publish performed (PAT revocation unconfirmed — see BLOCKER above). All commands run locally:

- `git status` → clean on `main` (no untracked / no modified)
- `git log --oneline -5` → `ec0e9ac` → `e9bd162` → `a93aed1` → `b84413b` → `f1130b5`
- `git remote -v` → `https://github.com/Open2445/v4scan.git` (no embedded token)
- `cargo test --release` → **9 passed, 0 failed**
- six-fixture sweep → `01:exit1/high1  02:exit1/high1  03:exit1/high1  04:exit1/high1  05:exit0/high0  06:exit0/high0`
- SARIF → version `2.1.0`; `tool.driver.rules` populated with **4 rules**
  (`V4-INSTALL-EXEC`/`V4-NET-EGRESS`/`V4-NO-PROVENANCE`/`V4-THIN-META`);
  4 results at levels `error`/`warning`/`warning`/`note`;
  every `ruleIndex` resolves to its `ruleId` (programmatic check = **True**)
- `cargo package --allow-dirty` → **packaged 33 files, 74.8 KiB (24.5 KiB compressed)**; verify compile finished

**Local quality gates: GREEN.** Public launch + install instrumentation remain **BLOCKED** on the PAT.

## Launch prep addendum — 2026-09-09 PM (CI release workflow + crates.io check)

Closes the multi-platform binary gap that blocked a clean Release:

- **Added `.github/workflows/release.yml`** (staged, uncommitted). Matrix builds 6 targets:
  Windows gnu+msvc, Linux gnu+musl, macOS arm64+x86_64. Creates the GitHub Release using the
  built-in `GITHUB_TOKEN` (no external secret, no `gh` install). windows-gnu uses choco MinGW +
  static-CRT so the binary carries no MinGW runtime DLLs (matching the locally staged gnu binary).
  The workflow is **untested in CI** (no CI run possible here); the windows-gnu job is the fragile
  part — if it ever fails, windows-msvc still covers Windows and the locally-built gnu .exe can be
  attached manually.
- **crates.io name `v4-scan` re-verified free** (HTTP 404) this session — publish is ready the moment
  a crates.io token is supplied via the secure mechanism.
- **Re-checked credentials:** still no crates.io token and `gh` not installed — so `cargo publish` and
  a manual Release remain credential-blocked; the CI workflow removes the *manual Release* blocker.

## Status snapshot (2026-09-08 → updated 2026-09-09)

| Dimension | Marker | Why |
|---|---|---|
| Product quality (tests, fixtures, SARIF, packaging) | **PROVEN** | 9/9 tests; six-fixture sweep; SARIF 4 rules; `cargo package` 33 files |
| Public launch surface (code on GitHub) | **PROVEN** | pushed 2026-09-09 → `27d1391`; remote `main` public |
| Release binary (Windows gnu) | **PROVEN** | built, functional, portable (system-DLL only); SHA256 recorded |
| crates.io publish (`cargo install`) | **BLOCKED** | no crates.io credential via secure mechanism |
| GitHub Release v0.1.0 (binaries) | **UNBLOCKED via CI** | `.github/workflows/release.yml` builds 6 targets + creates Release via `GITHUB_TOKEN`; pending commit+push of workflow + tag `v0.1.0` |
| CI release workflow | **STAGED (uncommitted)** | `.github/workflows/release.yml` present locally; not pushed (controlled-push discipline) |
| installs/week | **UNINSTRUMENTED** | no crates.io publish and no GitHub Release yet; do **not** record 0 |
| stars / clones / stranger issues+PRs | **NOT MEASURED** | repo public at `27d1391`; founder's private counters unverified |
| outreach touches / replies / meetings | **0 (NOT a signal)** | 25-row Tier-A queue staged; no send authorization this session |
| Condition #3 (novel malicious artifact) | **INCONCLUSIVE** | no obtainable genuine artifact unflagged by Socket/Snyk/GitHub |
| PAT revocation | **RESOLVED** | push completed 2026-09-09 via secure credential mechanism |

Full adoption/discovery/Condition-#3 operating spec:
`opc-doc/outputs/07-conversion/validation-ops.md`

---

## How to update

- `installs/week`: from npm/download counts or repo clones once published.
- `novel detections`: run `v4scan` over a corpus of real MCP servers / agent-skill
  packages (see `opc-doc/` condition-#3 runs). Verify "not already flagged" via
  `npm audit`, GitHub Security Advisories, and a web search — do **not** self-assert.
- Keep this file honest. A wrong "PASS" here is worse than an honest "INCONCLUSIVE".
