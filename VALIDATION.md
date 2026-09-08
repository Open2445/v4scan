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
| 3 | ≥1 genuinely malicious artifact found that **Socket / Snyk / GitHub had NOT flagged** within 60 days | 🔍 IN PROGRESS — 170/185 scanned; **0 novel found**; signal tuned | see "Condition #3 — interim finding" below |
| 4 | ≥3 of 20 cold contacts convert on HN / r-rust / r-Python / MCP Discords | ⬜ | |
| 5 | *(withdrawn — replaced by "≥1 paid pilot OR ≥2 signed LOIs within 8 weeks")* | ⬜ | |

---

## Day-30 gate (hard stop, 2026-10-08)

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

## How to update

- `installs/week`: from npm/download counts or repo clones once published.
- `novel detections`: run `v4scan` over a corpus of real MCP servers / agent-skill
  packages (see `opc-doc/` condition-#3 runs). Verify "not already flagged" via
  `npm audit`, GitHub Security Advisories, and a web search — do **not** self-assert.
- Keep this file honest. A wrong "PASS" here is worse than an honest "INCONCLUSIVE".
