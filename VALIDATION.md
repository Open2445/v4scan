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
| 3 | ≥1 genuinely malicious artifact found that **Socket / Snyk / GitHub had NOT flagged** within 60 days | 🔍 IN PROGRESS | see "Novel-detection log" below |
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
| | | | | | |

---

## How to update

- `installs/week`: from npm/download counts or repo clones once published.
- `novel detections`: run `v4scan` over a corpus of real MCP servers / agent-skill
  packages (see `opc-doc/` condition-#3 runs). Verify "not already flagged" via
  `npm audit`, GitHub Security Advisories, and a web search — do **not** self-assert.
- Keep this file honest. A wrong "PASS" here is worse than an honest "INCONCLUSIVE".
