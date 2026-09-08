//! Regression + behavior tests for v4scan.
//!
//! These scan the committed `examples/` fixtures (real, minimal package layouts)
//! and assert the expected signal IDs and severities. They lock the detection
//! contract so a future signal-quality regression (like the V4-OBF-EVAL false-
//! positive incident) fails CI instead of shipping.
//!
//! NOTE: synthetic fixtures prove the engine *can* detect a behavior. They do NOT
//! by themselves satisfy Condition #3 (a genuinely malicious artifact the major
//! scanners missed) — that requires a hostile corpus, documented in VALIDATION.md.

use std::collections::HashSet;
use std::path::PathBuf;

use v4_scan::{scan_path, Severity};

fn example_dir(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("examples");
    p.push(name);
    p
}

fn signal_ids(report: &v4_scan::ScanReport) -> HashSet<String> {
    report.findings.iter().map(|f| f.id.clone()).collect()
}

fn has_blocking(report: &v4_scan::ScanReport) -> bool {
    report
        .findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High))
}

fn max_severity(report: &v4_scan::ScanReport) -> Option<Severity> {
    report.findings.iter().map(|f| f.severity).max_by_key(|s| match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    })
}

#[test]
fn ex01_postinstall_curl_sh_is_blocking() {
    let r = scan_path(&example_dir("01-postinstall-curl-sh"));
    let ids = signal_ids(&r);
    assert!(
        ids.contains("V4-INSTALL-EXEC"),
        "expected V4-INSTALL-EXEC, got {:?}",
        ids
    );
    assert!(has_blocking(&r), "postinstall curl|sh must block (HIGH)");
}

#[test]
fn ex02_typosquat_is_blocking() {
    let r = scan_path(&example_dir("02-typosquat"));
    let ids = signal_ids(&r);
    assert!(
        ids.contains("V4-TYPOSQUAT"),
        "expected V4-TYPOSQUAT for 'lodeash'~'lodash', got {:?}",
        ids
    );
    assert!(has_blocking(&r), "typosquat must block (HIGH)");
}

#[test]
fn ex03_obfuscated_eval_is_blocking() {
    let r = scan_path(&example_dir("03-obfuscated-eval"));
    let ids = signal_ids(&r);
    assert!(
        ids.contains("V4-OBF-EVAL"),
        "expected V4-OBF-EVAL for eval(atob(...)), got {:?}",
        ids
    );
    assert!(has_blocking(&r), "decode-and-execute must block (HIGH)");
}

#[test]
fn ex04_install_network_exfil() {
    let r = scan_path(&example_dir("04-install-network-exfil"));
    let ids = signal_ids(&r);
    assert!(
        ids.contains("V4-INSTALL-EXEC"),
        "expected V4-INSTALL-EXEC, got {:?}",
        ids
    );
    assert!(
        ids.contains("V4-NET-EGRESS"),
        "expected V4-NET-EGRESS, got {:?}",
        ids
    );
    assert!(has_blocking(&r), "install-time exfil must block (HIGH)");
}

#[test]
fn ex05_benign_thin_meta_is_low_only() {
    let r = scan_path(&example_dir("05-benign-but-thin"));
    let ids = signal_ids(&r);
    assert!(
        ids.contains("V4-THIN-META"),
        "expected V4-THIN-META for metadata-less package, got {:?}",
        ids
    );
    assert!(
        !has_blocking(&r),
        "a benign thin package must NOT block (HIGH/CRITICAL)"
    );
    assert_eq!(
        max_severity(&r),
        Some(Severity::Low),
        "benign thin package should only ever reach LOW"
    );
}

/// This is the contract that the V4-OBF-EVAL tuning fix established: benign
/// decode primitives (atob / Buffer.from) must surface as the LOW informational
/// `V4-OBF-DECODE` and must NEVER be escalated to the HIGH `V4-OBF-EVAL`.
#[test]
fn ex06_benign_decode_is_not_eval_high() {
    let r = scan_path(&example_dir("06-benign-decode"));
    let ids = signal_ids(&r);
    assert!(
        !ids.contains("V4-OBF-EVAL"),
        "benign atob()/Buffer.from() must NOT trigger V4-OBF-EVAL (HIGH); got {:?}",
        ids
    );
    assert!(
        ids.contains("V4-OBF-DECODE"),
        "expected informational V4-OBF-DECODE for benign decode, got {:?}",
        ids
    );
    assert!(
        !has_blocking(&r),
        "benign decode must not block (HIGH/CRITICAL)"
    );
}

/// Regression for the SANDWORM_MODE-style typosquats (Feb 2026): a package named
/// one character off from `claude-code` must be caught as a typosquat.
#[test]
fn typosquat_claude_code_variant_is_blocking() {
    let dir = tempdir_with_package("claud-code", "4.17.21");
    let r = scan_path(&dir);
    let ids = signal_ids(&r);
    assert!(
        ids.contains("V4-TYPOSQUAT"),
        "expected V4-TYPOSQUAT for 'claud-code'~'claude-code', got {:?}",
        ids
    );
    assert!(has_blocking(&r));
}

#[test]
fn typosquat_openclaw_variant_is_blocking() {
    let dir = tempdir_with_package("opencraw", "1.0.0");
    let r = scan_path(&dir);
    let ids = signal_ids(&r);
    assert!(
        ids.contains("V4-TYPOSQUAT"),
        "expected V4-TYPOSQUAT for 'opencraw'~'openclaw', got {:?}",
        ids
    );
    assert!(has_blocking(&r));
}

#[test]
fn legit_name_is_not_typosquat() {
    // A genuinely distinct, legitimate name must not trip the typosquat heuristic.
    let dir = tempdir_with_package("openclaw-utils", "1.0.0");
    let r = scan_path(&dir);
    let ids = signal_ids(&r);
    assert!(
        !ids.contains("V4-TYPOSQUAT"),
        "'openclaw-utils' is a distinct legit name, not a claude-code/openclaw typosquat; got {:?}",
        ids
    );
}

/// Build a throwaway package directory under CARGO_TARGET_TMPDIR for typosquat
/// assertions that don't correspond to a committed example.
fn tempdir_with_package(name: &str, version: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("v4scan-test-{}-{}", name, std::process::id()));
    let _ = std::fs::create_dir_all(&base);
    let manifest = format!(
        "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"license\": \"MIT\"\n}}"
    );
    std::fs::write(base.join("package.json"), manifest).unwrap();
    base
}
