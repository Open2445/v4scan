//! v4-scan — install-time supply-chain firewall for MCP servers and AI-agent skill packages.
//! Deterministic detection only. No model in the loop.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub signal: String,
    pub description: String,
    pub evidence: String,
}

#[derive(Clone, Debug)]
pub struct ScanReport {
    pub target: String,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn to_json(&self) -> String {
        let mut counts = [0usize; 4];
        for f in &self.findings {
            let idx = match f.severity {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
            };
            counts[idx] += 1;
        }
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str("  \"tool\": \"v4scan\",\n");
        s.push_str("  \"version\": \"0.1.0\",\n");
        s.push_str(&format!("  \"target\": {},\n", json_str(&self.target)));
        s.push_str(&format!("  \"files_scanned\": {},\n", self.files_scanned));
        s.push_str("  \"summary\": {\n");
        s.push_str(&format!("    \"findings\": {},\n", self.findings.len()));
        s.push_str(&format!("    \"critical\": {},\n", counts[0]));
        s.push_str(&format!("    \"high\": {},\n", counts[1]));
        s.push_str(&format!("    \"medium\": {},\n", counts[2]));
        s.push_str(&format!("    \"low\": {}\n", counts[3]));
        s.push_str("  },\n");
        s.push_str("  \"findings\": [\n");
        for (i, f) in self.findings.iter().enumerate() {
            s.push_str("    {\n");
            s.push_str(&format!("      \"id\": {},\n", json_str(&f.id)));
            s.push_str(&format!("      \"severity\": {},\n", json_str(f.severity.as_str())));
            s.push_str(&format!("      \"category\": {},\n", json_str(&f.category)));
            s.push_str(&format!("      \"signal\": {},\n", json_str(&f.signal)));
            s.push_str(&format!("      \"description\": {},\n", json_str(&f.description)));
            s.push_str(&format!("      \"evidence\": {}\n", json_str(&f.evidence)));
            if i + 1 < self.findings.len() {
                s.push_str("    },\n");
            } else {
                s.push_str("    }\n");
            }
        }
        s.push_str("  ]\n");
        s.push_str("}\n");
        s
    }

    /// SARIF 2.1.0 with rule metadata, so consumers (GitHub code scanning, GRC
    /// tooling) can resolve each `ruleId` to a name, description and default level.
    pub fn to_sarif(&self) -> String {
        // Unique rule ids in first-seen order, so results can reference them by
        // index. Without a `rules` array, `ruleId` is unresolvable for consumers.
        let mut rule_ids: Vec<&str> = Vec::new();
        for f in &self.findings {
            if !rule_ids.contains(&f.id.as_str()) {
                rule_ids.push(f.id.as_str());
            }
        }

        let mut rules = String::new();
        for (i, id) in rule_ids.iter().enumerate() {
            let f = self
                .findings
                .iter()
                .find(|x| x.id.as_str() == *id)
                .unwrap();
            let default_level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            if i > 0 {
                rules.push_str(",\n");
            }
            rules.push_str("        {\n");
            rules.push_str(&format!("          \"id\": {},\n", json_str(id)));
            rules.push_str(&format!("          \"name\": {},\n", json_str(&f.category)));
            rules.push_str(&format!(
                "          \"shortDescription\": {{ \"text\": {} }},\n",
                json_str(&f.signal)
            ));
            rules.push_str(&format!(
                "          \"fullDescription\": {{ \"text\": {} }},\n",
                json_str(&f.description)
            ));
            rules.push_str(&format!(
                "          \"defaultConfiguration\": {{ \"level\": {} }},\n",
                json_str(default_level)
            ));
            rules.push_str(&format!(
                "          \"help\": {{ \"text\": {} }}\n",
                json_str(&f.description)
            ));
            rules.push_str("        }");
        }

        let mut results = String::new();
        for (i, f) in self.findings.iter().enumerate() {
            if i > 0 {
                results.push_str(",\n");
            }
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            let rule_index = rule_ids.iter().position(|r| *r == f.id.as_str()).unwrap();
            results.push_str("    {\n");
            results.push_str(&format!("      \"ruleId\": {},\n", json_str(&f.id)));
            results.push_str(&format!("      \"ruleIndex\": {},\n", rule_index));
            results.push_str(&format!("      \"level\": {},\n", json_str(level)));
            results.push_str("      \"message\": { \"text\": ");
            results.push_str(&json_str(&format!("{} — {}", f.signal, f.description)));
            results.push_str(" },\n");
            results.push_str(&format!("      \"properties\": {{ \"category\": {}, \"evidence\": {} }}\n",
                json_str(&f.category), json_str(&f.evidence)));
            results.push_str("    }");
        }
        format!(
            "{{\n  \"version\": \"2.1.0\",\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n  \"runs\": [\n    {{\n      \"tool\": {{ \"driver\": {{ \"name\": \"v4scan\", \"version\": \"0.1.0\", \"rules\": [\n{}\n      ] }} }},\n      \"results\": [\n{}\n      ]\n    }}\n  ]\n}}",
            rules, results
        )
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Lightweight `"key": "value"` extractor. Not a full JSON parser — good enough to pull
/// manifest metadata and script blocks from package.json / pyproject without external deps.
fn extract_pairs(text: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = text.chars().collect();
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' {
            let mut key = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    key.push(chars[i + 1]);
                    i += 2;
                } else {
                    key.push(chars[i]);
                    i += 1;
                }
            }
            i += 1;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            if i < chars.len() && chars[i] == ':' {
                i += 1;
                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    let mut val = String::new();
                    i += 1;
                    while i < chars.len() && chars[i] != '"' {
                        if chars[i] == '\\' && i + 1 < chars.len() {
                            val.push(chars[i + 1]);
                            i += 2;
                        } else {
                            val.push(chars[i]);
                            i += 1;
                        }
                    }
                    i += 1;
                    pairs.push((key, val));
                }
            }
        } else {
            i += 1;
        }
    }
    pairs
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let n = a.len();
    let m = b.len();
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur = vec![0usize; m + 1];
    for i in 1..=n {
        cur[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[m]
}

const POPULAR_PACKAGES: &[&str] = &[
    "react", "vue", "angular", "express", "lodash", "axios", "webpack", "babel",
    "eslint", "jest", "next", "nuxt", "tailwindcss", "chakra-ui", "d3", "three",
    "moment", "uuid", "async", "debug", "commander", "chalk", "request", "mongoose",
    "socket.io", "redux", "typescript", "vite", "rollup", "jquery", "bootstrap",
    "numpy", "pandas", "requests", "flask", "django", "pillow", "scipy", "torch",
    "tensorflow", "matplotlib", "requests", "click", "fastapi", "pydantic",
    // Beachhead-specific targets — AI-agent / MCP ecosystem names that real
    // typosquat campaigns (e.g. SANDWORM_MODE, Feb 2026) have impersonated.
    // These are legitimate detection improvements; they do not relax Condition #3.
    // Curated to distinctive names to minimize false positives: `claude-code`
    // catches claud-code / cloude-code; `openclaw` catches opencraw.
    "claude-code", "openclaw", "@modelcontextprotocol/sdk", "@anthropic-ai/sdk",
    "cursor", "codex",
];

const SCRIPT_KEYS: &[&str] = &[
    "preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare",
    "prepack", "postpack", "prepublish",
];

const RISKY_TOKENS: &[&str] = &[
    "curl", "wget", "| sh", "| bash", "eval(", "exec(", "base64", "rm -rf",
    "npm i ", "npm install", "pip install", "powershell", "iex", "Invoke-",
    "curl.exe", "certutil", "bitsadmin", "regsvr32",
];

const NETWORK_TOKENS: &[&str] = &[
    "http://", "https://", "curl", "wget", "fetch(", "requests.get", "urllib",
    "netcat", "nc -e", "socket",
];

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut e = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            e -= p * p.log2();
        }
    }
    e
}

fn is_text(_path: &Path, data: &[u8]) -> bool {
    if data.len() > 512 * 1024 {
        return false;
    }
    // Accept any valid UTF-8. The previous byte-range heuristic silently SKIPPED
    // files containing multibyte characters (em dashes, non-Latin identifiers,
    // emoji), creating a real blind spot where source that legitimately uses
    // Unicode was never scanned. Valid UTF-8 also covers pure-ASCII source.
    std::str::from_utf8(data).is_ok()
}

/// Returns true if `path` should be skipped because it matches an exclusion.
/// An exclude entry matches when:
/// - it has no path separator and equals one of the path's segment names
///   (e.g. `examples`, `test-fixtures`, `target`, `src`, `tests`), or
/// - it begins with `*` and the path ends with that suffix (e.g. `*.md`).
/// Exclusions are a scoping control (mirror Socket/Snyk ignore paths); they do
/// NOT change any detection rule — only which files are visited.
fn is_excluded(path: &Path, excludes: &[String]) -> bool {
    let segments: Vec<String> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(|s| s.to_string()))
        .collect();
    for ex in excludes {
        if let Some(suffix) = ex.strip_prefix('*') {
            if suffix.is_empty() {
                continue;
            }
            if path.to_string_lossy().ends_with(suffix) {
                return true;
            }
        } else if segments.iter().any(|s| s == ex) {
            return true;
        }
    }
    false
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>, limit: usize, excludes: &[String]) {
    if out.len() >= limit {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if out.len() >= limit {
            break;
        }
        let p = entry.path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name == "node_modules" || name == ".git" || name == "target" || name == ".venv"
                || name == "dist" || name == "__pycache__"
            {
                continue;
            }
        }
        if is_excluded(&p, excludes) {
            continue;
        }
        if p.is_dir() {
            collect_files(&p, out, limit, excludes);
        } else {
            out.push(p);
        }
    }
}

/// Scan a package/skill directory for supply-chain risk signals.
///
/// `excludes` is an optional list of path segments or `*.ext` suffixes to skip
/// (e.g. a project's own intentional hostile test corpus). Excluding a path
/// never changes a detection rule — it only narrows what is visited, so a
/// scanner pointed at real packages detects exactly as before.
pub fn scan_path(root: &Path) -> ScanReport {
    scan_path_with_excludes(root, &[])
}

/// Like [`scan_path`], but skips any path matched by `excludes` (see
/// [`is_excluded`]). Intended for self-scan gate CI that must not flag the
/// project's own intentional test fixtures.
pub fn scan_path_with_excludes(root: &Path, excludes: &[String]) -> ScanReport {
    let mut files = Vec::new();
    collect_files(root, &mut files, 3000, excludes);

    let mut findings: Vec<Finding> = Vec::new();
    let mut script_values: Vec<(String, String)> = Vec::new();
    let mut pkg_name: Option<String> = None;
    let mut has_package_manifest = false;
    let mut provenance_found = false;
    let mut manifest_blob = String::new();

    for path in &files {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let text = if is_text(path, &data) {
            String::from_utf8_lossy(&data).into_owned()
        } else {
            continue;
        };
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            let low = name.to_lowercase();
            if low.contains("provenance")
                || low.contains(".slsa")
                || low.contains("sigstore")
                || low.contains("intoto")
                || low.ends_with(".intoto.jsonl")
            {
                provenance_found = true;
            }
        }

        let is_manifest = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n == "package.json" || n == "pyproject.toml" || n == "setup.py" || n == "setup.cfg")
            .unwrap_or(false);

        if is_manifest {
            has_package_manifest = true;
            manifest_blob.push_str(&text);
            manifest_blob.push('\n');
            let pairs = extract_pairs(&text);
            for (k, v) in &pairs {
                if k == "name" && pkg_name.is_none() {
                    pkg_name = Some(v.clone());
                }
                if SCRIPT_KEYS.contains(&k.as_str()) {
                    script_values.push((k.clone(), v.clone()));
                } else if v.to_lowercase().contains("curl")
                    || v.to_lowercase().contains("eval")
                    || v.to_lowercase().contains("| sh")
                {
                    // catch risky tokens in non-standard script keys too
                    script_values.push((k.clone(), v.clone()));
                }
            }
        }

        // obfuscation scan across all source text
        detect_obfuscation(&text, path, &mut findings);
    }

    // install-script + network egress on script values
    for (key, value) in &script_values {
        let low = value.to_lowercase();
        let runs_install = SCRIPT_KEYS.contains(&key.as_str());
        for tok in RISKY_TOKENS {
            if low.contains(&tok.to_lowercase()) {
                findings.push(Finding {
                    id: "V4-INSTALL-EXEC".to_string(),
                    severity: if runs_install { Severity::High } else { Severity::Medium },
                    category: "install-script-execution".to_string(),
                    signal: format!("risky token '{tok}' in script '{key}'"),
                    description: "Package executes external/unsafe commands during install. This is the primary supply-chain attack vector.".to_string(),
                    evidence: truncate(value, 160),
                });
                break;
            }
        }
        for tok in NETWORK_TOKENS {
            if low.contains(&tok.to_lowercase()) {
                findings.push(Finding {
                    id: "V4-NET-EGRESS".to_string(),
                    severity: if runs_install { Severity::Medium } else { Severity::Low },
                    category: "network-egress-at-install".to_string(),
                    signal: format!("network egress token '{tok}' in script '{key}'"),
                    description: "Network call during install can exfiltrate data or pull second-stage payloads.".to_string(),
                    evidence: truncate(value, 160),
                });
                break;
            }
        }
    }

    // typosquat
    if let Some(name) = &pkg_name {
        let low = name.to_lowercase();
        for pop in POPULAR_PACKAGES {
            let d = levenshtein(&low, &pop.to_lowercase());
            if d >= 1 && d <= 2 && low != *pop {
                findings.push(Finding {
                    id: "V4-TYPOSQUAT".to_string(),
                    severity: Severity::High,
                    category: "typosquat".to_string(),
                    signal: format!("package name '{name}' is distance {d} from popular '{pop}'"),
                    description: "Name resembles a popular package — classic typosquat attack surface.".to_string(),
                    evidence: format!("'{name}' vs '{pop}' (levenshtein={d})"),
                });
                break;
            }
        }
    }

    // provenance
    if has_package_manifest && !provenance_found {
        findings.push(Finding {
            id: "V4-NO-PROVENANCE".to_string(),
            severity: Severity::Medium,
            category: "missing-provenance".to_string(),
            signal: "no provenance/signed-attestation artifact found".to_string(),
            description: "No SLSA/sigstore/provenance attestation detected. Cannot verify build integrity.".to_string(),
            evidence: "searched for provenance/slsa/sigstore/intoto files".to_string(),
        });
    }

    // metadata thinness (proxy for anonymous/squat packages)
    if has_package_manifest {
        let blob = manifest_blob.to_lowercase();
        let lacks_repo = !blob.contains("repository") && !blob.contains("repo");
        let lacks_license = !blob.contains("license") && !blob.contains("licence");
        if lacks_repo || lacks_license {
            findings.push(Finding {
                id: "V4-THIN-META".to_string(),
                severity: Severity::Low,
                category: "thin-metadata".to_string(),
                signal: "no repository/license metadata present".to_string(),
                description: "Missing standard manifest metadata. Common in freshly-created or anonymous packages.".to_string(),
                evidence: "no 'repository'/'license' keys in scanned manifests".to_string(),
            });
        }
    }

    ScanReport {
        target: root.to_string_lossy().into_owned(),
        files_scanned: files.len(),
        findings,
    }
}

fn detect_obfuscation(text: &str, path: &Path, findings: &mut Vec<Finding>) {
    // Manifests (package.json / pyproject.toml / setup.py / setup.cfg) routinely
    // contain URLs, emails and hashes that look "high entropy" — skip the entropy
    // and base64 heuristics there to avoid noise. Decode-and-execute patterns are
    // still checked everywhere.
    let is_manifest = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|n| n == "package.json" || n == "pyproject.toml" || n == "setup.py" || n == "setup.cfg")
        .unwrap_or(false);
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let path_str = path.to_string_lossy();
    // Vendored / minified third-party code is noisy for entropy & base64 heuristics
    // (bundlers emit long high-entropy runs). Decode-then-execute (HIGH) is still
    // checked everywhere, because malicious logic can hide in vendored paths too.
    let is_vendored = path_str.contains("node_modules")
        || path_str.contains("third_party")
        || path_str.contains("/vendor/")
        || fname.ends_with(".min.js")
        || fname.ends_with(".bundle.js")
        || fname.ends_with(".map");
    // high-entropy runs — skip manifests and vendored/minified third-party code
    if !is_manifest && !is_vendored {
        let bytes = text.as_bytes();
        if bytes.len() >= 25 {
            let e = shannon_entropy(bytes);
            if e > 4.6 {
                findings.push(Finding {
                    id: "V4-OBF-ENTROPY".to_string(),
                    severity: Severity::Medium,
                    category: "obfuscation".to_string(),
                    signal: "high-entropy content block".to_string(),
                    description: "Very high Shannon entropy — often packed/encoded payloads.".to_string(),
                    evidence: format!("entropy={:.2} in {}", e, path.display()),
                });
            }
        }
    }
    let low = text.to_lowercase();
    // base64-like long runs — skip manifests and vendored/minified third-party code
    if !is_manifest && !is_vendored {
        let mut run = 0;
        for c in low.chars() {
            if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
                run += 1;
            } else {
                if run >= 24 {
                    findings.push(Finding {
                        id: "V4-OBF-B64".to_string(),
                        severity: Severity::Medium,
                        category: "obfuscation".to_string(),
                        signal: "long base64-like run".to_string(),
                        description: "Long base64-style run — possible encoded payload.".to_string(),
                        evidence: format!("run length {} in {}", run, path.display()),
                    });
                    break;
                }
                run = 0;
            }
        }
    }
    // Tier 1: decode-then-execute (genuinely dangerous) -> HIGH.
    // Only flag when code decodes data AND then executes it.
    let decode_exec = ["eval(atob", "eval(base64", "new function(atob", "new function(base64"];
    let mut dangerous = false;
    for pat in decode_exec {
        if low.contains(pat) {
            findings.push(Finding {
                id: "V4-OBF-EVAL".to_string(),
                severity: Severity::High,
                category: "obfuscation".to_string(),
                signal: format!("decode-and-execute pattern '{pat}'"),
                description: "Code decodes data then executes it (eval / new Function on decoded content) — hallmark of obfuscated malicious logic.".to_string(),
                evidence: format!("found '{pat}' in {}", path.display()),
            });
            dangerous = true;
            break;
        }
    }
    // Tier 2: benign decode primitives (ubiquitous in legitimate code) -> LOW,
    // first-party only. Informational; does NOT gate CI.
    if !dangerous && !is_vendored {
        let benign = ["atob(", "base64.b64decode", "buffer.from(", "new function("];
        for pat in benign {
            if low.contains(pat) {
                findings.push(Finding {
                    id: "V4-OBF-DECODE".to_string(),
                    severity: Severity::Low,
                    category: "obfuscation".to_string(),
                    signal: format!("base64/decode primitive '{pat}'"),
                    description: "Base64 decode or dynamic-construct primitive. Ubiquitous in legitimate code; informational only — not gating.".to_string(),
                    evidence: format!("found '{pat}' in {}", path.display()),
                });
                break;
            }
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        format!("{t}…")
    } else {
        t
    }
}
