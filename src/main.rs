use std::path::PathBuf;
use std::process;
use v4_scan::scan_path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut target: Option<String> = None;
    let mut as_sarif = false;
    let mut explain = false;
    let mut excludes: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--sarif" => as_sarif = true,
            "--explain" => explain = true,
            "--exclude" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --exclude requires a comma-separated list");
                    process::exit(2);
                }
                i += 1;
                for part in args[i].split(',') {
                    let p = part.trim();
                    if !p.is_empty() {
                        excludes.push(p.to_string());
                    }
                }
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => {
                if other.starts_with('-') {
                    eprintln!("unknown flag: {other}");
                    process::exit(2);
                } else if target.is_none() {
                    target = Some(other.to_string());
                }
            }
        }
        i += 1;
    }

    let target = match target {
        Some(t) => t,
        None => {
            eprintln!("error: no target given. Usage: v4scan <path> [--sarif] [--explain]");
            print_help();
            process::exit(2);
        }
    };

    let path = PathBuf::from(&target);
    if !path.exists() {
        eprintln!("error: path does not exist: {target}");
        process::exit(2);
    }

    let report = if excludes.is_empty() {
        v4_scan::scan_path(&path)
    } else {
        v4_scan::scan_path_with_excludes(&path, &excludes)
    };
    if as_sarif {
        println!("{}", report.to_sarif());
    } else {
        println!("{}", report.to_json());
    }

    if explain && !report.findings.is_empty() {
        println!("\n--- EXPLANATIONS ---");
        for f in &report.findings {
            println!("\n[{}] {} — {}", f.severity.as_str().to_uppercase(), f.category, f.signal);
            println!("  {}", f.description);
            println!("  evidence: {}", f.evidence);
        }
    }

    // Exit non-zero if any Critical/High found (CI-friendly gate).
    let blocking = report.findings.iter().any(|f| {
        matches!(f.severity, v4_scan::Severity::Critical | v4_scan::Severity::High)
    });
    if blocking {
        process::exit(1);
    }
}

fn print_help() {
    println!("v4scan — install-time supply-chain firewall for MCP servers / AI-agent skill packages");
    println!();
    println!("USAGE:");
    println!("  v4scan <path-to-mcp-server-or-skill-package> [flags]");
    println!();
    println!("FLAGS:");
    println!("  --sarif     emit SARIF 2.1.0 (forwardable to GRC / security tooling)");
    println!("  --explain   print human-readable explanations after the JSON");
    println!("  --exclude   comma-separated dir names / '*.ext' suffixes to skip");
    println!("              (e.g. --exclude examples,test-fixtures,*.md). Scoping");
    println!("              only — never changes a detection rule.");
    println!("  -h, --help  this message");
    println!();
    println!("EXAMPLES:");
    println!("  v4scan ./my-mcp-server");
    println!("  v4scan ./agent-skill --sarif");
    println!("  v4scan . --exclude examples,test-fixtures,*.md");
    println!();
    println!("EXIT CODES: 0 = no blocking finding, 1 = critical/high finding, 2 = usage error");
}
