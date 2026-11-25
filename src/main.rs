use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use safe_anything::{Family, Finding, Options, Severity, report};
use serde::{Deserialize, Serialize};

const AFTER_HELP: &str = "\
Examples:
  safe-anything .
  safe-anything . --offline --fail-on never
  safe-anything . --sarif > results.sarif
  safe-anything . --write-baseline baseline.json
  safe-anything . --baseline baseline.json
  safe-anything mcp    serve scan and list_rules to AI agents over MCP

To ignore a finding, put safe-anything:ignore in a comment on that line or the line above it
(follow it with rule ids to silence only those), or list paths in .safe-anything-ignore.";

#[derive(Parser)]
#[command(
    version,
    about = "Find vulnerabilities in any app, and in the AI agent setup that builds it.",
    after_help = AFTER_HELP
)]
struct Cli {
    /// Folder or file to scan
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Print the report as JSON
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    /// Print the report as SARIF 2.1.0 (GitHub code scanning)
    #[arg(long)]
    sarif: bool,
    /// Also write the report as SARIF 2.1.0 to this file, from the same scan
    #[arg(long, value_name = "FILE")]
    sarif_file: Option<PathBuf>,
    /// Skip the dependency check (no network)
    #[arg(long)]
    offline: bool,
    /// Lowest severity to report: low, medium, high, critical
    #[arg(long, default_value = "low", value_parser = parse_severity)]
    severity: Severity,
    /// Exit with 1 when a finding is at least this severe: low, medium, high, critical, never
    #[arg(long, default_value = "high")]
    fail_on: String,
    /// Also report findings in test, spec and fixture files (by default only real tokens and keys count there)
    #[arg(long)]
    include_tests: bool,
    /// List every rule and exit
    #[arg(long)]
    list_rules: bool,
    /// Hide the findings recorded in this file by --write-baseline
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Record the current findings in this file for --baseline and exit (rule, path and a hash of
    /// the line; no code or secrets)
    #[arg(long, value_name = "FILE", conflicts_with_all = ["baseline", "json", "sarif", "sarif_file"])]
    write_baseline: Option<PathBuf>,
}

/// The file `--write-baseline` writes and `--baseline` reads.
#[derive(Serialize, Deserialize)]
struct Baseline {
    version: u32,
    findings: Vec<Known>,
}

/// What a baseline keeps of a finding. Not the line itself: a snippet can hold a secret the scan
/// does not mask, and the file is meant to be committed.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Known {
    path: String,
    rule: String,
    sha256: String,
}

impl Known {
    /// Line numbers are left out, so moving code does not bring an old finding back. A
    /// dependency's snippet is only `name@version (ecosystem)`, so its hash also takes the message,
    /// which names the advisories: a new advisory for the same version is a new finding.
    fn of(f: &Finding) -> Self {
        let line = f.snippet.trim();
        let text = if f.family == Family::Dependency {
            format!("{line}\n{}", f.message)
        } else {
            line.to_string()
        };
        let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
        Self {
            path: f.path.clone(),
            rule: f.rule.clone(),
            sha256: digest.as_ref().iter().map(|b| format!("{b:02x}")).collect(),
        }
    }
}

fn write_baseline(file: &Path, findings: &[Finding]) -> Result<(), String> {
    let mut findings: Vec<Known> = findings.iter().map(Known::of).collect();
    findings.sort();
    let json = serde_json::to_string_pretty(&Baseline {
        version: 1,
        findings,
    })
    .unwrap();
    std::fs::write(file, json + "\n").map_err(|e| format!("{}: {e}", file.display()))
}

/// Reads a `--write-baseline` file into a count per finding.
fn load_baseline(file: &Path) -> Result<HashMap<Known, usize>, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let baseline: Baseline = serde_json::from_str(text)
        .ok()
        .filter(|b: &Baseline| b.version == 1)
        .ok_or_else(|| {
            format!(
                "{} is not a baseline written by --write-baseline",
                file.display()
            )
        })?;
    let mut known = HashMap::new();
    for k in baseline.findings {
        *known.entry(k).or_default() += 1;
    }
    Ok(known)
}

/// Drops the findings in the baseline and returns how many. Each entry hides one finding, so a
/// second copy of a known line still counts as new.
fn apply_baseline(known: &mut HashMap<Known, usize>, findings: &mut Vec<Finding>) -> usize {
    let before = findings.len();
    findings.retain(|f| match known.get_mut(&Known::of(f)) {
        Some(n) if *n > 0 => {
            *n -= 1;
            false
        }
        _ => true,
    });
    before - findings.len()
}

fn findings(n: usize) -> String {
    if n == 1 {
        "1 finding".into()
    } else {
        format!("{n} findings")
    }
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    Severity::parse(s)
        .ok_or_else(|| format!("unknown severity `{s}` (low, medium, high, critical)"))
}

/// GitHub code scanning reads SARIF paths from the repository root, so they start at the working
/// directory (where the action runs) instead of the scanned folder. This is that folder as a
/// `dir/` prefix, or nothing when it is the working directory or lies outside it.
fn sarif_prefix(root: &Path) -> String {
    let dir = match root.parent() {
        Some(parent) if root.is_file() => parent,
        _ => root,
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Ok(cwd) = std::env::current_dir() else {
        return String::new();
    };
    let plain = std::path::absolute(dir)
        .ok()
        .filter(|p| !p.components().any(|c| c == Component::ParentDir))
        .and_then(|p| p.strip_prefix(&cwd).ok().map(Path::to_path_buf));
    // `..`, or a symlink like macOS's /tmp, needs the real paths.
    let rel = plain.or_else(|| {
        let (dir, cwd) = (dir.canonicalize().ok()?, cwd.canonicalize().ok()?);
        dir.strip_prefix(cwd).ok().map(Path::to_path_buf)
    });
    rel.map(|p| {
        p.components()
            .map(|c| format!("{}/", c.as_os_str().to_string_lossy()))
            .collect()
    })
    .unwrap_or_default()
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("mcp") {
        return match safe_anything::mcp::serve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }
    let cli = Cli::parse();
    if cli.list_rules {
        let rules = safe_anything::rules();
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&rules).unwrap());
        } else {
            for r in rules {
                println!(
                    "{:<36} {:<9} {:<9} {}",
                    r.id,
                    r.severity.as_str(),
                    r.cwe,
                    r.message
                );
            }
        }
        return ExitCode::SUCCESS;
    }
    let fail_on = match cli.fail_on.as_str() {
        "never" => None,
        s => match Severity::parse(s) {
            Some(s) => Some(s),
            None => {
                eprintln!("error: unknown --fail-on `{s}` (low, medium, high, critical, never)");
                return ExitCode::from(2);
            }
        },
    };
    let mut baseline = match cli.baseline.as_deref().map(load_baseline).transpose() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let mut options = if cli.offline {
        Options::offline()
    } else {
        Options::online()
    };
    options.include_tests = cli.include_tests;
    let mut report = match safe_anything::scan(&cli.path, &options) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    report.findings.retain(|f| f.severity >= cli.severity);
    if let Some(file) = &cli.write_baseline {
        return match write_baseline(file, &report.findings) {
            Ok(()) => {
                let n = findings(report.findings.len());
                eprintln!("Wrote {n} to {}.", file.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }
    if let Some(known) = &mut baseline {
        let n = apply_baseline(known, &mut report.findings);
        let verb = if n == 1 { "is" } else { "are" };
        eprintln!("{} {verb} in the baseline and not shown.", findings(n));
    }
    let sarif = (cli.sarif || cli.sarif_file.is_some()).then(|| {
        let prefix = sarif_prefix(&cli.path);
        let paths: Vec<String> = report
            .findings
            .iter_mut()
            .map(|f| {
                let path = format!("{prefix}{}", f.path);
                std::mem::replace(&mut f.path, path)
            })
            .collect();
        let out = serde_json::to_string_pretty(&safe_anything::sarif::render(&report)).unwrap();
        for (f, path) in report.findings.iter_mut().zip(paths) {
            f.path = path;
        }
        out
    });
    if let Some(path) = &cli.sarif_file
        && let Some(sarif) = &sarif
        && let Err(e) = std::fs::write(path, format!("{sarif}\n"))
    {
        eprintln!("error: can't write {}: {e}", path.display());
        return ExitCode::from(2);
    }
    if cli.sarif
        && let Some(sarif) = &sarif
    {
        println!("{sarif}");
    } else if cli.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        print!("{}", report::terminal(&report, &report::Style { color }));
    }
    let failed = fail_on.is_some_and(|t| report.findings.iter().any(|f| f.severity >= t));
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(family: Family, line: usize, message: &str, snippet: &str) -> Finding {
        Finding {
            rule: "r".into(),
            family,
            severity: Severity::High,
            path: "p".into(),
            line,
            message: message.into(),
            fix: String::new(),
            snippet: snippet.into(),
            cwe: String::new(),
            owasp: String::new(),
            learn_more: String::new(),
        }
    }

    #[test]
    fn baseline_entry_ignores_the_line_but_not_a_new_advisory() {
        let code =
            |line, message, snippet| Known::of(&finding(Family::Code, line, message, snippet));
        assert!(code(1, "a", "x = 1") == code(9, "b", "  x = 1 "));
        assert!(code(1, "a", "x = 1") != code(1, "a", "x = 2"));
        assert_eq!(code(1, "a", "").sha256.len(), 64);
        let dep = |message| {
            Known::of(&finding(
                Family::Dependency,
                1,
                message,
                "lodash@4.17.20 (npm)",
            ))
        };
        assert!(
            dep("lodash 4.17.20 has known vulnerabilities: GHSA-1")
                == dep("lodash 4.17.20 has known vulnerabilities: GHSA-1")
        );
        assert!(
            dep("lodash 4.17.20 has known vulnerabilities: GHSA-1")
                != dep("lodash 4.17.20 has known vulnerabilities: GHSA-1; GHSA-2")
        );
    }
}
