use std::fmt::Write;

use crate::{DependencyCheck, Report, Severity};

pub struct Style {
    pub color: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn severity(&self, s: Severity) -> String {
        let label = format!("{:<8}", s.as_str().to_uppercase());
        match s {
            Severity::Critical => self.paint("1;35", &label),
            Severity::High => self.paint("1;31", &label),
            Severity::Medium => self.paint("33", &label),
            Severity::Low => self.paint("36", &label),
        }
    }
}

pub fn terminal(report: &Report, style: &Style) -> String {
    let mut out = String::new();
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then((&a.path, a.line).cmp(&(&b.path, b.line)))
    });
    for f in &findings {
        let _ = writeln!(
            out,
            "{} {}  {}",
            style.severity(f.severity),
            style.paint("1", &format!("{}:{}", f.path, f.line)),
            style.paint("2", &f.rule)
        );
        let _ = writeln!(out, "         {}", f.message);
        if !f.snippet.is_empty() {
            let _ = writeln!(
                out,
                "         {}",
                style.paint("2", &format!("> {}", f.snippet))
            );
        }
        let _ = writeln!(out, "         {} {}\n", style.paint("32", "Fix:"), f.fix);
    }
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    if findings.is_empty() {
        let _ = writeln!(out, "{}", style.paint("1;32", "No problems found."));
    } else {
        let parts: Vec<String> = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ]
        .into_iter()
        .filter(|&s| count(s) > 0)
        .map(|s| format!("{} {}", count(s), s.as_str()))
        .collect();
        let _ = writeln!(
            out,
            "{} {}",
            style.paint(
                "1",
                &format!(
                    "{} finding{}:",
                    findings.len(),
                    if findings.len() == 1 { "" } else { "s" }
                )
            ),
            parts.join(", ")
        );
    }
    let deps = match &report.dependency_check {
        DependencyCheck::Skipped => "skipped (offline)".to_string(),
        DependencyCheck::Done => format!(
            "{} packages checked against OSV.dev",
            report.packages_checked
        ),
        DependencyCheck::Failed(e) => format!("failed: {e}"),
    };
    let _ = writeln!(
        out,
        "{}",
        style.paint(
            "2",
            &format!(
                "Scanned {} files in {:.2} s. Dependencies: {deps}.",
                thousands(report.files_scanned),
                report.elapsed_ms as f64 / 1000.0
            )
        )
    );
    if !report.lockfiles_too_large.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            style.paint(
                "2",
                &format!(
                    "Not checked, over {} MB: {}.",
                    crate::engine::MAX_LOCK_BYTES / (1024 * 1024),
                    report.lockfiles_too_large.join(", ")
                )
            )
        );
    }
    out
}

fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
