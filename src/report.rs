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
            "{} package{} checked against OSV.dev",
            report.packages_checked,
            if report.packages_checked == 1 {
                ""
            } else {
                "s"
            }
        ),
        DependencyCheck::Failed(e) => format!("failed: {e}"),
    };
    let _ = writeln!(
        out,
        "{}",
        style.paint(
            "2",
            &format!(
                "Scanned {} file{} in {:.2} s. Dependencies: {deps}.",
                thousands(report.files_scanned),
                if report.files_scanned == 1 { "" } else { "s" },
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
    if !report.lockfiles_binary.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            style.paint(
                "2",
                &format!(
                    "Not checked, binary lockfile: {}. Run bun install --save-text-lockfile to write bun.lock.",
                    report.lockfiles_binary.join(", ")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(files: usize, packages: usize) -> String {
        let report = Report {
            files_scanned: files,
            packages_checked: packages,
            dependency_check: DependencyCheck::Done,
            ..Default::default()
        };
        terminal(&report, &Style { color: false })
    }

    #[test]
    fn binary_lockfiles_are_named_after_the_summary() {
        let report = Report {
            lockfiles_binary: vec!["bun.lockb".to_string(), "web/bun.lockb".to_string()],
            dependency_check: DependencyCheck::Done,
            ..Default::default()
        };
        let out = terminal(&report, &Style { color: false });
        assert!(
            out.contains(
                "Not checked, binary lockfile: bun.lockb, web/bun.lockb. Run bun install --save-text-lockfile to write bun.lock."
            ),
            "{out}"
        );
        assert!(!summary(1, 1).contains("binary lockfile"));
    }

    #[test]
    fn summary_line_uses_singular_for_one() {
        let out = summary(1, 1);
        assert!(out.contains("Scanned 1 file in "), "{out}");
        assert!(out.contains("1 package checked against OSV.dev"), "{out}");
    }

    #[test]
    fn summary_line_keeps_plural_and_thousands_separator() {
        let out = summary(1195, 2);
        assert!(out.contains("Scanned 1,195 files in "), "{out}");
        assert!(out.contains("2 packages checked against OSV.dev"), "{out}");
        let out = summary(0, 0);
        assert!(out.contains("Scanned 0 files in "), "{out}");
        assert!(out.contains("0 packages checked against OSV.dev"), "{out}");
    }
}
