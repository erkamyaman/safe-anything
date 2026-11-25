pub mod deps;
mod engine;
pub mod mcp;
mod refs;
pub mod report;
mod rules;
pub mod sarif;

use std::path::Path;

use serde::Serialize;

pub use deps::{Advisories, Advisory, OsvClient, Package};

#[derive(Serialize)]
pub struct RuleInfo {
    pub id: &'static str,
    pub family: Family,
    pub severity: Severity,
    pub message: &'static str,
    pub fix: &'static str,
    pub cwe: &'static str,
    pub owasp: &'static str,
    pub learn_more: &'static str,
}

impl RuleInfo {
    fn new(
        id: &'static str,
        family: Family,
        severity: Severity,
        message: &'static str,
        fix: &'static str,
    ) -> Self {
        let r = refs::of(id);
        Self {
            id,
            family,
            severity,
            message,
            fix,
            cwe: r.cwe,
            owasp: r.owasp,
            learn_more: r.learn_more,
        }
    }
}

pub fn rules() -> Vec<RuleInfo> {
    let mut seen = std::collections::HashSet::new();
    rules::all()
        .filter(|r| seen.insert(r.id))
        .map(|r| RuleInfo::new(r.id, r.family, r.severity, r.message, r.fix))
        .chain(
            rules::agent::STRUCTURED
                .iter()
                .map(|&(id, severity, message, fix)| {
                    RuleInfo::new(id, Family::Agent, severity, message, fix)
                }),
        )
        .chain(std::iter::once({
            let (id, severity, message, fix) = rules::secrets::ENV_NOT_IGNORED;
            RuleInfo::new(id, Family::Secret, severity, message, fix)
        }))
        .chain(std::iter::once(RuleInfo::new(
            "dependency.known-vulnerability",
            Family::Dependency,
            Severity::High,
            "A locked dependency version has a published advisory (OSV.dev).",
            "Upgrade the package to the fixed version the advisory names, or read the advisory for workarounds if none is published.",
        )))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Code,
    Secret,
    Agent,
    Mobile,
    Config,
    Dependency,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Secret => "secret",
            Self::Agent => "agent",
            Self::Mobile => "mobile",
            Self::Config => "config",
            Self::Dependency => "dependency",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: String,
    pub family: Family,
    pub severity: Severity,
    pub path: String,
    pub line: usize,
    pub message: String,
    pub fix: String,
    pub snippet: String,
    pub cwe: String,
    pub owasp: String,
    pub learn_more: String,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        rule: &str,
        family: Family,
        severity: Severity,
        path: String,
        line: usize,
        message: String,
        fix: String,
        snippet: String,
    ) -> Self {
        let r = refs::of(rule);
        Self {
            rule: rule.to_string(),
            family,
            severity,
            path,
            line,
            message,
            fix,
            snippet,
            cwe: r.cwe.to_string(),
            owasp: r.owasp.to_string(),
            learn_more: r.learn_more.to_string(),
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub packages_checked: usize,
    pub elapsed_ms: u64,
    pub dependency_check: DependencyCheck,
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum DependencyCheck {
    #[default]
    Skipped,
    Done,
    Failed(String),
}

pub struct Options {
    pub advisories: Option<Box<dyn Advisories>>,
    pub include_tests: bool,
}

impl Options {
    pub fn offline() -> Self {
        Self {
            advisories: None,
            include_tests: false,
        }
    }

    pub fn online() -> Self {
        Self {
            advisories: Some(Box::new(OsvClient::default())),
            include_tests: false,
        }
    }
}

pub fn scan(root: &Path, options: &Options) -> std::io::Result<Report> {
    if !root.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} does not exist", root.display()),
        ));
    }
    let started = std::time::Instant::now();
    let mut scanned = engine::scan_files(root, options.include_tests);
    if root.is_dir() {
        scanned
            .findings
            .extend(rules::secrets::env_not_ignored(root, &scanned.env_files));
    }
    let mut report = Report {
        files_scanned: scanned.files,
        packages_checked: scanned.packages.len(),
        findings: scanned.findings,
        ..Report::default()
    };
    if let Some(source) = &options.advisories {
        if scanned.packages.is_empty() {
            report.dependency_check = DependencyCheck::Done;
        } else {
            match source.lookup(&scanned.packages) {
                Ok(found) => {
                    report
                        .findings
                        .extend(deps::findings(&scanned.packages, found));
                    report.dependency_check = DependencyCheck::Done;
                }
                Err(e) => report.dependency_check = DependencyCheck::Failed(e),
            }
        }
    }
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    report
        .findings
        .sort_by(|a, b| (&a.path, a.line, &a.rule).cmp(&(&b.path, b.line, &b.rule)));
    Ok(report)
}
