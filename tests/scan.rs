mod common;

use std::collections::BTreeSet;

fn check(family: &str) {
    check_with(family, safe_anything::Options::offline(), None);
}

fn check_with(family: &str, options: safe_anything::Options, packages: Option<usize>) {
    let root = common::fixtures().join(family);
    let expected: BTreeSet<String> = std::fs::read_to_string(root.join("EXPECTED"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| l.trim().to_string())
        .collect();
    let report = safe_anything::scan(&root, &options).unwrap();
    if let Some(n) = packages {
        assert_eq!(report.packages_checked, n, "packages read from lockfiles");
    }
    let found: BTreeSet<String> = report
        .findings
        .iter()
        .map(|f| format!("{}:{} {}", f.path, f.line, f.rule))
        .collect();
    let missing: Vec<_> = expected.difference(&found).collect();
    let extra: Vec<_> = found.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "missing (not found): {missing:#?}\nextra (false positives): {extra:#?}"
    );
}

#[test]
fn secrets() {
    check("secrets");
}

#[test]
fn code() {
    check("code");
}

#[test]
fn agent() {
    check("agent");
}

#[test]
fn mobile() {
    check("mobile");
}

#[test]
fn config() {
    check("config");
}

struct Known(&'static [(&'static str, &'static str, &'static str)]);

impl safe_anything::Advisories for Known {
    fn lookup(
        &self,
        packages: &[safe_anything::Package],
    ) -> Result<std::collections::HashMap<usize, Vec<safe_anything::Advisory>>, String> {
        let mut out = std::collections::HashMap::new();
        for (i, p) in packages.iter().enumerate() {
            if self
                .0
                .contains(&(p.ecosystem.as_str(), p.name.as_str(), p.version.as_str()))
            {
                out.insert(
                    i,
                    vec![safe_anything::Advisory {
                        id: "GHSA-test-0001".into(),
                        summary: "Test advisory".into(),
                        severity: safe_anything::Severity::High,
                        fixed: Some("9.9.9".into()),
                    }],
                );
            }
        }
        Ok(out)
    }
}

#[test]
fn deps() {
    let known = Known(&[
        ("npm", "lodash", "4.17.20"),
        ("PyPI", "requests", "2.19.0"),
        ("Go", "github.com/gin-gonic/gin", "1.6.0"),
        ("RubyGems", "rack", "2.0.0"),
        ("crates.io", "smallvec", "1.0.0"),
        ("Packagist", "guzzlehttp/guzzle", "6.5.0"),
    ]);
    let options = safe_anything::Options {
        advisories: Some(Box::new(known)),
        include_tests: false,
    };
    // The web/yarn.lock fixture contains a `my-app@workspace:.` entry that must be
    // skipped (not counted as a dependency). The expected package count stays 18.
    check_with("deps", options, Some(18));
}
