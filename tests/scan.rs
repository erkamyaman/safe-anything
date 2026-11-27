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
fn secrets_without_gitignore() {
    // Self-contained: the project is built in a temp dir so the test does not
    // depend on a fixture folder that must exist alongside it.
    let root =
        std::env::temp_dir().join(format!("safe-anything-no-gitignore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(".env"), "SETTING=example-value\n").unwrap();
    let report = safe_anything::scan(&root, &safe_anything::Options::offline()).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "secret.env-not-ignored")
        .expect("expected an unignored .env finding");
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(finding.path, ".env");
    assert_eq!(finding.line, 1);
    assert!(
        finding.snippet.is_empty(),
        "secret leaked in snippet: {}",
        finding.snippet
    );
    assert!(!format!("{finding:?}").contains("example-value"));
}

#[test]
fn env_example_without_gitignore() {
    let root = std::env::temp_dir().join(format!(
        "safe-anything-example-no-gitignore-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(".env.example"), "SETTING=\n").unwrap();
    let report = safe_anything::scan(&root, &safe_anything::Options::offline()).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.rule == "secret.env-not-ignored"),
        "a lone .env.example should not be reported"
    );
}

#[test]
fn env_not_ignored_marker_with_rule_ids() {
    let root =
        std::env::temp_dir().join(format!("safe-anything-ignore-ids-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(".env"), "SETTING=example-value\n").unwrap();
    let reported = |gitignore: &str| {
        std::fs::write(root.join(".gitignore"), gitignore).unwrap();
        let report = safe_anything::scan(&root, &safe_anything::Options::offline()).unwrap();
        report
            .findings
            .iter()
            .any(|f| f.rule == "secret.env-not-ignored")
    };
    let other = reported("# safe-anything:ignore code.eval\nnode_modules\n");
    let this = reported("# safe-anything:ignore secret.env-not-ignored\nnode_modules\n");
    let bare = reported("# safe-anything:ignore\nnode_modules\n");
    let _ = std::fs::remove_dir_all(&root);
    assert!(other, "a marker for another rule keeps the finding");
    assert!(!this, "a marker for this rule drops it");
    assert!(!bare, "a bare marker drops it");
}

#[test]
fn file_kinds_scanned_and_skipped() {
    let root =
        std::env::temp_dir().join(format!("safe-anything-file-kinds-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let line = format!("aws_access_key_id = {}\n", common::fake("aws"));
    let filler = "x".repeat(10_000);
    let files: &[(&str, Vec<u8>)] = &[
        // Scanned: text, whatever the extension, and the key may come after 8 KB.
        ("notes.weird", line.clone().into_bytes()),
        ("long.txt", format!("{filler}\n{line}").into_bytes()),
        ("late-zero.weird", format!("{line}{filler}\0").into_bytes()),
        (
            "exact-8k.txt",
            format!("{}\n{line}", "x".repeat(8191 - line.len())).into_bytes(),
        ),
        ("report.pdf", line.clone().into_bytes()),
        // Skipped: a zero byte in the first 8 KB means binary.
        ("blob.weird", format!("\0{line}").into_bytes()),
        (
            "zero-at-8191.weird",
            format!("{line}{}\0", "x".repeat(8191 - line.len())).into_bytes(),
        ),
        // Skipped by name, without being read.
        ("app.min.js", line.clone().into_bytes()),
        ("app.js.map", line.clone().into_bytes()),
        ("server.log", line.clone().into_bytes()),
        ("rows.jsonl", line.clone().into_bytes()),
        ("logo.png", line.clone().into_bytes()),
        ("font.woff2", line.clone().into_bytes()),
        ("bundle.zip", line.clone().into_bytes()),
    ];
    for (name, bytes) in files {
        std::fs::write(root.join(name), bytes).unwrap();
    }
    let report = safe_anything::scan(&root, &safe_anything::Options::offline()).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    let found: BTreeSet<&str> = report
        .findings
        .iter()
        .filter(|f| f.rule == "secret.aws-access-key")
        .map(|f| f.path.as_str())
        .collect();
    let expected = BTreeSet::from([
        "exact-8k.txt",
        "late-zero.weird",
        "long.txt",
        "notes.weird",
        "report.pdf",
    ]);
    assert_eq!(found, expected);
    assert_eq!(report.files_scanned, 5);
}

#[test]
fn gitignore_must_really_match_env() {
    // (.gitignore contents, env file in the project, expect the finding)
    let cases = [
        (".envrc\n", ".env", true),
        (".env.local\n", ".env", true),
        (".env.example\n", ".env", true),
        (".env.*\n", ".env", true),
        ("# .env\n", ".env", true),
        (".env/\n", ".env", true),
        ("config/.env\n", ".env", true),
        (".env*\n!.env\n", ".env", true),
        ("node_modules\n", ".env", true),
        (".env\n", ".env.production", false),
        ("/.env\n", ".env.production", false),
        ("**/.env\n", ".env.production", false),
        ("*.env\n", ".env.production", false),
        (".env   \n", ".env.production", false),
        (".env\r\n", ".env.production", false),
        ("\u{feff}.env\n", ".env.production", false),
        (".env*\n!.env.production\n", ".env.production", false),
        (".env\n!.env.example\n", ".env.production", false),
    ];
    let root =
        std::env::temp_dir().join(format!("safe-anything-env-patterns-{}", std::process::id()));
    let mut wrong = Vec::new();
    for (gitignore, env, expected) in cases {
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".gitignore"), gitignore).unwrap();
        std::fs::write(root.join(env), "DEBUG=1\n").unwrap();
        let report = safe_anything::scan(&root, &safe_anything::Options::offline()).unwrap();
        let found = report
            .findings
            .iter()
            .any(|f| f.rule == "secret.env-not-ignored");
        if found != expected {
            wrong.push((gitignore, env, expected));
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        wrong.is_empty(),
        "(gitignore, env file, expected finding): {wrong:#?}"
    );
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
        ("Pub", "http", "0.13.2"),
    ]);
    let options = safe_anything::Options {
        advisories: Some(Box::new(known)),
        include_tests: false,
    };
    // Entries that are not fetched from a registry must be skipped (not counted
    // as a dependency): the `my-app@workspace:.` entry in web/yarn.lock, and the
    // gems in the `GIT` and `PATH` sections of rb/Gemfile.lock, and the editable
    // git checkout of `requests` in pipenv/Pipfile.lock. Only the gems in its two
    // `GEM` sections count. In bun/bun.lock the `ui@workspace:` and `debug@github:`
    // entries are skipped the same way.
    check_with("deps", options, Some(31));
}

/// Writes a package-lock.json listing `n` packages, padded with a long
/// `resolved` URL so a few thousand entries pass the size of an ordinary file.
/// Sorted, the keys are in byte order as npm writes them; otherwise `pkg-{i}`
/// sits in numeric order, and its version is on line `7 + 5 * i`.
fn big_lockfile(dir: &std::path::Path, n: usize, sorted: bool) -> u64 {
    let mut text = String::from(
        "{\n  \"name\": \"app\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"\": { \"name\": \"app\" }",
    );
    let mut ids: Vec<usize> = (0..n).collect();
    if sorted {
        ids.sort_by_key(|i| format!("pkg-{i}"));
    }
    for i in ids {
        text.push_str(&format!(
            ",\n    \"node_modules/pkg-{i}\": {{\n      \"version\": \"1.0.{i}\",\n      \"resolved\": \"https://registry.npmjs.org/pkg-{i}/-/pkg-{i}-1.0.{i}.tgz\",\n      \"integrity\": \"sha512-{}\"\n    }}",
            "a".repeat(88)
        ));
    }
    text.push_str("\n  }\n}\n");
    std::fs::write(dir.join("package-lock.json"), &text).unwrap();
    text.len() as u64
}

#[test]
fn large_lockfile_is_still_read() {
    let root = std::env::temp_dir().join(format!("safe-anything-big-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let size = big_lockfile(&root, 12_000, true);
    let report = safe_anything::scan(&root, &safe_anything::Options::offline()).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        size > 2 * 1024 * 1024,
        "the lockfile should be over 2 MB, it is {size} bytes"
    );
    assert_eq!(
        report.packages_checked, 12_000,
        "packages read from a {size}-byte lockfile"
    );
}

#[test]
fn large_lockfile_out_of_byte_order_keeps_its_lines() {
    let root = std::env::temp_dir().join(format!(
        "safe-anything-big-lock-unsorted-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    big_lockfile(&root, 12_000, false);
    let options = safe_anything::Options {
        advisories: Some(Box::new(Known(&[
            ("npm", "pkg-9", "1.0.9"),
            ("npm", "pkg-10", "1.0.10"),
            ("npm", "pkg-11999", "1.0.11999"),
        ]))),
        include_tests: false,
    };
    let report = safe_anything::scan(&root, &options).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    let mut lines: Vec<usize> = report.findings.iter().map(|f| f.line).collect();
    lines.sort_unstable();
    assert_eq!(report.packages_checked, 12_000);
    assert_eq!(lines, [7 + 5 * 9, 7 + 5 * 10, 7 + 5 * 11_999]);
}

#[test]
fn lockfile_over_the_limit_is_named() {
    let root = std::env::temp_dir().join(format!("safe-anything-huge-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("web")).unwrap();
    // Sized from the metadata, so these are never read.
    let over = 64 * 1024 * 1024 + 1;
    for name in ["web/yarn.lock", "notes.txt"] {
        std::fs::File::create(root.join(name))
            .unwrap()
            .set_len(over)
            .unwrap();
    }
    let report = safe_anything::scan(&root, &safe_anything::Options::offline()).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(report.lockfiles_too_large, ["web/yarn.lock"]);
    assert_eq!(report.packages_checked, 0);
}
