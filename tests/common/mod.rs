use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn body(n: usize, alphabet: &str) -> String {
    alphabet.chars().cycle().take(n).collect()
}

const MIXED: &str = "Q7mZ2xK9pL4vR8tN3wB6yH1cF5jD0sG";
const UPPER: &str = "Q7MZ2XK9PL4VR8TN3WB6YH1CF5JD0SG";

pub fn fake(name: &str) -> String {
    match name {
        "aws" => ["AK", "IA", &body(16, UPPER)].concat(),
        "github" => ["gh", "p_", &body(36, MIXED)].concat(),
        "gitlab" => ["gl", "pat-", &body(20, MIXED)].concat(),
        "github-pat" => ["github", "_pat_", &body(82, MIXED)].concat(),
        "slack" => [
            "xo",
            "xb-",
            "4815162342-",
            "1123581321345-",
            &body(24, MIXED),
        ]
        .concat(),
        "stripe-live" => ["sk", "_live_", &body(24, MIXED)].concat(),
        "npm" => ["np", "m_", &body(36, MIXED)].concat(),
        "stripe-test" => ["sk", "_test_", &body(24, MIXED)].concat(),
        "anthropic" => ["sk-", "ant-api03-", &body(40, MIXED)].concat(),
        "openai" => ["sk-", "proj-", &body(48, MIXED)].concat(),
        "google" => ["AI", "za", &body(35, MIXED)].concat(),
        "password" => ["hunter2", "hunter2"].concat(),
        "db-password" => ["S3cret", "Passw0rd"].concat(),
        "random" => body(40, MIXED),
        "private-key" => [
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\n",
            "MIIEowIBAAKCAQEA",
            &body(48, MIXED),
        ]
        .concat(),
        other => panic!("no fake value named {other}"),
    }
}

fn fill(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{fake:") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 7..];
        let end = tail.find("}}").expect("closing }} for fake placeholder");
        out.push_str(&fake(&tail[..end]));
        rest = &tail[end + 2..];
    }
    out.push_str(rest);
    out
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy(&entry.path(), &target);
        } else {
            let bytes = std::fs::read(entry.path()).unwrap();
            match String::from_utf8(bytes) {
                Ok(text) => std::fs::write(&target, fill(&text)).unwrap(),
                Err(e) => std::fs::write(&target, e.into_bytes()).unwrap(),
            }
        }
    }
}

pub fn fixtures() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "safe-anything-fixtures-{}-{}",
            env!("CARGO_CRATE_NAME"),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        copy(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
            &dir,
        );
        dir
    })
}
