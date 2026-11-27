use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn body(n: usize, alphabet: &str) -> String {
    alphabet.chars().cycle().take(n).collect()
}

const MIXED: &str = "Q7mZ2xK9pL4vR8tN3wB6yH1cF5jD0sG";
const UPPER: &str = "Q7MZ2XK9PL4VR8TN3WB6YH1CF5JD0SG";
const LETTERS: &str = "QmZxKpLvRtNwByHcFjDsG";
const HEX: &str = "a3f91c07d5e284b6";
// The Bech32 alphabet in upper case, as age writes its keys.
const BECH32: &str = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L";
// Unlike the others, so a leak of this body is not mistaken for another token.
const KEY_BODY: &str = "Zr8Wq2Xn5Mb7Vc4Lk1Jh6Gf9Dd3Ss0AaUe";

pub fn fake(name: &str) -> String {
    match name {
        "aws" => ["AK", "IA", &body(16, UPPER)].concat(),
        "aws-secret" => [
            &body(18, MIXED),
            "/",
            &body(10, LETTERS),
            "+",
            &body(10, HEX),
        ]
        .concat(),
        "aws-secret-example" => [&body(30, MIXED), "EXAMPLE", "KEY"].concat(),
        "github" => ["gh", "p_", &body(36, MIXED)].concat(),
        "gitlab" => ["gl", "pat-", &body(20, MIXED)].concat(),
        "gitlab-deploy" => ["gl", "dt-", &body(20, MIXED)].concat(),
        "gitlab-trigger" => ["gl", "ptt-", &body(40, HEX)].concat(),
        "gitlab-trigger-upper" => ["gl", "ptt-", &body(40, HEX).to_uppercase()].concat(),
        "github-pat" => ["github", "_pat_", &body(82, MIXED)].concat(),
        "slack" => [
            "xo",
            "xb-",
            "4815162342-",
            "1123581321345-",
            &body(24, MIXED),
        ]
        .concat(),
        "slack-app" => [
            "xa",
            "pp-1-",
            "A0",
            &body(9, UPPER),
            "-4815162342123-",
            &body(64, HEX),
        ]
        .concat(),
        "slack-webhook" => [
            "https://hooks.",
            "slack.com/services/",
            "T0",
            &body(9, UPPER),
            "/B0",
            &body(9, UPPER),
            "/",
            &body(24, MIXED),
        ]
        .concat(),
        "stripe-live" => ["sk", "_live_", &body(24, MIXED)].concat(),
        "npm" => ["np", "m_", &body(36, MIXED)].concat(),
        "huggingface-token" => ["h", "f_", &body(34, LETTERS)].concat(),
        "stripe-test" => ["sk", "_test_", &body(24, MIXED)].concat(),
        "anthropic" => ["sk-", "ant-api03-", &body(40, MIXED)].concat(),
        "openai" => ["sk-", "proj-", &body(48, MIXED)].concat(),
        "google" => ["AI", "za", &body(35, MIXED)].concat(),
        "google-oauth" => ["GO", "CSPX-", &body(28, MIXED)].concat(),
        "google-oauth-hyphen" => ["GO", "CSPX-", &body(27, MIXED), "-"].concat(),
        "mailgun" => ["ke", "y-", &body(32, HEX)].concat(),
        "groq" => ["gs", "k_", &body(52, MIXED)].concat(),
        "perplexity" => ["pp", "lx-", &body(48, MIXED)].concat(),
        "perplexity-upper" => ["pp", "lx-", &body(48, MIXED).to_uppercase()].concat(),
        "openrouter" => ["sk-or", "-v1-", &body(64, HEX)].concat(),
        "openrouter-short" => ["sk-or", "-v1-", &body(63, HEX)].concat(),
        "openrouter-upper" => ["sk-or", "-v1-", &body(64, HEX).to_uppercase()].concat(),
        "notion" => ["nt", "n_", "1234", "5678901", &body(35, MIXED)].concat(),
        "notion-letter-in-prefix" => ["nt", "n_", "1234", "567a901", &body(35, MIXED)].concat(),
        "notion-short" => ["nt", "n_", "1234", "5678901", &body(34, MIXED)].concat(),
        "telegram" => ["1234", "567890", ":", &body(35, MIXED)].concat(),
        "telegram-hyphen" => ["1234", "567890", ":", &body(34, MIXED), "-"].concat(),
        "password" => ["hunter2", "hunter2"].concat(),
        "db-password" => ["S3cret", "Passw0rd"].concat(),
        "base64-padded" => [&body(30, MIXED), "=="].concat(),
        "symbol-secret" => [
            &body(8, MIXED),
            "!",
            &body(4, LETTERS),
            "#",
            &body(4, HEX),
            "%",
        ]
        .concat(),
        "random" => body(40, MIXED),
        "private-key" => [
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\n",
            "MIIEowIBAAKCAQEA",
            &body(48, MIXED),
        ]
        .concat(),
        // How a Google service-account JSON file stores a key: one JSON
        // string, with `\n` escapes instead of line breaks.
        "private-key-json" => [
            "-----BEGIN ",
            "PRIVATE KEY-----\\n",
            "MIIEvQIBADANBgkq",
            &body(48, KEY_BODY),
            "\\n",
            &body(64, KEY_BODY),
            "\\n",
            &body(40, KEY_BODY),
            "=\\n-----END ",
            "PRIVATE KEY-----\\n",
        ]
        .concat(),
        "discord-webhook" => [
            "https://disc",
            "ord.com/api/webhooks/",
            "1234567890",
            "12345678/",
            &body(34, MIXED),
            "-",
            &body(33, MIXED),
        ]
        .concat(),
        "sendgrid-key" => ["S", "G.", &body(22, MIXED), ".", &body(43, MIXED)].concat(),
        "pypi-token" => ["py", "pi-", "AgEIcHlw", "aS5vcmc", &body(70, MIXED)].concat(),
        "shopify-token" => ["sh", "pat_", &body(32, HEX)].concat(),
        "digitalocean-token" => ["do", "p_v1_", &body(64, HEX)].concat(),
        "twilio" => ["S", "K", &body(32, HEX)].concat(),
        "linear" => ["lin", "_api_", &body(40, MIXED)].concat(),
        "prefect" => ["pn", "u_", &body(36, MIXED)].concat(),
        "postman" => ["PM", "AK-", &body(24, HEX), "-", &body(34, HEX)].concat(),
        "postman-upper" => ["PM", "AK-", &body(24, HEX), "-", &body(34, HEX)]
            .concat()
            .to_uppercase(),
        "pulumi-token" => ["pu", "l-", &body(40, HEX)].concat(),
        "pulumi-upper" => ["pu", "l-", &body(40, HEX).to_uppercase()].concat(),
        "sentry" => ["sntr", "yu_", &body(64, HEX)].concat(),
        "newrelic" => ["NR", "AK-", &body(27, UPPER)].concat(),
        "newrelic-short" => ["NR", "AK-", &body(26, UPPER)].concat(),
        "supabase" => ["sb", "p_", &body(40, HEX)].concat(),
        "grafana" => ["gl", "sa_", &body(32, MIXED), "_", &body(8, HEX)].concat(),
        "doppler" => ["dp", ".pt.", &body(43, MIXED)].concat(),
        "rubygems" => ["ruby", "gems_", &body(48, HEX)].concat(),
        "rubygems-upper" => ["ruby", "gems_", &body(48, HEX).to_uppercase()].concat(),
        "databricks" => ["da", "pi", &body(32, HEX)].concat(),
        "databricks-suffix" => ["da", "pi", &body(32, HEX), "-2"].concat(),
        "databricks-upper" => ["da", "pi", &body(32, HEX).to_uppercase()].concat(),
        "age" => ["AGE-SECRET-", "KEY-1", &body(58, BECH32)].concat(),
        // `B` is not in the Bech32 alphabet.
        "age-not-bech32" => ["AGE-SECRET-", "KEY-1", &body(57, BECH32), "B"].concat(),
        "age-pq" => ["AGE-SECRET-", "KEY-PQ-1", &body(58, BECH32)].concat(),
        "age-pq-short" => ["AGE-SECRET-", "KEY-PQ-1", &body(57, BECH32)].concat(),
        "age-pq-not-bech32" => ["AGE-SECRET-", "KEY-PQ-1", &body(57, BECH32), "B"].concat(),
        "dockerhub" => ["dckr", "_pat_", &body(26, MIXED), "-"].concat(),
        "heroku" => ["HR", "KU-AA", &body(57, MIXED), "-"].concat(),
        "heroku-short" => ["HR", "KU-AA", &body(57, MIXED)].concat(),
        "heroku-no-aa" => ["HR", "KU-", &body(58, MIXED)].concat(),
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
