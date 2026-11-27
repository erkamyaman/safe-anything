use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use ignore::gitignore::GitignoreBuilder;

use super::{FileInfo, Meta, Rule, Text, finding};
use crate::{Family, Finding, Severity};

pub const NAME_ONLY: &[&str] = &["secret.public-env-secret"];
pub const ENV_VALUE_RULES: &[&str] = &["secret.env-file", "secret.env-example-value"];

pub const ENV_NOT_IGNORED: (&str, Severity, &str, &str) = (
    "secret.env-not-ignored",
    Severity::Medium,
    "The project has env files but .gitignore does not exclude .env, so real secrets are one git add away from the repository.",
    "Add .env and .env.* to .gitignore, with !.env.example so the example file stays tracked.",
);

pub fn is_env(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.")
}

pub fn env_not_ignored(root: &Path, env_files: &[String]) -> Option<Finding> {
    let first_env = env_files.iter().filter(|p| !is_env_template(p)).min()?;
    // With no .gitignore nothing is ignored, so report at the env file itself.
    let gitignore = std::fs::read_to_string(root.join(".gitignore")).ok();
    let covered = gitignore
        .as_deref()
        .is_some_and(|src| ignores_env(root, src));
    if covered {
        return None;
    }
    let has_gitignore = gitignore.is_some();
    let (file, src) = match gitignore {
        Some(src) => (".gitignore".to_string(), src),
        None => (
            first_env.clone(),
            std::fs::read_to_string(root.join(first_env)).unwrap_or_default(),
        ),
    };
    let text = Text::new(&src);
    if text.suppressed(1, ENV_NOT_IGNORED.0) {
        return None;
    }
    // `.env` contents are only needed to honor suppression directives; never
    // copy the secret value into a diagnostic snippet.
    let empty = Text::new("");
    let finding_text = if has_gitignore { &text } else { &empty };
    let (id, severity, message, fix) = ENV_NOT_IGNORED;
    Some(finding(
        &FileInfo::new(&file),
        finding_text,
        1,
        Meta {
            id,
            family: Family::Secret,
            severity,
            message,
            fix,
        },
    ))
}

/// Whether `.gitignore` text really ignores a `.env` file at the root, read
/// the way git reads it: comments, negations, anchors, directory-only
/// patterns, trailing spaces and a leading byte order mark all count. A line
/// that is not a valid pattern is skipped.
fn ignores_env(root: &Path, src: &str) -> bool {
    let mut builder = GitignoreBuilder::new(root);
    for line in src.trim_start_matches('\u{feff}').lines() {
        let _ = builder.add_line(None, line);
    }
    builder
        .build()
        .is_ok_and(|gitignore| gitignore.matched(root.join(".env"), false).is_ignore())
}

fn any_text(_: &FileInfo) -> bool {
    true
}

fn is_env_template(name: &str) -> bool {
    ["example", "sample", "template", "dist", "defaults"]
        .iter()
        .any(|s| name.ends_with(s))
}

fn env_file(f: &FileInfo) -> bool {
    is_env(&f.name) && !is_env_template(&f.name)
}

fn env_example(f: &FileInfo) -> bool {
    is_env(&f.name) && is_env_template(&f.name)
}

const ENV_SECRET_LINE: &str = concat!(
    r"(?m)^[ \t]*(?:export[ \t]+)?",
    r"(?:[A-Za-z0-9_]*(?i:secret|token|password|passwd|api_?key|private_?key|access_?key|auth|credential)[A-Za-z0-9_]*|(?:[A-Za-z0-9_]*_)?(?i:pass|pwd)(?:_[A-Za-z0-9_]*)?)",
    r"[ \t]*=[ \t]*(?:",
    r#""([A-Za-z0-9+/_.=!@#$%^&*\-]{16,})"[ \t]*(?:#[^\r\n]*)?"#,
    r#"|'([A-Za-z0-9+/_.=!@#$%^&*\-]{16,})'[ \t]*(?:#[^\r\n]*)?"#,
    r#"|([A-Za-z0-9+/_.=!@$%^&*\-][A-Za-z0-9+/_.=!@#$%^&*\-]{15,})(?:[ \t]+#[^\r\n]*)?[ \t]*"#,
    r")\r?$",
);

const ENV_PLACEHOLDER: &str = concat!(
    r"^[ \t]*(?:export[ \t]+)?(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|VUE_APP|PUBLIC)_",
    r#"|^[ \t]*(?:export[ \t]+)?(?:[A-Za-z0-9_]*_(?i:file|path|dir)|(?i:pwd))[ \t]*=[ \t]*["']?(?:/|\.\.?/|~/)"#,
    r"|^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]+[ \t]*=[ \t]*(?:",
    r#"(?i:["']?(?:[^ \t"']*(?:your|example|change|replace|placeholder|dummy|xxxx|\.\.\.|<)|sk_test_|pk_test_|(?-i:[a-z]+[-_][a-z]+[-_][a-z]+)))"#,
    r#"|"\*+"[ \t]*(?:#.*)?$"#,
    r#"|'\*+'[ \t]*(?:#.*)?$"#,
    r#"|\*+(?:[ \t]+#.*)?[ \t]*$"#,
    r#"|["']?\$"#,
    r")",
);

/// Drop a trailing `# ...` comment from an env assignment so it stays out of
/// the finding snippet. A `#` inside quotes, or inside an unquoted value with
/// no whitespace before it, is part of the value and stays.
pub fn strip_env_comment(line: &str) -> &str {
    let Some(eq) = line.find('=') else {
        return line;
    };
    let after_eq = &line[eq + 1..];
    let val_start = eq + 1 + (after_eq.len() - after_eq.trim_start_matches([' ', '\t']).len());
    let rest = &line[val_start..];
    if let Some(quote @ ('"' | '\'')) = rest.chars().next() {
        if let Some(close) = rest[1..].find(quote) {
            return &line[..val_start + 1 + close + 1];
        }
        return line;
    }
    if rest.starts_with('#') {
        return line[..val_start].trim_end_matches([' ', '\t']);
    }
    let bytes = rest.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#' && matches!(bytes[i - 1], b' ' | b'\t') {
            return line[..val_start + i].trim_end_matches([' ', '\t']);
        }
    }
    line.trim_end_matches([' ', '\t'])
}

// A name with `aws` and `secret` in it, then `=` or `:` and a 40-character value. `aws` and
// `secret` each start a word: at the start of the line, after a character that is not a letter
// or digit (`_`, `-`, `.`, a quote), right after the other word (`awssecret`), or as a camelCase
// word (`myAwsSecret`, `IAMAwsSecret`, `myAWSSecret`). So `flaws_secret` and `aws_unsecret` are
// not read as one. Between the name and the value: a closing quote and `]`
// (`environ["AWS_SECRET_ACCESS_KEY"] =`), a type (`: string =`, `: &str =`), and an opening
// quote or backtick. The value itself, and what follows it, is checked by `plausible`.
const AWS_SECRET_KEY: &str = concat!(
    r#"(?m)(?:(?:(?:^|[^A-Za-z0-9\r\n])(?i:aws)|[a-z0-9]AWS|[A-Za-z0-9]Aws)"#,
    r#"(?:(?i:secret)|[A-Za-z0-9_.\-]{0,64}(?:[_.\-](?i:secret)|[a-z0-9]SECRET|[A-Za-z0-9]Secret))"#,
    r#"|(?:(?:^|[^A-Za-z0-9\r\n])(?i:secret)|[a-z0-9]SECRET|[A-Za-z0-9]Secret)"#,
    r#"(?:(?i:aws)|[A-Za-z0-9_.\-]{0,64}(?:[_.\-](?i:aws)|[a-z0-9]AWS|[A-Za-z0-9]Aws)))"#,
    r#"[A-Za-z0-9_.\-]{0,64}["']?\]?[ \t]{0,8}"#,
    r#"(?::[ \t]{0,8}&?(?:'[A-Za-z_]{1,16}[ \t]{1,8})?[A-Za-z_][A-Za-z0-9_:<>]{0,64}[ \t]{0,8}=|:=|=>|[:=])"#,
    r#"[ \t]{0,8}["'`]?([A-Za-z0-9/+]{40})"#,
);

/// Whether a matched value can be a secret for the rule. Only `secret.aws-secret-key` is checked:
/// its value has no prefix, so placeholders and other 40-character strings have to be told apart
/// by the value alone, and its pattern stops after the 40 characters, so `after` (the text that
/// follows the match) must not go on with another base64 character.
pub fn plausible(id: &str, value: Option<&str>, after: &str) -> bool {
    id != "secret.aws-secret-key"
        || (value.is_some_and(plausible_aws_secret)
            && !after.starts_with(|c: char| c.is_ascii_alphanumeric() || "/+=".contains(c)))
}

/// Words that read as a name or a path: a first word in small letters, then words that start
/// with a capital or after `/` or `+`, each with digits only at its end
/// (`TestSecretKeyTestSecretKey1`, `myAwsSecretKey123`, `/Prod/East1/Payments/Keys`). In 40
/// random base64 characters every capital would have to be followed by a small letter and every
/// digit by a capital, `/`, `+` or the end, which practically never happens.
static WORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[/+]?[a-z]*[0-9]*(?:(?:[/+]?[A-Z]|[/+])[a-z]+[0-9]*)*[/+]?$").unwrap()
});

/// An AWS secret access key is 40 random base64 characters. So it has upper and lower case
/// letters, about 30 different characters, no repeating chunk, no run of the alphabet, and it
/// does not read as words or a path. That leaves out hex hashes, paths, `000...`, `xxx...`,
/// `abcd...`, `TestSecretKey...` and the AWS docs key (`...EXAMPLEKEY`).
fn plausible_aws_secret(value: &str) -> bool {
    let v = value.as_bytes();
    let distinct = v.iter().collect::<std::collections::HashSet<_>>().len();
    // A chunk of up to 20 characters repeated over the value, give or take two characters.
    let repeats = (1..=20.min(v.len() / 2)).any(|k| {
        let same = (0..v.len() - k).filter(|&i| v[i] == v[i + k]).count();
        same + k + 2 >= v.len()
    });
    let ascending = v
        .windows(2)
        .filter(|w| w[1] == w[0].wrapping_add(1))
        .count();
    v.iter().any(u8::is_ascii_uppercase)
        && v.iter().any(u8::is_ascii_lowercase)
        && !v.iter().all(u8::is_ascii_hexdigit)
        && !value.to_ascii_lowercase().contains("example")
        && distinct >= 12
        && !repeats
        && ascending < 10
        && !WORDS.is_match(value)
}

const ROTATE: &str = "Revoke this credential at the provider, then load it from the environment or a secrets manager and keep it out of the repository.";

macro_rules! secret {
    ($id:literal, $sev:ident, $pat:literal, $msg:literal) => {
        Rule {
            id: $id,
            family: Family::Secret,
            severity: Severity::$sev,
            files: any_text,
            pattern: $pat,
            unless: None,
            message: $msg,
            fix: ROTATE,
        }
    };
}

pub static RULES: &[Rule] = &[
    secret!(
        "secret.aws-access-key",
        Critical,
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "An AWS access key id is written in the file."
    ),
    Rule {
        id: "secret.aws-secret-key",
        family: Family::Secret,
        severity: Severity::Critical,
        files: any_text,
        pattern: AWS_SECRET_KEY,
        unless: None,
        message: "An AWS secret access key is written in the file.",
        fix: ROTATE,
    },
    secret!(
        "secret.github-token",
        Critical,
        r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})",
        "A GitHub token is written in the file."
    ),
    secret!(
        "secret.gitlab-token",
        Critical,
        r"\b(?:gl(?:pat|dt)-[0-9a-zA-Z_\-]{20}|glptt-[0-9a-f]{40}\b)",
        "A GitLab token is written in the file."
    ),
    secret!(
        "secret.slack-token",
        High,
        r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)",
        "A Slack token is written in the file."
    ),
    Rule {
        id: "secret.slack-webhook",
        family: Family::Secret,
        severity: Severity::High,
        files: any_text,
        pattern: r"\bhooks\.slack\.com/services/(T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24})\b",
        unless: Some(r"hooks\.slack\.com/services/[A-Za-z0-9/]*?(?:0{8}|(?i:x{8}))"),
        message: "A Slack incoming webhook URL is written in the file.",
        fix: ROTATE,
    },
    secret!(
        "secret.discord-webhook",
        High,
        r"https://(?:discord|discordapp)\.com/api/webhooks/([0-9]{17,20}/[A-Za-z0-9_\-]{60,})",
        "A Discord webhook URL is written in the file."
    ),
    secret!(
        "secret.stripe-live-key",
        Critical,
        r"\b[sr]k_live_[A-Za-z0-9]{24,}",
        "A live Stripe secret key is written in the file."
    ),
    secret!(
        "secret.shopify-token",
        Critical,
        r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
        "A Shopify access token is written in the file."
    ),
    secret!(
        "secret.npm-token",
        Critical,
        r"\bnpm_[A-Za-z0-9]{36}\b",
        "An npm access token is written in the file."
    ),
    secret!(
        "secret.pulumi-token",
        Critical,
        r"\bpul-[a-f0-9]{40}\b",
        "A Pulumi access token is written in the file."
    ),
    secret!(
        "secret.pypi-token",
        Critical,
        r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
        "A PyPI upload token is written in the file."
    ),
    secret!(
        "secret.rubygems-token",
        Critical,
        r"\brubygems_[0-9a-f]{48}\b",
        "A RubyGems API key is written in the file."
    ),
    secret!(
        "secret.dockerhub-token",
        Critical,
        r"\b(dckr_pat_[A-Za-z0-9_\-]{27})(?:[^A-Za-z0-9_\-]|\z)",
        "A Docker Hub personal access token is written in the file."
    ),
    secret!(
        "secret.huggingface-token",
        Critical,
        r"\bhf_[A-Za-z]{34}\b",
        "A Hugging Face access token is written in the file."
    ),
    secret!(
        "secret.anthropic-key",
        Critical,
        r"\bsk-ant-[A-Za-z0-9_\-]{32,}",
        "An Anthropic API key is written in the file."
    ),
    secret!(
        "secret.openai-key",
        Critical,
        r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{32,}|\bsk-[A-Za-z0-9]{48}\b",
        "An OpenAI API key is written in the file."
    ),
    secret!(
        "secret.groq-key",
        Critical,
        r"\bgsk_[A-Za-z0-9]{52}\b",
        "A Groq API key is written in the file."
    ),
    secret!(
        "secret.perplexity-key",
        Critical,
        r"\bpplx-[A-Za-z0-9]{48}\b",
        "A Perplexity API key is written in the file."
    ),
    secret!(
        "secret.openrouter-key",
        Critical,
        r"\bsk-or-v1-[0-9a-f]{64}\b",
        "An OpenRouter API key is written in the file."
    ),
    secret!(
        "secret.google-api-key",
        High,
        r"\bAIza[0-9A-Za-z_\-]{35}",
        "A Google API key is written in the file."
    ),
    secret!(
        "secret.google-oauth-secret",
        High,
        r"\bGOCSPX-[A-Za-z0-9_\-]{28}(?:[^A-Za-z0-9_\-]|\z)",
        "A Google OAuth client secret is written in the file."
    ),
    secret!(
        "secret.notion-token",
        Critical,
        r"\bntn_[0-9]{11}[A-Za-z0-9]{35}\b",
        "A Notion integration token is written in the file."
    ),
    secret!(
        "secret.mailgun-key",
        Critical,
        r"\bkey-[0-9a-f]{32}\b",
        "A Mailgun API key is written in the file."
    ),
    secret!(
        "secret.sendgrid-key",
        Critical,
        r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?:[^A-Za-z0-9_\-]|\z)",
        "A SendGrid API key is written in the file."
    ),
    secret!(
        "secret.telegram-bot-token",
        High,
        r"\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})(?:[^A-Za-z0-9_\-]|\z)",
        "A Telegram bot token is written in the file."
    ),
    secret!(
        "secret.digitalocean-token",
        Critical,
        r"\bdo[opr]_v1_[a-f0-9]{64}\b",
        "A DigitalOcean token is written in the file."
    ),
    secret!(
        "secret.heroku-key",
        Critical,
        r"(?:\\[nrt]|\b)(HRKU-AA[0-9A-Za-z_\-]{58})(?:[^0-9A-Za-z_\-]|\z)",
        "A Heroku API key is written in the file."
    ),
    secret!(
        "secret.flyio-token",
        Critical,
        r"(?:\\[nrt]|\b)(fo1_[A-Za-z0-9_\-]{43})(?:[^A-Za-z0-9_\-]|\z)",
        "A Fly.io access token is written in the file."
    ),
    secret!(
        "secret.databricks-token",
        Critical,
        r"\bdapi[0-9a-f]{32}(?:-\d)?\b",
        "A Databricks personal access token is written in the file."
    ),
    secret!(
        "secret.twilio-api-key",
        Critical,
        r"\bSK[0-9a-f]{32}\b",
        "A Twilio API key is written in the file."
    ),
    secret!(
        "secret.linear-api-key",
        Critical,
        r"\blin_api_[A-Za-z0-9]{40}\b",
        "A Linear API key is written in the file."
    ),
    secret!(
        "secret.prefect-api-key",
        Critical,
        r"\bpnu_[A-Za-z0-9]{36}\b",
        "A Prefect API key is written in the file."
    ),
    secret!(
        "secret.postman-api-key",
        Critical,
        r"\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b",
        "A Postman API key is written in the file."
    ),
    secret!(
        "secret.sentry-token",
        Critical,
        r"\bsntryu_[0-9a-f]{64}\b",
        "A Sentry user auth token is written in the file."
    ),
    secret!(
        "secret.newrelic-key",
        Critical,
        r"(?:\\[nrt]|\b)(NRAK-[A-Z0-9]{27})\b",
        "A New Relic user API key is written in the file."
    ),
    secret!(
        "secret.supabase-token",
        Critical,
        r"\bsbp_[0-9a-f]{40}\b",
        "A Supabase access token is written in the file."
    ),
    secret!(
        "secret.grafana-token",
        Critical,
        r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b",
        "A Grafana service account token is written in the file."
    ),
    secret!(
        "secret.doppler-token",
        Critical,
        r"\bdp\.pt\.[A-Za-z0-9]{43}\b",
        "A Doppler personal token is written in the file."
    ),
    secret!(
        "secret.age-key",
        Critical,
        // In a JSON string the key can follow an escape like `\n`, where `\b` fails
        // between `n` and `A`.
        r"(?:\\[nrt]|\b)(AGE-SECRET-KEY-(?:PQ-)?1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b",
        "An age private key is written in the file."
    ),
    secret!(
        "secret.private-key",
        Critical,
        // A PEM file has real line breaks. A JSON string (a Google
        // service-account key) has `\n` escapes instead; there the whole body
        // is on the line, so all of it is captured for redaction.
        r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----(?:\r?\n([A-Za-z0-9+/=]{20,})|\\n([A-Za-z0-9+/=]{20,}(?:\\n[A-Za-z0-9+/=]+)*))",
        "A private key is stored in the repository."
    ),
    Rule {
        id: "secret.hardcoded-password",
        family: Family::Secret,
        severity: Severity::High,
        files: any_text,
        pattern: r#"(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token|client_?secret)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']"#,
        unless: Some(
            r#"(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token|client_?secret)\b["']?\s*[:=]\s*["'](?:[^"']*(?:\.\.\.|…)|(\$|changeme|password|secret|example|x{3,}|your[-_]|<|\$\{|\{\{|%\(|dummy|test|placeholder|redacted|\*{3,}|none|null))"#,
        ),
        message: "A password or secret is written in the code.",
        fix: ROTATE,
    },
    Rule {
        id: "secret.url-credentials",
        family: Family::Secret,
        severity: Severity::High,
        files: any_text,
        pattern: r#"\b[a-z][a-z0-9+.\-]*://[^\s:/@"'`]+:[^\s@/"'`$]{4,}@[^\s"'`]+"#,
        unless: Some(
            r"(?i)localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org)|:password@|:pass@|:<[^>@]*>@|\$\{|\buser(?:name)?:(?:token|pass(?:word)?|secret|pat)@|:\*+@",
        ),
        message: "A connection string carries a username and password.",
        fix: ROTATE,
    },
    Rule {
        id: "secret.env-file",
        family: Family::Secret,
        severity: Severity::High,
        files: env_file,
        pattern: ENV_SECRET_LINE,
        unless: Some(ENV_PLACEHOLDER),
        message: "A .env file in the repository holds a secret value.",
        fix: "Revoke the value, remove the file from git (keep a .env.example without values) and add .env to .gitignore.",
    },
    Rule {
        id: "secret.env-example-value",
        family: Family::Secret,
        severity: Severity::High,
        files: env_example,
        pattern: ENV_SECRET_LINE,
        unless: Some(ENV_PLACEHOLDER),
        message: "An example env file holds what looks like a real secret value; example files are meant to be committed and shared.",
        fix: "Revoke the value, replace it with an empty value or a placeholder like your-key-here, and keep real values only in the ignored .env.",
    },
    Rule {
        id: "secret.public-env-secret",
        family: Family::Secret,
        severity: Severity::High,
        files: any_text,
        pattern: r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|VUE_APP|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|OPENAI|ANTHROPIC)[A-Z0-9_]*\b",
        unless: None,
        message: "A secret is given a public env prefix, so the build ships it inside the client bundle where anyone can read it.",
        fix: "Drop the public prefix and use the value only in server code (an API route or server action); the browser should call your server instead.",
    },
];

#[cfg(test)]
mod tests {
    use super::plausible_aws_secret;
    use crate::rules::{FileInfo, check};

    #[test]
    fn env_secret_line_does_not_cross_newlines() {
        let s = ["Fake0000", "Value0000", "Q7mZ"].concat();
        for (name, src) in [
            (".env.example", "API_KEY=\nNEXT_VAR=some_regular_value\n"),
            (".env", "API_SECRET=\nAPP_ENVIRONMENT=production\n"),
            (".env.example", "API_KEY=\n\nNEXT_VAR=some_regular_value\n"),
            (".env.example", "API_KEY=   \nNEXT_VAR=some_regular_value\n"),
            (
                ".env.example",
                "API_KEY=\r\nNEXT_VAR=some_regular_value\r\n",
            ),
            (".env", "API_SECRET=\r\nAPP_ENVIRONMENT=production\r\n"),
            (".env.example", "\nAPI_KEY=your-placeholder-key-here\n"),
            (".env.example", "\r\nAPI_KEY=your-placeholder-key-here\r\n"),
            (
                ".env.example",
                "export\nAPI_KEY=your-placeholder-key-here\n",
            ),
        ] {
            let found = check(&FileInfo::new(name), src, false);
            assert!(found.is_empty(), "{name} {src:?} => {found:#?}");
        }
        let (ex, ef) = ("secret.env-example-value", "secret.env-file");
        for (name, rule, src, line) in [
            (".env.example", ex, format!("\nAPI_KEY={s}\n"), 2),
            (".env.example", ex, format!("\r\nAPI_KEY={s}\r\n"), 2),
            (".env", ef, format!("\n  export API_KEY = {s}\n"), 2),
            (
                ".env",
                ef,
                format!("\n  export SECRET_KEY = \"{s}\"  \r\n"),
                2,
            ),
            (".env", ef, format!("API_KEY={s}  \r\n"), 1),
        ] {
            let found: Vec<_> = check(&FileInfo::new(name), &src, false)
                .into_iter()
                .filter(|f| f.rule == rule)
                .collect();
            assert_eq!(found.len(), 1, "{name} {src:?} => {found:#?}");
            assert_eq!(found[0].line, line);
            assert!(found[0].snippet.contains('=') && !found[0].snippet.contains(&s));
        }
    }

    #[test]
    fn env_secret_line_inline_comments() {
        let s = ["Fake0000", "Value0000", "Q7mZ"].concat();
        let with_hash = ["abc#def", "1234567890", "Q7mZ"].concat();
        let leading_hash = ["#abc1234", "567890defg", "Q7mZ"].concat();
        for (name, src) in [
            (
                ".env.example",
                "API_KEY=your-key-here # set me\n".to_string(),
            ),
            (
                ".env.example",
                "API_KEY=your-api-key-here # set me\n".to_string(),
            ),
            (
                ".env.example",
                "PASSWORD=**************** # masked\n".to_string(),
            ),
            (
                ".env.example",
                "PASSWORD=\"****************\" # masked\n".to_string(),
            ),
            (".env", "PASSWORD='****************'#masked\n".to_string()),
            (
                ".env",
                "API_KEY=$PROD_API_KEY_VALUE # from env\n".to_string(),
            ),
            (
                ".env.example",
                "API_KEY=#comment_longer_than_16_chars\n".to_string(),
            ),
            (
                ".env.example",
                "API_KEY= #comment_longer_than_16_chars\n".to_string(),
            ),
            (
                ".env",
                "API_KEY=short # very_long_comment_over_16_chars\n".to_string(),
            ),
            (".env", format!("SECRET_TOKEN=\"{s}' # mismatched\n")),
            (".env", format!("SECRET_TOKEN=\"{s} # unclosed\n")),
            (".env", format!("API_KEY={s} not a comment\n")),
            (".env", format!("# API_KEY={s} # commented out\n")),
        ] {
            let found = check(&FileInfo::new(name), &src, false);
            assert!(found.is_empty(), "{name} {src:?} => {found:#?}");
        }

        let (ex, ef) = ("secret.env-example-value", "secret.env-file");
        for (name, rule, src, want_snippet) in [
            (
                ".env.example",
                ex,
                format!("API_KEY={s} # prod key\n"),
                "API_KEY=Fake****",
            ),
            (
                ".env.example",
                ex,
                format!("SECRET_TOKEN=\"{s}\" # rotated monthly\n"),
                "SECRET_TOKEN=\"Fake****\"",
            ),
            (
                ".env",
                ef,
                format!("SECRET_TOKEN='{s}'#note\n"),
                "SECRET_TOKEN='Fake****'",
            ),
            (
                ".env",
                ef,
                format!("API_KEY={with_hash}\n"),
                "API_KEY=abc#****",
            ),
            (
                ".env.example",
                ex,
                format!("API_KEY={with_hash} # prod key\n"),
                "API_KEY=abc#****",
            ),
            (
                ".env",
                ef,
                format!("SECRET_TOKEN=\"{leading_hash}\" # note\n"),
                "SECRET_TOKEN=\"#abc****\"",
            ),
            (
                ".env",
                ef,
                format!("API_KEY={s}\t# tab comment\r\n"),
                "API_KEY=Fake****",
            ),
            (
                ".env.example",
                ex,
                format!("API_KEY={s} # replace with your own key\n"),
                "API_KEY=Fake****",
            ),
            (
                ".env.example",
                ex,
                format!("API_KEY={s} # e.g. API_KEY=your-key-here\n"),
                "API_KEY=Fake****",
            ),
            (
                ".env",
                ef,
                format!("SECRET_TOKEN=\"{s}\"#your-token\n"),
                "SECRET_TOKEN=\"Fake****\"",
            ),
            (
                ".env",
                ef,
                format!("API_KEY={s} # masked=****************\n"),
                "API_KEY=Fake****",
            ),
        ] {
            let found: Vec<_> = check(&FileInfo::new(name), &src, false)
                .into_iter()
                .filter(|f| f.rule == rule)
                .collect();
            assert_eq!(found.len(), 1, "{name} {src:?} => {found:#?}");
            assert_eq!(found[0].line, 1);
            assert_eq!(found[0].snippet, want_snippet, "{name} {src:?}");
            assert!(!found[0].snippet.contains(&s));
        }
    }

    #[test]
    fn aws_secret_value_check() {
        // Built from parts, like the fixtures, so the source holds no key-shaped literal.
        let random = ["Q7mZ2xK9pL4vR8tN3wB6", "yH1cF5jD0s/QmZxK+a3f"].concat();
        assert!(plausible_aws_secret(&random));
        let docs_key = ["wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY"].concat();
        let chunk = "Q7mZ2xK9pL4vR8tN".repeat(3)[..40].to_string();
        let lower = "q7mz2xk9pl4vr8tn3wb6yh1cf5jd0sg".repeat(2)[..40].to_string();
        let upper = lower.to_ascii_uppercase();
        // Each shape is turned down by one check only.
        let rejected = [
            ("no capital", lower),
            ("no small letter", upper),
            (
                "all hex",
                ["Da39A3eE5e6b4B0d", "3255bFeF95601890", "aFd80709"].concat(),
            ),
            ("example", docs_key),
            (
                "few distinct characters",
                ["9ZpBQm7m9aQ7xQmp", "pmxm7pQamxBBaQaa", "pQxQ7ZKp"].concat(),
            ),
            ("a repeated chunk", chunk),
            (
                "a run of the alphabet",
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN".to_string(),
            ),
            (
                "a path",
                "/Prod/East1/Payments/Stripe/Billing/Keys".to_string(),
            ),
            (
                "words",
                "AwsSecretAccessKeyParameterNameForProd12".to_string(),
            ),
        ];
        for (shape, value) in rejected {
            assert_eq!(value.len(), 40, "{shape}");
            assert!(!plausible_aws_secret(&value), "{shape}: {value}");
        }
    }

    #[test]
    fn hardcoded_password_placeholder_only_counts_in_its_own_value() {
        let v = ["Zq7Wd0000", "Kx9Fake"].concat();
        let src = format!(
            "connect(user=\"testuser\", password=\"{v}\")\nconnect(user=\"admin\", password=\"{v}\")\ncfg = {{\"env\": \"none\", \"password\": \"{v}\"}}\n"
        );
        let found: Vec<_> = check(&FileInfo::new("app.py"), &src, false)
            .into_iter()
            .filter(|f| f.rule == "secret.hardcoded-password")
            .collect();
        assert_eq!(found.len(), 3, "{src:?} => {found:#?}");
        assert_eq!(
            found.iter().map(|f| f.line).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        for src in [
            "password=\"changeme12345\"\n".to_string(),
            "password=\"test1234\"\n".to_string(),
            "password=\"your-password-here\"\n".to_string(),
            "password=\"<enter-password>\"\n".to_string(),
        ] {
            let found = check(&FileInfo::new("app.py"), &src, false);
            assert!(found.is_empty(), "{src:?} => {found:#?}");
        }
    }

    #[test]
    fn age_key_after_json_escape() {
        let bech32 = &"QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".repeat(2)[..58];
        let classic = ["AGE-SECRET-", "KEY-1", bech32].concat();
        let pq = ["AGE-SECRET-", "KEY-PQ-1", bech32].concat();
        let age = |src: &str| -> Vec<_> {
            check(&FileInfo::new("keys.json"), src, false)
                .into_iter()
                .filter(|f| f.rule == "secret.age-key")
                .collect()
        };
        for key in [&classic, &pq] {
            for src in [
                format!(r#"{{"key":"line\n{key}"}}"#),
                format!(r#"{{"key":"line\r\n{key}\n"}}"#),
                format!(r#"{{"key":"\t{key}"}}"#),
                format!("key = \"{key}\""),
            ] {
                let found = age(&src);
                assert_eq!(found.len(), 1, "{src} => {found:#?}");
                assert!(!found[0].snippet.contains(key), "{src} => {found:#?}");
            }
            for src in [
                format!("X{key}"),
                format!("{key}Q"),
                format!(r#""line\n{key}Q""#),
            ] {
                assert!(age(&src).is_empty(), "{src}");
            }
        }
        let recipient = format!("recipient = \"age1pq1{}\"", bech32.to_lowercase());
        assert!(age(&recipient).is_empty(), "{recipient}");
    }

    #[test]
    fn env_secret_line_pass_and_pwd_names() {
        let s = ["Fake0000", "Value0000", "Q7mZ"].concat();
        for name in [".env", ".env.example"] {
            for var in ["PASSPORT_ID", "BYPASS_CACHE", "COMPASS_URL"] {
                let src = format!("{var}={s}\n");
                assert!(check(&FileInfo::new(name), &src, false).is_empty(), "{var}");
            }
            for src in ["DB_PASS=your-pass-here\n", "MYSQL_PWD=your-pwd-here\n"] {
                assert!(check(&FileInfo::new(name), src, false).is_empty(), "{src}");
            }
        }
        for (name, rule) in [
            (".env", "secret.env-file"),
            (".env.example", "secret.env-example-value"),
        ] {
            for var in [
                "DB_PASS",
                "SMTP_PASS",
                "PASS_FILE",
                "MYSQL_PWD",
                "PASS",
                "PWD",
                "_PASS",
                "PWD_",
            ] {
                let src = format!("{var}={s}\n");
                let found: Vec<_> = check(&FileInfo::new(name), &src, false)
                    .into_iter()
                    .filter(|f| f.rule == rule)
                    .collect();
                assert_eq!(found.len(), 1, "{name} {src:?} => {found:#?}");
                assert_eq!(found[0].snippet, format!("{var}=Fake****"));
                assert!(!found[0].snippet.contains(&s));
            }
        }
    }

    #[test]
    fn env_secret_line_file_path_and_pwd_values() {
        let s = ["Fake0000", "Value0000", "Q7mZ"].concat();
        let slash_s = ["/", &s].concat();
        for name in [".env", ".env.example"] {
            for src in [
                "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password\n",
                "PRIVATE_KEY_PATH=./certs/server.key\n",
                "SECRET_KEY_DIR=../secrets/prod\n",
                "API_TOKEN_FILE=\"~/secrets/api_token\"\n",
                "PASS_FILE='/var/run/secrets/db_pass'\n",
                "PWD=/srv/app/releases/current\n",
            ] {
                assert!(check(&FileInfo::new(name), src, false).is_empty(), "{src}");
            }
        }
        for (name, rule) in [
            (".env", "secret.env-file"),
            (".env.example", "secret.env-example-value"),
        ] {
            for (var, val, masked) in [
                ("DB_PASSWORD_FILE", &s, "Fake****"),
                ("PWD", &s, "Fake****"),
                ("DB_PASSWORD", &slash_s, "/Fak****"),
            ] {
                let src = format!("{var}={val}\n");
                let found: Vec<_> = check(&FileInfo::new(name), &src, false)
                    .into_iter()
                    .filter(|f| f.rule == rule)
                    .collect();
                assert_eq!(found.len(), 1, "{name} {src:?} => {found:#?}");
                assert_eq!(found[0].snippet, format!("{var}={masked}"));
                assert!(!found[0].snippet.contains(&s));
            }
        }
    }
}
