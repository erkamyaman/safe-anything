use std::path::Path;

use super::{FileInfo, Meta, Rule, Text, finding};
use crate::{Family, Finding, Severity};

pub const NAME_ONLY: &[&str] = &["secret.public-env-secret"];

pub const ENV_NOT_IGNORED: (&str, Severity, &str) = (
    "secret.env-not-ignored",
    Severity::Medium,
    "The project has env files but .gitignore does not exclude .env, so real secrets are one git add away from the repository.",
);

pub fn is_env(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.")
}

pub fn env_not_ignored(root: &Path, env_files: &[String]) -> Option<Finding> {
    if env_files.is_empty() {
        return None;
    }
    let src = std::fs::read_to_string(root.join(".gitignore")).ok()?;
    let covered = src.lines().map(str::trim).any(|l| {
        let l = l.trim_start_matches("**/").trim_start_matches('/');
        l.starts_with(".env") || l.starts_with("*.env")
    });
    if covered {
        return None;
    }
    let text = Text::new(&src);
    if text.suppressed(1) {
        return None;
    }
    let (id, severity, message) = ENV_NOT_IGNORED;
    Some(finding(
        &FileInfo::new(".gitignore"),
        &text,
        1,
        Meta {
            id,
            family: Family::Secret,
            severity,
            message,
            fix: "Add .env and .env.* to .gitignore, with !.env.example so the example file stays tracked.",
            secret: None,
        },
    ))
}

fn any_text(_: &FileInfo) -> bool {
    true
}

fn env_file(f: &FileInfo) -> bool {
    is_env(&f.name)
        && !["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|s| f.name.ends_with(s))
}

fn env_example(f: &FileInfo) -> bool {
    is_env(&f.name)
        && ["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|s| f.name.ends_with(s))
}

const ENV_SECRET_LINE: &str = r#"(?m)^\s*(?:export\s+)?[A-Za-z0-9_]*(?i:secret|token|password|passwd|api_?key|private_?key|access_?key|auth|credential)[A-Za-z0-9_]*\s*=\s*["']?([A-Za-z0-9+/_.\-]{16,})["']?\s*$"#;

const ENV_PLACEHOLDER: &str = r"^\s*(?:export\s+)?(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|VUE_APP|PUBLIC)_|(?i)=\s*[\x22']?(?:\S*(?:your|example|change|replace|placeholder|dummy|xxxx|\.\.\.|<)|sk_test_|pk_test_|(?-i:[a-z]+[-_][a-z]+[-_][a-z]+))";

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
    secret!(
        "secret.github-token",
        Critical,
        r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})",
        "A GitHub token is written in the file."
    ),
    secret!(
        "secret.gitlab-token",
        Critical,
        r"\bglpat-[0-9a-zA-Z_\-]{20}",
        "A GitLab personal access token is written in the file."
    ),
    secret!(
        "secret.slack-token",
        High,
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
        "A Slack token is written in the file."
    ),
    secret!(
        "secret.stripe-live-key",
        Critical,
        r"\b[sr]k_live_[A-Za-z0-9]{24,}",
        "A live Stripe secret key is written in the file."
    ),
    secret!(
        "secret.npm-token",
        Critical,
        r"\bnpm_[A-Za-z0-9]{36}\b",
        "An npm access token is written in the file."
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
        "secret.google-api-key",
        High,
        r"\bAIza[0-9A-Za-z_\-]{35}",
        "A Google API key is written in the file."
    ),
    secret!(
        "secret.private-key",
        Critical,
        r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----\r?\n([A-Za-z0-9+/=]{20,})",
        "A private key is stored in the repository."
    ),
    Rule {
        id: "secret.hardcoded-password",
        family: Family::Secret,
        severity: Severity::High,
        files: any_text,
        pattern: r#"(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token|client_?secret)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']"#,
        unless: Some(
            r#"(?i)[:=]\s*["'][^"']*(?:\.\.\.|…)|[:=]\s*["'](\$|changeme|password|secret|example|x{3,}|your[-_]|<|\$\{|\{\{|%\(|dummy|test|placeholder|redacted|\*{3,}|none|null)"#,
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
