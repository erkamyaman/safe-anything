use std::collections::HashMap;

use serde_json::Value;

use super::{FileInfo, Meta, Rule, Text, finding};
use crate::{Family, Finding, Severity};

pub fn is_mcp_config(f: &FileInfo) -> bool {
    f.name == ".mcp.json"
        || f.name == "mcp.json"
        || f.name == "claude_desktop_config.json"
        || f.name == "opencode.json"
        || f.name == "opencode.jsonc"
        // Windsurf and Cline.
        || f.name == "mcp_config.json"
        || f.name == "cline_mcp_settings.json"
        || (f.name.starts_with("settings")
            && f.ext == "json"
            && (f.under(".gemini/") || f.under(".claude/")))
        // Zed: `.zed/settings.json` in a project, `.config/zed/settings.json` in a home folder.
        || ends_with_path(f, ".zed/settings.json")
        || ends_with_path(f, ".config/zed/settings.json")
}

/// Whether the file is `tail` itself or `tail` inside some folder, matched by whole folder names.
fn ends_with_path(f: &FileInfo, tail: &str) -> bool {
    f.rel
        .strip_suffix(tail)
        .is_some_and(|head| head.is_empty() || head.ends_with('/'))
}

fn claude_settings(f: &FileInfo) -> bool {
    f.under(".claude/") && f.name.starts_with("settings") && f.ext == "json"
}

pub fn is_agent_file(f: &FileInfo) -> bool {
    is_mcp_config(f)
        || matches!(
            f.name.as_str(),
            "skill.md"
                | "claude.md"
                | "agents.md"
                | "gemini.md"
                | ".cursorrules"
                | ".windsurfrules"
                | "copilot-instructions.md"
        )
        || (f.under(".codex/") && f.ext == "toml")
        || f.under(".claude/commands/")
        || f.under(".claude/agents/")
        || f.under(".claude/skills/")
        || f.under(".claude/hooks/")
        || f.under(".cursor/rules/")
        || f.under(".gemini/commands/")
        // Cline reads `.clinerules` as one file or as a folder of rule files.
        || f.name == ".clinerules"
        || f.under(".clinerules/")
        || f.under(".windsurf/rules/")
        || (f.under(".github/instructions/") && f.name.ends_with(".instructions.md"))
        || (f.under(".github/prompts/") && f.name.ends_with(".prompt.md"))
        || f.under(".roo/rules/")
        || f.under(".kiro/steering/")
}

macro_rules! rule {
    ($id:literal, $sev:ident, $files:ident, $pat:literal, $unless:expr, $msg:literal, $fix:literal) => {
        Rule {
            id: $id,
            family: Family::Agent,
            severity: Severity::$sev,
            files: $files,
            pattern: $pat,
            unless: $unless,
            message: $msg,
            fix: $fix,
        }
    };
}

pub static RULES: &[Rule] = &[
    rule!(
        "agent.bypass-permissions",
        High,
        is_agent_file,
        r#""defaultMode"\s*:\s*"bypassPermissions"|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|sandbox_mode\s*=\s*"danger-full-access"|--yolo\b"#,
        None,
        "The agent is set to run every action without asking, so one bad instruction can do anything on this machine.",
        "Use the default or an accept-edits mode and allow specific commands instead of skipping all approvals."
    ),
    rule!(
        "agent.mcp-auto-approve",
        High,
        claude_settings,
        r#""enableAllProjectMcpServers"\s*:\s*true\b"#,
        None,
        "Claude Code starts every MCP server in the project's .mcp.json without asking about each one, so a cloned repository's servers can run commands on this machine.",
        "Remove it and approve project MCP servers one by one, or list the trusted ones in \"enabledMcpjsonServers\"."
    ),
    rule!(
        "agent.remote-script",
        High,
        is_agent_file,
        r#"\b(?:curl|wget)\b[^|\n]*?(?:https?://|\$\{?\w)[^|\n]*\|\s*(?:sudo\s+(?:(?:-[AbBEeHiKklnPSsVv]*[ugCDhprtTU]|--(?:user|group|chdir|host|prompt|role|type|other-user|close-from|command-timeout))\s+(?:"[^"\n]*"|'[^'\n]*'|\\"[^"\n]*?\\"|[\w.$/~][\w.${}/~-]*)\s+|-[AbBEeHiKklnPSsVv]*[ugCDhprtTU](?:"[^"\n]*"|'[^'\n]*'|\\"[^"\n]*?\\"|[^\s;|&`<>()"']+)\s+|-[AbBEeHiKklnPSsVv]+\s+|--[\w-]+=\S*\s+|--(?:preserve-env|login|shell|non-interactive|background|stdin|set-home|preserve-groups|askpass|bell|reset-timestamp|remove-timestamp)\s+)*(?:--\s+)?)?(?:sh|bash|zsh|python3?|node)\b|\b(?:ba|z|da|k)?sh\s+(?:[-+]o\s+[\w-]+\s+|-[A-Za-z]+\s+)*?-[A-Za-z]*c[A-Za-z]*\s+\\?["']?(?:\$\(|`)\s*(?:curl|wget)\b(?:[^()`\n]|\([^()`\n]*\))*?(?:https?://|\$\{?\w)"#,
        None,
        "A script is downloaded and run straight from the internet; whoever controls that URL controls this machine.",
        "Download, review and pin the script (or a checksum), or install the tool from a package manager."
    ),
    rule!(
        "agent.prompt-injection",
        Medium,
        is_agent_file,
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|directions|prompts?)|\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|alert)\s+the\s+user|\bwithout\s+(?:telling|asking|informing|notifying)\s+the\s+user|\bexfiltrat",
        Some(
            r#"(?i)["“'‘(]\s*(?:ignore|disregard|forget)|\b(?:never|don't|do not|must not|should not|shouldn't|not)\b[^.]{0,80}\bwithout\s+(?:asking|telling|informing|notifying)|\b(?:must not|never|do not|don't)\s+(?:contain|follow|obey|act on|comply)|\b(?:malware|injection|attack|malicious|treat\b[^.]*\bas data)"#
        ),
        "Instruction text tells the agent to override its rules or hide actions from the user (prompt injection).",
        "Remove the text, and do not install skills or rules from sources you have not read."
    ),
    rule!(
        "agent.sensitive-file-access",
        High,
        is_agent_file,
        r"~/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|\.git-credentials|/etc/shadow|\bLogin Data\b|security\s+find-(?:generic|internet)-password",
        None,
        "Agent instructions read credential files such as SSH keys or cloud credentials.",
        "Remove the step; an agent never needs your private keys or credential stores."
    ),
    rule!(
        "agent.hidden-unicode",
        High,
        is_agent_file,
        r"[\x{E0000}-\x{E007F}\x{200B}\x{200C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]",
        None,
        "Invisible Unicode characters are in agent instructions; they can hide text the agent reads but you don't see.",
        "Delete the invisible characters and review what they spelled out."
    ),
];

/// Rules found by reading the config's structure. A finding writes its own message (and, for a
/// secret in `headers`, its own fix); these are the general texts for `--list-rules` and the
/// SARIF rule help.
pub static STRUCTURED: &[(&str, Severity, &str, &str)] = &[
    (
        "agent.unrestricted-shell",
        Severity::High,
        "Every shell command is pre-approved, so the agent can run anything without asking.",
        SHELL_FIX,
    ),
    (
        "agent.mcp-unpinned",
        Severity::Medium,
        "An MCP server is started from a package or image with no pinned version.",
        UNPINNED_FIX,
    ),
    (
        "agent.mcp-plaintext-secret",
        Severity::High,
        "An MCP server's token or key is written in plain text in the config.",
        PLAINTEXT_FIX,
    ),
    (
        "agent.mcp-insecure-url",
        Severity::High,
        "A remote MCP server is reached over plain HTTP.",
        INSECURE_URL_FIX,
    ),
];

const SHELL_FIX: &str = "Allow specific commands, for example \"Bash(npm test:*)\".";
const UNPINNED_FIX: &str =
    "Pin an exact version (pkg@1.2.3, pkg==1.2.3, or an image digest) and update on purpose.";
const PLAINTEXT_FIX: &str = "Reference an environment variable (\"${VAR}\") and keep the value out of files that get shared or committed.";
const INSECURE_URL_FIX: &str = "Use https:// for every MCP server that is not on this machine.";

pub fn structured(file: &FileInfo, text: &Text) -> Vec<Finding> {
    if !is_mcp_config(file) {
        return Vec::new();
    }
    let Ok(json) = serde_json::from_str::<Value>(&strip_jsonc(text.src)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in ["mcpServers", "servers", "mcp", "context_servers"] {
        let Some(servers) = json.get(key).and_then(Value::as_object) else {
            continue;
        };
        let positions = root_object(text.src)
            .and_then(|root| object_keys(text.src, root).get(key).copied())
            .and_then(|at| value_object(text.src, at))
            .map(|at| object_keys(text.src, at))
            .unwrap_or_default();
        for (name, server) in servers {
            let start = positions
                .get(name.as_str())
                .copied()
                .or_else(|| text.src.find(&format!("\"{name}\"")))
                .unwrap_or(0);
            check_server(file, text, start, server, &mut out);
        }
    }
    if claude_settings(file) {
        check_claude_permissions(file, text, &json, &mut out);
    }
    out
}

fn check_claude_permissions(file: &FileInfo, text: &Text, json: &Value, out: &mut Vec<Finding>) {
    let Some(allow) = json
        .get("permissions")
        .and_then(|p| p.get("allow"))
        .and_then(Value::as_array)
    else {
        return;
    };
    let perms_start = find_json_key(text.src, 0, "permissions").unwrap_or(0);
    let mut cursor = find_json_key(text.src, perms_start, "allow").unwrap_or(perms_start);
    for entry in allow.iter().filter_map(Value::as_str) {
        if matches!(entry, "Bash" | "Bash(*)" | "Bash(:*)") {
            let needle = format!("\"{entry}\"");
            let at = match text.src[cursor..].find(&needle) {
                Some(i) => {
                    let pos = cursor + i;
                    cursor = pos + needle.len();
                    pos
                }
                None => cursor,
            };
            out.push(finding(
                file,
                text,
                text.line_of(at),
                Meta {
                    id: "agent.unrestricted-shell",
                    family: Family::Agent,
                    severity: Severity::High,
                    message: "Every shell command is pre-approved, so the agent can run anything without asking.",
                    fix: SHELL_FIX,
                    secret: None,
                },
            ));
        }
    }
}

fn find_json_key(src: &str, start: usize, key: &str) -> Option<usize> {
    let quoted = format!("\"{key}\"");
    let mut pos = start;
    while let Some(i) = src[pos..].find(&quoted) {
        let key_pos = pos + i;
        let after = key_pos + quoted.len();
        if src[after..].trim_start().starts_with(':') {
            return Some(key_pos);
        }
        pos = after;
    }
    None
}

fn check_server(
    file: &FileInfo,
    text: &Text,
    start: usize,
    server: &Value,
    out: &mut Vec<Finding>,
) {
    let mut argv: Vec<String> = Vec::new();
    match server.get("command") {
        Some(Value::String(c)) => argv.push(c.clone()),
        Some(Value::Array(a)) => argv.extend(a.iter().filter_map(|v| v.as_str().map(String::from))),
        _ => {}
    }
    if let Some(Value::Array(a)) = server.get("args") {
        argv.extend(a.iter().filter_map(|v| v.as_str().map(String::from)));
    }
    if let Some(spec) = unpinned(&argv) {
        let line = line_after(text, start, &format!("\"{spec}\""));
        out.push(finding(
            file,
            text,
            line,
            Meta {
                id: "agent.mcp-unpinned",
                family: Family::Agent,
                severity: Severity::Medium,
                message: &format!("The MCP server runs `{spec}` without a pinned version, so every start installs whatever was published last."),
                fix: UNPINNED_FIX,
                secret: None,
            },
        ));
    }
    // Local servers get credentials in `env`; remote ones in `headers` (`http_headers` is Codex's
    // name for it).
    for (field, header) in [
        ("env", false),
        ("environment", false),
        ("headers", true),
        ("http_headers", true),
    ] {
        let Some(values) = server.get(field).and_then(Value::as_object) else {
            continue;
        };
        // Find each key inside its own object, so the same name in `args`, in `env` or as a value
        // does not take its line.
        let field_keys = value_object(text.src, start)
            .and_then(|at| object_keys(text.src, at).get(field).copied())
            .and_then(|at| value_object(text.src, at))
            .map(|at| object_keys(text.src, at))
            .unwrap_or_default();
        for (k, v) in values {
            let Some(v) = v.as_str() else { continue };
            // `Authorization` and `Proxy-Authorization` are credential words in `secret_like_key`.
            if secret_like_key(k) && !references_variable(v) {
                let line = field_keys.get(k.as_str()).map_or_else(
                    || line_after(text, start, &format!("\"{k}\"")),
                    |&at| text.line_of(at),
                );
                let (message, fix) = if header {
                    (
                        format!(
                            "The MCP server's {k} header is written in plain text in the config."
                        ),
                        "Reference an environment variable (\"${VAR}\", or \"Bearer ${VAR}\" for Authorization) and keep the value out of files that get shared or committed.",
                    )
                } else {
                    (
                        format!("The MCP server's {k} is written in plain text in the config."),
                        PLAINTEXT_FIX,
                    )
                };
                out.push(finding(
                    file,
                    text,
                    line,
                    Meta {
                        id: "agent.mcp-plaintext-secret",
                        family: Family::Agent,
                        severity: Severity::High,
                        message: &message,
                        fix,
                        secret: Some(v),
                    },
                ));
            }
        }
    }
    if let Some(url) = server
        .get("url")
        .or_else(|| server.get("serverUrl"))
        .and_then(Value::as_str)
        && let Some(rest) = url
            .get(..7)
            .filter(|prefix| prefix.eq_ignore_ascii_case("http://"))
            .map(|_| &url[7..])
    {
        let host = match rest.find(']') {
            Some(end) if rest.starts_with('[') => &rest[..end + 1],
            _ => rest.split(['/', ':']).next().unwrap_or(""),
        };
        if !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
            let line = line_after(text, start, url);
            out.push(finding(
            file,
            text,
            line,
            Meta {
                id: "agent.mcp-insecure-url",
                family: Family::Agent,
                severity: Severity::High,
                message: "A remote MCP server is reached over plain HTTP, so its tools and your data can be read or changed on the way.",
                fix: INSECURE_URL_FIX,
                secret: None,
            },
        ));
        }
    }
}

/// Whether a value points at a credential kept elsewhere instead of holding one. After the auth
/// scheme (`Bearer`, `Basic`, ...): it starts with `$` or `<`, or what is left once every
/// `${VAR}` and `{env:VAR}` is taken out is shorter than 8 characters. So `Bearer ${TOKEN}`,
/// `user:${PASSWORD}` and `<your token>` are skipped, and `admin:hunter2hunter2@${DB_HOST}` and
/// `${TOKEN:-sk_live_default}` (a real default) are not.
fn references_variable(value: &str) -> bool {
    const SCHEMES: &[&str] = &[
        "bearer", "basic", "token", "bot", "digest", "apikey", "oauth",
    ];
    let bare = value
        .split_once(char::is_whitespace)
        .filter(|(scheme, _)| SCHEMES.iter().any(|s| scheme.eq_ignore_ascii_case(s)))
        .map_or(value, |(_, rest)| rest.trim_start());
    // A value that starts with a variable is taken from the environment (`$TOKEN`,
    // `${HOME}/key.json`), unless its default is a value of its own (`${TOKEN:-sk_live_...}`).
    let has_default = bare
        .strip_prefix("${")
        .and_then(|r| r.split_once('}'))
        .and_then(|(inner, _)| inner.split_once(":-"))
        .is_some_and(|(_, default)| !references_variable(default));
    if bare.starts_with('<') || value.starts_with('<') || (bare.starts_with('$') && !has_default) {
        return true;
    }
    without_variables(bare).len() < 8
}

/// The value with each `${VAR}`, `${env:VAR}`, `${input:VAR}` and `{env:VAR}` taken out. A
/// `${VAR:-default}` leaves its default, which may be a real value.
fn without_variables(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(i) = rest.find(['$', '{']) {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        let inner = after
            .strip_prefix("${")
            .or_else(|| after.strip_prefix("{env:"))
            .and_then(|r| r.find('}').map(|end| (&r[..end], &r[end + 1..])));
        match inner {
            Some((inner, tail)) => {
                let (name, default) = inner.split_once(":-").unwrap_or((inner, ""));
                if is_variable_name(name) {
                    out.push_str(default);
                } else {
                    out.push_str(&after[..after.len() - tail.len()]);
                }
                rest = tail;
            }
            // No `}` follows, so no later `${` closes either: keep the rest as it is. This also
            // keeps the scan linear on a value full of unclosed `${`.
            None if after.starts_with("${") || after.starts_with("{env:") => {
                rest = after;
                break;
            }
            None => {
                out.push_str(&after[..1]);
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `API_TOKEN`, or `env:API_TOKEN` / `input:api-token` (VS Code ids may hold `-` and `.`). A plain
/// name is a shell name, so `${TOKEN-realvalue}` is not taken for one.
fn is_variable_name(name: &str) -> bool {
    let (name, extra): (&str, &[char]) = match name
        .strip_prefix("env:")
        .or_else(|| name.strip_prefix("input:"))
    {
        Some(id) => (id, &['_', '-', '.']),
        None => (name, &['_']),
    };
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

/// Whether an env key names a credential. Each part of the key (split at every character that
/// is not a letter or digit) is searched for the credential words, as before, except where the
/// word only shows up as part of an ordinary one: a part that starts with `monkey`, `keyboard`
/// or `author`, and `pat` in `path`, `patch` or `compat`. A camelCase word of its own always
/// counts. So `PATH`, `DISPATCH_MODE`, `AUTHOR` and `MONKEY_PATCH` don't count, and
/// `daemonKey`, `patHash`, `GITHUB_PAT` and `PATv2` do.
fn secret_like_key(key: &str) -> bool {
    // Found anywhere in a part, as on main: these don't hide inside ordinary words.
    const ANYWHERE: &[&str] = &["token", "secret", "password", "credential"];
    // Ordinary words that start a part and contain `key` or `auth`. Only taken out at the start,
    // so `snapshotKey` and `apiKeyChain` still count.
    const NOT_KEY: &[&str] = &[
        "monkey",
        "donkey",
        "turkey",
        "hockey",
        "jockey",
        "whiskey",
        "lackey",
        "latchkey",
        "keychain",
        "keyboard",
        "keynote",
        "keyword",
        "keystroke",
    ];
    const NOT_AUTH: &[&str] = &["authority", "authorities", "authors", "author"];
    let after_word = |part: &str, words: &[&str]| -> String {
        let rest = words
            .iter()
            .find_map(|w| part.strip_prefix(w))
            .unwrap_or(part);
        rest.to_string()
    };
    key.split(|c: char| !c.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .any(|original| {
            let part = original.to_lowercase();
            let part = part.as_str();
            // `hotKey`, `patHash`, `gitlabComPat`: a camelCase word that is the credential word.
            let camel = camel_words(original);
            camel.iter().any(|w| {
                let w = w.strip_suffix('s').unwrap_or(w);
                matches!(w, "key" | "pat" | "auth")
            }) || ANYWHERE.iter().any(|w| part.contains(w))
                || after_word(part, NOT_KEY).contains("key")
                // `authorization` and `authentication` start like `author` but are credentials.
                || ["authoriz", "authoris", "authent"]
                    .iter()
                    .any(|w| part.contains(w))
                || after_word(part, NOT_AUTH).contains("auth")
                || pat_word(part)
        })
}

/// The lower-case words of a camelCase part: `githubPatHash` gives `github`, `pat`, `hash`. A
/// part with no lower-to-upper change (`GITHUBPAT`, `pythonpath`) is one word.
fn camel_words(part: &str) -> Vec<String> {
    let mut words = vec![String::new()];
    let mut prev_lower = false;
    for c in part.chars() {
        if c.is_uppercase() && prev_lower {
            words.push(String::new());
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        words.last_mut().unwrap().extend(c.to_lowercase());
    }
    words
}

/// Whether a lower-case part has `pat` other than inside `path`, `patch`, `pattern`, `patient`,
/// `patron`, `patio`, `patent`, `spatial`, `spatula` or `compat`.
fn pat_word(part: &str) -> bool {
    const NOT_AFTER: &[&str] = &["h", "ch", "tern", "ien", "ron", "io", "ent", "ial", "ula"];
    part.match_indices("pat").any(|(i, _)| {
        let after = &part[i + 3..];
        !part[..i].ends_with("com") && !NOT_AFTER.iter().any(|w| after.starts_with(w))
    })
}

/// Flags of `uvx` (`uv tool run`) and `pipx run` whose value is the next argument, so it is not
/// taken for the package.
const PYTHON_RUNNER_VALUE_FLAGS: &[&str] = &[
    "-p",
    "--python",
    "--with-editable",
    "--with-requirements",
    "-c",
    "--constraints",
    "--overrides",
    "--index",
    "--default-index",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--env-file",
    "--directory",
    "--project",
    "--cache-dir",
    "--config-file",
    "--pip-args",
];

/// Flags of `docker run` and `podman run` whose value is the next argument, so it is not taken for
/// the image.
const CONTAINER_RUN_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--env",
    "--env-file",
    "-v",
    "--volume",
    "--mount",
    "-p",
    "--publish",
    "--name",
    "--network",
    "--net",
    "-w",
    "--workdir",
    "-u",
    "--user",
    "--entrypoint",
    "--platform",
    "-h",
    "--hostname",
    "-l",
    "--label",
    "--add-host",
    "-m",
    "--memory",
    "--cpus",
    "--pull",
    "--restart",
    "--cap-add",
    "--cap-drop",
    "--device",
    "--security-opt",
    "--tmpfs",
    "--gpus",
];

/// The first argument that is not a flag, not the value of one of `value_flags`, not empty and not
/// one of `skip`.
fn first_operand<'a>(
    args: &'a [String],
    value_flags: &[&str],
    skip: &[&str],
) -> Option<&'a String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a.starts_with('-') {
            if value_flags.contains(&a.as_str()) {
                it.next();
            }
        } else if !a.is_empty() && !skip.contains(&a.as_str()) {
            return Some(a);
        }
    }
    None
}

fn unpinned(argv: &[String]) -> Option<String> {
    let cmd = argv.first()?;
    let base = cmd
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(cmd)
        .trim_end_matches(".cmd")
        .trim_end_matches(".exe");
    let rest = &argv[1..];
    match base {
        "npx" | "bunx" | "pnpx" => {
            let pkg = first_operand(rest, &[], &[])?.clone();
            (!npm_pinned(&pkg)).then_some(pkg)
        }
        "pnpm" | "yarn" | "bun"
            if rest.first().map(String::as_str) == Some("dlx")
                || rest.first().map(String::as_str) == Some("x") =>
        {
            let pkg = first_operand(&rest[1..], &[], &[])?.clone();
            (!npm_pinned(&pkg)).then_some(pkg)
        }
        "uvx" | "pipx" => {
            let pkg = match rest.iter().position(|a| a == "--from") {
                Some(i) => rest.get(i + 1).cloned()?,
                None => first_operand(rest, PYTHON_RUNNER_VALUE_FLAGS, &["run"])?.clone(),
            };
            (!(pkg.contains("==")
                || pkg.contains('@')
                || pkg.starts_with('.')
                || pkg.starts_with('/')))
            .then_some(pkg)
        }
        "docker" | "podman" => {
            let i = rest.iter().position(|a| a == "run")?;
            let image = first_operand(&rest[i + 1..], CONTAINER_RUN_VALUE_FLAGS, &[])?.clone();
            let last = image.rsplit('/').next().unwrap_or(&image);
            let pinned =
                image.contains("@sha256:") || (last.contains(':') && !last.ends_with(":latest"));
            (!pinned).then_some(image)
        }
        _ => None,
    }
}

fn npm_pinned(pkg: &str) -> bool {
    if pkg.starts_with('.') || pkg.starts_with('/') {
        return true;
    }
    // The first character is skipped so the `@` of a scope is not taken for a version.
    let Some((start, _)) = pkg.char_indices().nth(1) else {
        return false;
    };
    match pkg[start..].rfind('@') {
        Some(i) => {
            let v = &pkg[start + i + 1..];
            !v.is_empty() && v != "latest" && v.chars().next().is_some_and(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// The offset of each key of the object whose `{` is at `open` (the first one if a key repeats),
/// skipping nested values, strings and comments. One pass, so looking up every server or every
/// key of a large object stays linear.
fn object_keys(src: &str, open: usize) -> HashMap<&str, usize> {
    let b = src.as_bytes();
    let mut keys = HashMap::new();
    let mut i = open + 1;
    let mut depth = 1usize;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let Some(end) = string_end(b, i) else { break };
                if depth == 1 && b[skip_blank(b, end + 1)..].first() == Some(&b':') {
                    keys.entry(&src[i + 1..end]).or_insert(i);
                }
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                i = src[i..].find('\n').map_or(b.len(), |n| i + n);
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i = src[i + 2..].find("*/").map_or(b.len(), |n| i + 3 + n);
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    keys
}

/// The offset of the `{` that opens the file's top-level object, after any blank space and
/// comments.
fn root_object(src: &str) -> Option<usize> {
    let b = src.as_bytes();
    let mut i = 0;
    loop {
        i = skip_blank(b, i);
        if b[i..].starts_with(b"//") {
            i = src[i..].find('\n').map_or(b.len(), |n| i + n);
        } else if b[i..].starts_with(b"/*") {
            i = src[i + 2..].find("*/").map_or(b.len(), |n| i + 4 + n);
        } else {
            return (b.get(i) == Some(&b'{')).then_some(i);
        }
    }
}

/// The offset of the `{` that starts the value of the key at `key_at`, if it is an object.
fn value_object(src: &str, key_at: usize) -> Option<usize> {
    let b = src.as_bytes();
    let colon = skip_blank(b, string_end(b, key_at)? + 1);
    (b.get(colon) == Some(&b':')).then_some(())?;
    let open = skip_blank(b, colon + 1);
    (b.get(open) == Some(&b'{')).then_some(open)
}

fn string_end(b: &[u8], open: usize) -> Option<usize> {
    let mut i = open + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn skip_blank(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn line_after(text: &Text, start: usize, needle: &str) -> usize {
    let at = text.src[start..]
        .find(needle)
        .map(|i| start + i)
        .unwrap_or(start);
    text.line_of(at)
}

fn strip_jsonc(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            out.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            for n in chars.by_ref() {
                if n == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut prev = ' ';
            for n in chars.by_ref() {
                if n == '\n' {
                    out.push('\n');
                }
                if prev == '*' && n == '/' {
                    break;
                }
                prev = n;
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs every case and lists all that differ, as `argv: got X, want Y`.
    fn check_unpinned(cases: &[(&[&str], Option<&str>)]) {
        let wrong: Vec<String> = cases
            .iter()
            .filter_map(|(argv, want)| {
                let argv_owned: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
                let got = unpinned(&argv_owned);
                (got.as_deref() != *want).then(|| format!("{argv:?}: got {got:?}, want {want:?}"))
            })
            .collect();
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn unpinned_reads_npm_runners() {
        let cases: &[(&[&str], Option<&str>)] = &[
            (
                &["npx", "-y", "@modelcontextprotocol/server-github"],
                Some("@modelcontextprotocol/server-github"),
            ),
            (&["npx", "-y", "@scope/pkg@1.2.3"], None),
            (&["npx", "pkg"], Some("pkg")),
            (&["npx", "pkg@1.2.3", "--port", "3000"], None),
            (&["npx", "pkg@latest"], Some("pkg@latest")),
            (&["npx", "pkg@^1.2.0"], Some("pkg@^1.2.0")),
            (&["npx", "pkg@~1.2.0"], Some("pkg@~1.2.0")),
            (&["npx", "pkg@next"], Some("pkg@next")),
            (&["npx", "@scope/pkg@latest"], Some("@scope/pkg@latest")),
            (&["npx", "--yes", "--", "pkg@2.0.0"], None),
            (&["npx", "./tools/server.js"], None),
            (&["npx", "/opt/tools/server"], None),
            (&["npx"], None),
            (&["npx", ""], None),
            (&["npx", "é@1.0.0"], None),
            (&["npx", "é"], Some("é")),
            (&["bunx", "pkg"], Some("pkg")),
            (&["pnpx", "pkg@1.0.0"], None),
            (&["/usr/local/bin/npx", "pkg"], Some("pkg")),
            (&[r"C:\Program Files\nodejs\npx.cmd", "pkg"], Some("pkg")),
            (&["npx.exe", "pkg@1.0.0"], None),
            (&["pnpm", "dlx", "pkg"], Some("pkg")),
            (&["pnpm", "dlx", "-s", "@scope/pkg@1.0.0"], None),
            (&["pnpm", "dlx", ""], None),
            (&["pnpm", "dlx"], None),
            (&["yarn", "dlx", "pkg"], Some("pkg")),
            (&["bun", "x", "pkg"], Some("pkg")),
            (&["bun", "x", "pkg@1.0.0"], None),
            // Not a one-off runner.
            (&["pnpm", "install", "pkg"], None),
            (&["bun", "run", "server.ts"], None),
            (&["node", "server.js"], None),
            (&[], None),
            (&[""], None),
        ];
        check_unpinned(cases);
    }

    #[test]
    fn unpinned_reads_python_runners() {
        let cases: &[(&[&str], Option<&str>)] = &[
            (&["uvx", "mcp-server-fetch"], Some("mcp-server-fetch")),
            (&["uvx", "mcp-server-fetch==2025.4.7"], None),
            (&["uvx", "mcp-server-fetch@2025.4.7"], None),
            (&["uvx", "pkg>=1.0"], Some("pkg>=1.0")),
            (&["uvx", "pkg[extra]==1.0"], None),
            (&["uvx", "--from", "pkg==1.0", "cmd"], None),
            (&["uvx", "--from", "pkg", "cmd"], Some("pkg")),
            (&["uvx", "--from", "./local", "cmd"], None),
            (&["uvx", "--from", "/opt/tools/pkg", "cmd"], None),
            (&["uvx", "--from"], None),
            (&["uvx", "--python", "3.12", "pkg==1.0"], None),
            (&["uvx", "-p", "3.12", "pkg"], Some("pkg")),
            (&["uvx", "--python=3.12", "pkg"], Some("pkg")),
            // `--with` is not read yet: its value is taken for the package, as on main, so an
            // unpinned extra package is still reported (and a pinned one hides the main package).
            (&["uvx", "--with", "httpx", "pkg==1.0"], Some("httpx")),
            (
                &[
                    "uvx",
                    "--index-url",
                    "https://pypi.example/simple",
                    "pkg==1.0",
                ],
                None,
            ),
            (&["uvx", ""], None),
            (&["uvx"], None),
            (&["uvx.exe", "pkg"], Some("pkg")),
            (&["pipx", "run", "pkg"], Some("pkg")),
            (&["pipx", "run", "pkg==1.0"], None),
            (&["pipx", "run", "--python", "3.12", "pkg==1.0"], None),
            (&["pipx", "run", "--spec", "pkg==1.0", "cmd"], None),
        ];
        check_unpinned(cases);
    }

    #[test]
    fn unpinned_reads_container_runners() {
        let cases: &[(&[&str], Option<&str>)] = &[
            (
                &["docker", "run", "-i", "--rm", "acme/mcp"],
                Some("acme/mcp"),
            ),
            (&["docker", "run", "acme/mcp:1.0"], None),
            (&["docker", "run", "--net", "host", "acme/mcp:1.0"], None),
            (
                &["docker", "run", "acme/mcp:latest"],
                Some("acme/mcp:latest"),
            ),
            (&["docker", "run", "acme/mcp@sha256:0123abcd"], None),
            (&["docker", "run", "ghcr.io/acme/mcp:1.0"], None),
            (
                &["docker", "run", "registry.example:5000/mcp"],
                Some("registry.example:5000/mcp"),
            ),
            (&["docker", "run", "registry.example:5000/mcp:1.0"], None),
            (
                &[
                    "docker",
                    "run",
                    "-e",
                    "TOKEN",
                    "-v",
                    "/data:/data",
                    "acme/mcp",
                ],
                Some("acme/mcp"),
            ),
            (&["docker", "run", "--env=TOKEN=x", "acme/mcp:1.0"], None),
            (
                &[
                    "docker",
                    "run",
                    "--name",
                    "mcp",
                    "--network",
                    "host",
                    "acme/mcp:1.0",
                ],
                None,
            ),
            (&["docker", "run", "--user", "1000", "acme/mcp:1.0"], None),
            (
                &["docker", "run", "-u", "1000:1000", "acme/mcp"],
                Some("acme/mcp"),
            ),
            (
                &["docker", "run", "--platform", "linux/amd64", "acme/mcp:1.0"],
                None,
            ),
            (
                &["docker", "run", "--entrypoint", "/bin/sh", "acme/mcp:1.0"],
                None,
            ),
            (
                &[
                    "docker",
                    "run",
                    "-i",
                    "acme/mcp:1.0",
                    "serve",
                    "--port",
                    "80",
                ],
                None,
            ),
            (&["docker", "run", "", "acme/mcp:1.0"], None),
            (&["docker", "run"], None),
            (&["docker", "run", "-i"], None),
            (&["docker", "pull", "acme/mcp"], None),
            (&["docker"], None),
            (&["podman", "run", "--rm", "acme/mcp"], Some("acme/mcp")),
            (&["podman", "run", "--user", "1000", "acme/mcp:1.0"], None),
            (&["docker.exe", "run", "acme/mcp"], Some("acme/mcp")),
        ];
        check_unpinned(cases);
    }

    #[test]
    fn npm_pinned_needs_a_version_after_the_name() {
        for pkg in [
            "pkg@1.2.3",
            "@scope/pkg@1.2.3",
            "pkg@0.0.1-beta.1",
            "./local",
            "/abs/path",
            "é@1.0.0",
        ] {
            assert!(npm_pinned(pkg), "{pkg}");
        }
        for pkg in [
            "",
            "@",
            "p",
            "é",
            "pkg",
            "pkg@",
            "pkg@latest",
            "pkg@next",
            "pkg@^1.2.3",
            "pkg@~1.2.3",
            "pkg@>=1",
            "@scope/pkg",
            "@scope/pkg@",
            "@scope/pkg@latest",
        ] {
            assert!(!npm_pinned(pkg), "{pkg}");
        }
    }

    #[test]
    fn unrestricted_shell_only_flags_permissions_allow() {
        let file = FileInfo::new(".claude/settings.json");

        let safe = r#"{
  "permissions": {
    "allow": ["Read", "Bash(npm test:*)"],
    "deny": ["Bash", "Bash(*)"],
    "ask": ["Bash(:*)"]
  },
  "hooks": {
    "PreToolUse": [{ "matcher": "Bash", "hooks": [] }]
  }
}"#;
        assert!(structured(&file, &Text::new(safe)).is_empty());

        let unsafe_cfg = r#"{
  "permissions": {
    "deny": ["allow", "Bash"],
    "allow": [
      "Read",
      "Bash",
      "Bash(*)",
      "Bash(:*)"
    ]
  }
}"#;
        let findings = structured(&file, &Text::new(unsafe_cfg));
        let lines: Vec<usize> = findings.iter().map(|f| f.line).collect();
        assert_eq!(lines, vec![6, 7, 8]);
        assert!(
            findings
                .iter()
                .all(|f| f.rule == "agent.unrestricted-shell")
        );
    }
}
