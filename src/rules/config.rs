use std::sync::LazyLock;

use regex::Regex;

use super::{FileInfo, Rule, Text};
use crate::Finding;
use crate::{Family, Severity};

fn dockerfile(f: &FileInfo) -> bool {
    f.name == "dockerfile"
        || f.name.starts_with("dockerfile.")
        || f.name.ends_with(".dockerfile")
        || f.name == "containerfile"
}
fn shell(f: &FileInfo) -> bool {
    f.ext_in(&["sh", "bash", "zsh", "ps1"])
        || f.name == "makefile"
        || f.name == "justfile"
        || dockerfile(f)
}
fn workflow(f: &FileInfo) -> bool {
    f.under(".github/workflows/") && f.ext_in(&["yml", "yaml"])
}

// A `#` inside a block scalar is script text, not a YAML comment.
fn block_scalar_indent(line: &str) -> Option<(usize, Option<usize>)> {
    let trimmed = line.trim_start();
    let content = trimmed.strip_prefix("- ").map_or(trimmed, str::trim_start);
    let indent = line.len() - content.len();
    let (key, value) = content.split_once(':')?;
    if !matches!(key.trim(), "run" | "script") {
        return None;
    }
    let value = value.trim_start();
    if !value.starts_with('|') && !value.starts_with('>') {
        return None;
    }
    let indicator: Vec<char> = value[1..].split('#').next()?.trim().chars().collect();
    let valid = match indicator.as_slice() {
        [] => true,
        [one] => matches!(one, '+' | '-' | '1'..='9'),
        [one, two] => {
            (matches!(one, '+' | '-') && matches!(two, '1'..='9'))
                || (matches!(one, '1'..='9') && matches!(two, '+' | '-'))
        }
        _ => false,
    };
    let explicit = indicator
        .iter()
        .find(|c| c.is_ascii_digit())
        .and_then(|c| c.to_digit(10))
        .map(|n| indent + n as usize);
    valid.then_some((indent, explicit))
}

fn in_workflow_block_scalar(text: &Text, line_no: usize) -> bool {
    let mut block: Option<(usize, Option<usize>)> = None;
    for n in 1..=line_no {
        let line = text.line(n);
        let indent = line.len() - line.trim_start().len();
        if let Some((header_indent, content_indent)) = block {
            if line.trim().is_empty() {
                if n == line_no {
                    return false;
                }
                continue;
            }
            if indent <= header_indent {
                block = None;
            } else {
                let content_indent = content_indent.unwrap_or_else(|| {
                    block = Some((header_indent, Some(indent)));
                    indent
                });
                if n == line_no {
                    return indent >= content_indent;
                }
                continue;
            }
        }
        if let Some((header_indent, explicit_content_indent)) = block_scalar_indent(line) {
            block = Some((header_indent, explicit_content_indent));
        }
    }
    false
}

fn shell_or_workflow(f: &FileInfo) -> bool {
    shell(f) || workflow(f)
}
fn yaml(f: &FileInfo) -> bool {
    f.ext_in(&["yml", "yaml"])
}
fn terraform(f: &FileInfo) -> bool {
    f.ext_in(&["tf", "hcl"])
}
fn server_conf(f: &FileInfo) -> bool {
    f.ext == "conf" || f.name == "nginx.conf" || f.name == "httpd.conf" || f.name == ".htaccess"
}

macro_rules! rule {
    ($id:literal, $sev:ident, $files:ident, $pat:literal, $unless:expr, $msg:literal, $fix:literal) => {
        Rule {
            id: $id,
            family: Family::Config,
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
        "config.remote-script",
        Medium,
        shell_or_workflow,
        r#"\b(?i:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\n]*?(?:https?://|\$\{?\w)[^|\n]*\|\s*(?:sudo\s+(?:(?:-[AbBEeHiKklnPSsVv]*[ugCDhprtTU]|--(?:user|group|chdir|host|prompt|role|type|other-user|close-from|command-timeout))\s+(?:"[^"\n]*"|'[^'\n]*'|[\w.$/~][\w.${}/~-]*)\s+|-[AbBEeHiKklnPSsVv]*[ugCDhprtTU](?:"[^"\n]*"|'[^'\n]*'|[^\s;|&`<>()"']+)\s+|-[AbBEeHiKklnPSsVv]+\s+|--[\w-]+=\S*\s+|--(?:preserve-env|login|shell|non-interactive|background|stdin|set-home|preserve-groups|askpass|bell|reset-timestamp|remove-timestamp)\s+)*(?:--\s+)?)?(?:sh|bash|zsh|python3?|(?i:iex|invoke-expression))\b|\b(?:ba|z|da|k)?sh\s+(?:[-+]o\s+[\w-]+\s+|-[A-Za-z]+\s+)*?-[A-Za-z]*c[A-Za-z]*\s+\\?["']?(?:\$\(|`)\s*(?:curl|wget)\b(?:[^()`\n]|\([^()`\n]*\))*?(?:https?://|\$\{?\w)"#,
        None,
        "A script is downloaded and piped straight into a shell, with no pinning or checksum.",
        "Download to a file, verify a pinned checksum or signature, then run it; or use a package manager."
    ),
    rule!(
        "config.docker-unpinned-image",
        Low,
        dockerfile,
        r"(?mi)^FROM\s+(?:--platform=\S+\s+)?[^\s:@$]+(?::latest)?(?:\s+AS\s+\S+)?\s*$",
        Some(r"(?i)^FROM\s+scratch\b"),
        "The base image has no version tag (or uses latest), so builds change without notice.",
        "Pin a version tag, ideally with a digest (image:1.2@sha256:...)."
    ),
    rule!(
        "config.docker-secret-env",
        High,
        dockerfile,
        r"(?mi)^(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\w*\s*[= ]\s*\S+",
        None,
        "A secret is baked into the image; anyone who pulls it can read it from the layers.",
        "Pass secrets at run time, or use BuildKit secrets (RUN --mount=type=secret)."
    ),
    rule!(
        "config.docker-add-url",
        Low,
        dockerfile,
        r"(?mi)^ADD\s+https?://",
        None,
        "ADD downloads a remote file at build time without checking it.",
        "Download with curl and verify a checksum, or COPY a vendored file."
    ),
    rule!(
        "config.docker-root-user",
        Medium,
        dockerfile,
        r"(?mi)^USER\s+(?:root|0)\s*$",
        None,
        "The container runs as root, so a break-out starts with full privileges.",
        "Create an unprivileged user and switch to it with USER."
    ),
    rule!(
        "config.gha-pull-request-target",
        Medium,
        workflow,
        r"(?m)^\s*pull_request_target\s*:|on:\s*\[[^\]\n]*pull_request_target",
        None,
        "pull_request_target runs with repository secrets on code from forks; checking out the PR head here is a known takeover path.",
        "Use pull_request, or never check out or run the PR's code in this workflow."
    ),
    rule!(
        "config.gha-write-all",
        Medium,
        workflow,
        r"permissions\s*:\s*write-all",
        None,
        "The workflow token can write to everything in the repository.",
        "Set permissions: contents: read, and grant writes per job only where needed."
    ),
    rule!(
        "config.gha-unpinned-action",
        Medium,
        workflow,
        r"uses:\s*[\w.\-]+/[\w./\-]+@(?:main|master|dev|develop|HEAD|latest)\b",
        None,
        "A third-party action runs from a moving branch, so any push to it runs in your CI with your secrets.",
        "Pin the action to a full commit SHA."
    ),
    rule!(
        "config.gha-script-injection",
        High,
        workflow,
        r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)[\w.\[\]*]*\.(?:title|body|message|name|label|ref|email|default_branch)|event\.workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|(?:author|committer)\.(?:name|email)))|head_ref)\s*\}\}",
        None,
        "Text an outsider controls (a PR title, issue body, branch name) is pasted into the workflow, so it can run commands.",
        "Pass it through an env: variable and use \"$VAR\" in the script."
    ),
    rule!(
        "config.privileged-container",
        High,
        yaml,
        r"(?m)^\s*(?:privileged|allowPrivilegeEscalation)\s*:\s*true\b",
        None,
        "A container runs privileged (or may gain privileges), which gives it near-root access to the host.",
        "Remove privileged and set allowPrivilegeEscalation: false; add only the capabilities you need."
    ),
    rule!(
        "config.k8s-host-access",
        High,
        yaml,
        r"(?m)^\s*host(?:Network|PID|IPC)\s*:\s*true\b",
        None,
        "The pod shares the host's network, process or IPC namespace.",
        "Remove hostNetwork/hostPID/hostIPC unless the workload truly needs it."
    ),
    rule!(
        "config.tf-open-ingress",
        Medium,
        terraform,
        r#"\bcidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"|\bipv6_cidr_blocks\s*=\s*\[\s*"::/0""#,
        None,
        "A network rule is open to the whole internet.",
        "Limit the CIDR to known addresses, especially for SSH, RDP and databases. Ignore for public web ports or egress."
    ),
    rule!(
        "config.tf-public-bucket",
        High,
        terraform,
        r#"\bacl\s*=\s*"public-read(?:-write)?""#,
        None,
        "A storage bucket is public.",
        "Make it private and serve files through a CDN or signed URLs."
    ),
    rule!(
        "config.tf-public-access-block",
        Medium,
        terraform,
        r#"(?m)\b(?:block_public_policy|restrict_public_buckets)\s*=\s*(?:false|"false")\s*(?:$|#|//|/\*|,|\})"#,
        None,
        "An S3 public access block is turned off, so a bucket policy can make the bucket (or every bucket in the account) public.",
        "Set block_public_policy and restrict_public_buckets to true. Ignore for a bucket that serves a public website on purpose."
    ),
    rule!(
        "config.tf-public-database",
        High,
        terraform,
        r#"(?m)^[ \t]*publicly_accessible[ \t]*=[ \t]*(?:true|"true")[ \t]*(?:\r?$|#|//|/\*)"#,
        None,
        "A database gets a public IP address, so only its security group stands between it and the internet.",
        "Set publicly_accessible = false and reach the database from inside its network, through a bastion host or a VPN."
    ),
    rule!(
        "config.tf-unencrypted-storage",
        Medium,
        terraform,
        r#"(?m)^[ \t]*storage_encrypted[ \t]*=[ \t]*(?:false|"false")[ \t]*(?:\r?$|#|//|/\*)"#,
        None,
        "A database's storage is not encrypted at rest, so its snapshots and backups are not encrypted either.",
        "Set storage_encrypted = true, with a kms_key_id if you manage your own keys."
    ),
    rule!(
        "config.nginx-autoindex",
        Low,
        server_conf,
        r"(?m)^\s*autoindex\s+on\s*;",
        None,
        "Directory listing is on, so every file in the folder can be browsed.",
        "Set autoindex off."
    ),
    rule!(
        "config.weak-tls-version",
        Medium,
        server_conf,
        r#"(?i)(?:ssl_protocols|SSLProtocol)[^;\n]*\b(?:SSLv[23]|TLSv1|TLSv1\.1)(?:\s|;|$|["'])"#,
        None,
        "Old TLS or SSL versions are enabled; they have known attacks.",
        "Allow only TLSv1.2 and TLSv1.3."
    ),
];

static STAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?mi)^FROM\s+\S+\s+AS\s+(\S+)").unwrap());
static FROM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)").unwrap());
static YAML_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*-?\s*([A-Za-z_][\w-]*)\s*:\s*\S").unwrap());
// A YAML key needs a space or the line end after its colon, so `C:\Windows\...` in a `run: |`
// block is a command, not a key.
static STEP_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*-?\s*([A-Za-z_][\w-]*)\s*:(?:\s|$)").unwrap());
// The whole `key = false`, not just the key, so `= true # was block_public_policy = false`
// is judged by the part in the comment, which the walk then rejects.
// The rule's own pattern (`key = false` that ends the value), found again on the line in `keep`.
static PUBLIC_ACCESS_OFF: LazyLock<Regex> = LazyLock::new(|| {
    let rule = RULES
        .iter()
        .find(|r| r.id == "config.tf-public-access-block")
        .expect("the rule is in RULES");
    Regex::new(rule.pattern).unwrap()
});
// Re-used in `keep` after stripping a trailing `#` comment from a matched line.
static REMOTE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    let rule = RULES
        .iter()
        .find(|r| r.id == "config.remote-script")
        .expect("the rule is in RULES");
    Regex::new(rule.pattern).unwrap()
});

enum ShellFrame {
    DoubleQuote,
    CmdSubst { parens: usize },
    ParamExpand { braces: usize },
}

enum SingleQuote {
    None,
    Plain,
    AnsiC,
}

/// The runnable prefix of a shell, PowerShell, Dockerfile, Makefile or workflow line, ending at
/// the first `#` that starts a comment (at the start of a word, outside quotes and escapes).
fn strip_shell_comment(line: &str, powershell: bool) -> &str {
    let b = line.as_bytes();
    let escape = if powershell { b'`' } else { b'\\' };
    let mut frames: Vec<ShellFrame> = Vec::new();
    let mut single = SingleQuote::None;
    let mut word_start = true;
    let mut i = 0;

    while i < b.len() {
        let ch = b[i];
        match single {
            SingleQuote::Plain => {
                if ch == b'\'' {
                    single = SingleQuote::None;
                    word_start = false;
                }
                i += 1;
                continue;
            }
            SingleQuote::AnsiC => {
                if ch == b'\\' {
                    i = (i + 2).min(b.len());
                    continue;
                }
                if ch == b'\'' {
                    single = SingleQuote::None;
                    word_start = false;
                }
                i += 1;
                continue;
            }
            SingleQuote::None => {}
        }
        // `$(...)` and non-PowerShell `${...}` can nest quotes both inside double quotes and
        // unquoted.
        if ch == b'$' && b.get(i + 1) == Some(&b'(') {
            frames.push(ShellFrame::CmdSubst { parens: 1 });
            word_start = true;
            i += 2;
            continue;
        }
        if !powershell && ch == b'$' && b.get(i + 1) == Some(&b'{') {
            frames.push(ShellFrame::ParamExpand { braces: 1 });
            word_start = false;
            i += 2;
            continue;
        }
        if matches!(frames.last(), Some(ShellFrame::DoubleQuote)) {
            if ch == escape {
                i = (i + 2).min(b.len());
                continue;
            }
            if ch == b'"' {
                frames.pop();
                word_start = false;
            }
            i += 1;
            continue;
        }
        match ch {
            c if c == escape => {
                i = (i + 2).min(b.len());
                word_start = false;
                continue;
            }
            b'$' if !powershell && b.get(i + 1) == Some(&b'\'') => {
                single = SingleQuote::AnsiC;
                word_start = false;
                i += 2;
                continue;
            }
            b'\'' => {
                single = SingleQuote::Plain;
                word_start = false;
            }
            b'"' => {
                frames.push(ShellFrame::DoubleQuote);
                word_start = false;
            }
            b'{' => {
                if let Some(ShellFrame::ParamExpand { braces }) = frames.last_mut() {
                    *braces += 1;
                }
                word_start = false;
            }
            b'}' => {
                if let Some(ShellFrame::ParamExpand { braces }) = frames.last_mut() {
                    *braces -= 1;
                    if *braces == 0 {
                        frames.pop();
                    }
                }
                word_start = false;
            }
            b'(' => {
                if let Some(ShellFrame::CmdSubst { parens }) = frames.last_mut() {
                    *parens += 1;
                }
                word_start = true;
            }
            b')' => {
                if let Some(ShellFrame::CmdSubst { parens }) = frames.last_mut() {
                    *parens -= 1;
                    if *parens == 0 {
                        frames.pop();
                        word_start = false;
                    } else {
                        word_start = true;
                    }
                } else {
                    word_start = true;
                }
            }
            // In PowerShell, `<# ... #>` is a block comment; skip inline blocks and do not treat
            // a closing `#>` as a `#` line comment.
            b'<' if powershell && b.get(i + 1) == Some(&b'#') => {
                if let Some(rel) = line[i + 2..].find("#>") {
                    i += 2 + rel + 2;
                    word_start = true;
                    continue;
                }
                return &line[..i];
            }
            b'#' if word_start
                && !matches!(frames.last(), Some(ShellFrame::ParamExpand { .. }))
                && !(powershell && b.get(i + 1) == Some(&b'>')) =>
            {
                return &line[..i];
            }
            b' ' | b'\t' | b';' | b'&' | b'|' => {
                word_start = true;
            }
            _ => {
                word_start = false;
            }
        }
        i += 1;
    }
    line
}

fn remote_script_in_code(line: &str, powershell: bool) -> bool {
    let code = strip_shell_comment(line, powershell);
    code.len() == line.len() || REMOTE_SCRIPT.is_match(code)
}

/// The end of the quoted string that opens at `b[start]`: the index of its closing quote, of the
/// newline that ends it unclosed, or `b.len()`. A `${ ... }` or `%{ ... }` template inside may
/// hold braces and quoted strings of its own; a stack (not recursion) keeps deep nesting safe.
fn hcl_string_end(b: &[u8], start: usize) -> usize {
    // One entry per open string (None) or template (Some(open braces)).
    let mut open: Vec<Option<usize>> = vec![None];
    let mut j = start + 1;
    while j < b.len() {
        match open.last_mut() {
            Some(None) => match b[j] {
                b'"' => {
                    open.pop();
                    if open.is_empty() {
                        return j;
                    }
                }
                b'\n' if open.len() == 1 => return j,
                b'\\' => j += 1,
                // `$${` and `%%{` are a literal `${` and `%{`, not a template.
                b'$' | b'%' if b.get(j + 1) == Some(&b[j]) && b.get(j + 2) == Some(&b'{') => j += 2,
                b'$' | b'%' if b.get(j + 1) == Some(&b'{') => {
                    open.push(Some(1));
                    j += 1;
                }
                _ => {}
            },
            Some(Some(depth)) => match b[j] {
                b'"' => open.push(None),
                b'{' => *depth += 1,
                b'}' => {
                    *depth -= 1;
                    if *depth == 0 {
                        open.pop();
                    }
                }
                _ => {}
            },
            None => unreachable!("the outer string is popped only by returning"),
        }
        j += 1;
    }
    b.len()
}

/// A walk through one HCL file that remembers where it stopped. Asking about
/// offsets in increasing order (the order findings come in) reads the file
/// once in total, instead of once per finding.
#[derive(Default)]
pub struct HclWalk {
    i: usize,
    depth: usize,
    line_start: usize,
    header: Option<(usize, usize)>,
    // Where the last step started when it jumped past the offset asked for (over a comment,
    // string or heredoc). Any later offset before `i` but after this is inside that same span.
    over_from: Option<usize>,
}

impl HclWalk {
    /// The header of the top-level HCL block whose own body holds byte `at`
    /// (e.g. `resource "aws_s3_bucket_public_access_block" "site"`). None when
    /// `at` is outside every block, inside a nested block, or in a comment,
    /// string or heredoc.
    fn block_at<'s>(&mut self, src: &'s str, at: usize) -> Option<&'s str> {
        if at < self.i {
            if self.over_from.is_some_and(|s| s < at) {
                return None;
            }
            *self = Self::default();
        }
        let b = src.as_bytes();
        let mut last = None;
        while self.i < at {
            let i = self.i;
            last = Some(i);
            match b[i] {
                b'\n' => self.line_start = i + 1,
                b'#' => self.i = src[i..].find('\n').map_or(b.len(), |n| i + n) - 1,
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    self.i = src[i..].find('\n').map_or(b.len(), |n| i + n) - 1
                }
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    self.i = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 1);
                    // `/* note */ resource ... {`: the header starts after the comment.
                    if src[self.line_start..i].trim().is_empty() {
                        self.line_start = (self.i + 1).min(b.len());
                    }
                }
                b'"' => {
                    let j = hcl_string_end(b, i);
                    // An unclosed string ends at its newline, which the walk still reads.
                    self.i = if b.get(j) == Some(&b'\n') { j - 1 } else { j };
                }
                b'<' if src[i..].starts_with("<<") => {
                    let rest = src[i + 2..].trim_start_matches('-');
                    let tag: &str = rest
                        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                        .next()
                        .unwrap_or("");
                    if !tag.is_empty() {
                        let body = src[i..].find('\n').map_or(b.len(), |n| i + n + 1);
                        let mut end = b.len();
                        let mut pos = body;
                        for l in src[body..].split_inclusive('\n') {
                            pos += l.len();
                            if l.trim() == tag {
                                end = pos;
                                break;
                            }
                        }
                        self.line_start = end;
                        self.i = end - 1;
                    }
                }
                b'{' => {
                    if self.depth == 0 {
                        self.header = Some((self.line_start, i));
                    }
                    self.depth += 1;
                }
                b'}' => {
                    self.depth = self.depth.saturating_sub(1);
                    // A next block on the same line starts its header here.
                    if self.depth == 0 {
                        self.line_start = i + 1;
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
        if self.i > at {
            self.over_from = last;
            return None;
        }
        self.over_from = None;
        if self.depth != 1 {
            return None;
        }
        self.header.map(|(s, e)| src[s..e].trim())
    }
}

fn is_public_access_block(header: &str) -> bool {
    let mut words = header.split_whitespace().map(|w| w.trim_matches('"'));
    words.next() == Some("resource")
        && matches!(
            words.next(),
            Some("aws_s3_bucket_public_access_block" | "aws_s3_account_public_access_block")
        )
}

pub fn keep(file: &FileInfo, text: &Text, f: &Finding, hcl: &mut HclWalk) -> bool {
    match f.rule.as_str() {
        "config.docker-unpinned-image" => {
            let stages: Vec<String> = STAGE
                .captures_iter(text.src)
                .map(|c| c[1].to_ascii_lowercase())
                .collect();
            FROM.captures(text.line(f.line))
                .is_none_or(|c| !stages.contains(&c[1].to_ascii_lowercase()))
        }
        "config.gha-script-injection" if workflow(file) => {
            let line = text.line(f.line);
            let yaml_comment =
                line.trim_start().starts_with('#') && !in_workflow_block_scalar(text, f.line);
            !yaml_comment
                && YAML_KEY
                    .captures(line)
                    .is_none_or(|c| &c[1] == "run" || &c[1] == "script")
        }
        // A `#` comment (whole-line or trailing) in a shell script, PowerShell script, Dockerfile,
        // Makefile or workflow does not run; in a workflow, only a `run:` or `script:` step (or a
        // line of its block) runs, not a step `name:`. Re-check the line only when a comment was
        // actually stripped so multi-line matches (e.g. `|\n  sh`) stay reported. Workflows can
        // run either POSIX shells or `pwsh`, so keep a workflow finding if either dialect keeps it.
        "config.remote-script" => {
            let line = text.line(f.line);
            let matches = if workflow(file) {
                remote_script_in_code(line, false) || remote_script_in_code(line, true)
            } else {
                remote_script_in_code(line, file.ext == "ps1")
            };
            matches
                && (!workflow(file)
                    || STEP_KEY
                        .captures(line)
                        .is_none_or(|c| &c[1] == "run" || &c[1] == "script"))
        }
        "config.tf-public-access-block" => {
            let line = text.line(f.line);
            let start = text.line_start(f.line);
            PUBLIC_ACCESS_OFF.find_iter(line).any(|m| {
                hcl.block_at(text.src, start + m.start())
                    .is_some_and(is_public_access_block)
            })
        }
        "config.weak-tls-version" => old_tls_on(text.line(f.line)),
        _ => true,
    }
}

/// Whether an Apache `SSLProtocol` line leaves an old version on. Its words are applied in
/// order: `all` turns every version on, `-name` turns one off, and `+name` turns it on, so
/// `all -SSLv3 -TLSv1 -TLSv1.1` is safe while `all -SSLv3` still allows TLS 1.0. A plain name
/// (or a plain `all`) replaces the set so far, as mod_ssl does, so `TLSv1 TLSv1.2` leaves only
/// TLS 1.2 on. Any other line, such as nginx `ssl_protocols` (no signs), is kept as the pattern
/// found it, and so is one that this line alone cannot settle: it goes on after a trailing
/// backslash, uses a `${VAR}`, or has a word that is not a known protocol. Quotes around words
/// are dropped, as in Apache.
fn old_tls_on(line: &str) -> bool {
    const OLD: [&str; 4] = ["sslv2", "sslv3", "tlsv1", "tlsv1.1"];
    let lower = line.to_ascii_lowercase();
    let mut words = lower.split_whitespace();
    if words.next() != Some("sslprotocol") {
        return true;
    }
    if lower.trim_end().ends_with('\\') || lower.contains("${") {
        return true;
    }
    // Only the known names are tracked, so a long line costs one pass; an unknown word keeps the finding.
    const KNOWN: [&str; 6] = ["sslv2", "sslv3", "tlsv1", "tlsv1.1", "tlsv1.2", "tlsv1.3"];
    let mut on: Vec<&str> = Vec::new();
    for word in words {
        let word = word.trim_matches(|c| c == '"' || c == '\'');
        if word.contains(['"', '\'']) {
            return true;
        }
        let (add, name) = match word.strip_prefix('-') {
            Some(name) => (false, name),
            None => (true, word.strip_prefix('+').unwrap_or(word)),
        };
        if name != "all" && !KNOWN.contains(&name) {
            return true;
        }
        // A plain name (no sign) replaces the set so far, as mod_ssl does.
        if !word.starts_with(['+', '-']) {
            on.clear();
        }
        let names = if name == "all" {
            &OLD[1..]
        } else {
            std::slice::from_ref(&name)
        };
        for &n in names {
            on.retain(|&o| o != n);
            if add {
                on.push(n);
            }
        }
    }
    on.iter().any(|n| OLD.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sslprotocol_minus_turns_a_version_off() {
        for (line, on) in [
            ("SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", false),
            ("  sslprotocol ALL -sslv3 -tlsv1 -tlsv1.1", false),
            ("SSLProtocol -all +TLSv1.2 +TLSv1.3", false),
            ("SSLProtocol all -SSLv3", true),
            ("SSLProtocol all -SSLv3 -TLSv1", true),
            ("SSLProtocol -all +TLSv1.1 +TLSv1.2", true),
            // A plain name replaces the set so far, as mod_ssl does: only TLSv1.2 is on.
            ("SSLProtocol TLSv1 TLSv1.2", false),
            ("SSLProtocol TLSv1.2 TLSv1", true),
            ("SSLProtocol TLSv1.2 +TLSv1.1", true),
            // An unknown word cannot be weighed, so the finding stays.
            ("SSLProtocol -all +TLSv1.2 bogus", true),
            ("SSLProtocol -TLSv1 all", true),
            // Apache removes argument quotes before reading the words.
            ("SSLProtocol \"all\" \"-SSLv3\" '-TLSv1' -TLSv1.1", false),
            ("SSLProtocol \"all -SSLv3\"", true),
            // Quotes that run two words together cannot be split safely here.
            ("SSLProtocol \"-all\"\"+TLSv1.2\"", true),
            // A line that goes on after a backslash, or a ${VAR}, is not read in full here.
            ("SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 \\", true),
            ("SSLProtocol ${LEGACY} -SSLv3 -TLSv1 -TLSv1.1", true),
            ("ssl_protocols TLSv1 TLSv1.2;", true),
            (
                "ssl_protocols TLSv1 TLSv1.2; # like SSLProtocol in Apache",
                true,
            ),
        ] {
            assert_eq!(old_tls_on(line), on, "{line}");
        }
    }

    /// Whether the first `key = false` in `src` is reported: it matches and sits in an S3
    /// public access block.
    fn in_block(src: &str) -> bool {
        let Some(m) = PUBLIC_ACCESS_OFF.find(src) else {
            return false;
        };
        HclWalk::default()
            .block_at(src, m.start())
            .is_some_and(is_public_access_block)
    }

    #[test]
    fn public_access_block_reads_hcl_around_the_key() {
        let block = |body: &str| {
            format!("resource \"aws_s3_bucket_public_access_block\" \"site\" {{\n{body}\n}}\n")
        };
        let cases: &[(String, bool)] = &[
            (block("  block_public_policy = false"), true),
            // Two top-level blocks on one line: each block's header starts after the last `}`.
            (
                "resource \"aws_s3_bucket_public_access_block\" \"a\" {} resource \"aws_s3_access_point\" \"b\" {\n  block_public_policy = false\n}\n".to_string(),
                false,
            ),
            (
                "resource \"aws_s3_access_point\" \"b\" {} resource \"aws_s3_bucket_public_access_block\" \"a\" {\n  block_public_policy = false\n}\n".to_string(),
                true,
            ),
            // A block comment before the header on the same line.
            (
                "/* site */ resource \"aws_s3_bucket_public_access_block\" \"site\" {\n  block_public_policy = false\n}\n".to_string(),
                true,
            ),
            (
                block("  block_public_policy = false # public website"),
                true,
            ),
            (block("  block_public_policy = \"false\","), true),
            // `false` is part of a longer expression, not the value.
            (block("  block_public_policy = false == var.public"), false),
            // `$${` and `%%{` are literal text, not a template that would swallow the block.
            (
                format!(
                    "locals {{\n  x = \"$${{\"\n  y = \"%%{{\"\n}}\n{}",
                    block("  block_public_policy = false")
                ),
                true,
            ),
            // A heredoc tag with a hyphen ends at its own line.
            (
                format!(
                    "locals {{\n  d = <<END-POLICY\nhi\nEND-POLICY\n}}\n{}",
                    block("  block_public_policy = false")
                ),
                true,
            ),
            // The key itself is fine; the `= false` is in a comment.
            (
                block("  block_public_policy = true # was block_public_policy = false"),
                false,
            ),
            (block("  # block_public_policy = false"), false),
            // A template with a quoted brace, before the block and inside it.
            (
                format!(
                    "locals {{\n  n = \"${{replace(var.name, \"{{\", \"-\")}}\"\n}}\n{}",
                    block("  block_public_policy = false")
                ),
                true,
            ),
            (
                block(
                    "  bucket = \"${replace(var.name, \"{\", \"-\")}\"\n  block_public_policy = false",
                ),
                true,
            ),
            (
                block("  bucket = \"%{ if var.x }{%{ endif }\"\n  block_public_policy = false"),
                true,
            ),
            // The `= false` inside a string is not a setting.
            (
                block("  note = \"block_public_policy = false\"\n  block_public_policy = true"),
                false,
            ),
            // Nested blocks and other resource types are not the access block.
            (
                block("  tags = {\n    block_public_policy = false\n  }"),
                false,
            ),
            (
                "resource \"aws_s3_access_point\" \"ap\" {\n  block_public_policy = false\n}\n"
                    .to_string(),
                false,
            ),
        ];
        for (src, want) in cases {
            assert_eq!(in_block(src), *want, "{src}");
        }
    }

    #[test]
    fn hcl_string_end_survives_deep_or_unclosed_templates() {
        let deep = format!("\"{}", "${\"".repeat(100_000));
        assert_eq!(hcl_string_end(deep.as_bytes(), 0), deep.len());
        assert_eq!(hcl_string_end(b"\"abc\nx\"", 0), 4);
        assert_eq!(hcl_string_end(b"\"a\\\"b\" x", 0), 5);
        assert_eq!(hcl_string_end(b"\"${ \"}\" }\" x", 0), 9);
    }

    #[test]
    fn hcl_walk_gives_the_same_answer_resumed_or_fresh() {
        // Offsets inside one heredoc and one block comment must not restart the walk (each
        // restart reads the file from the top again) and must still give the fresh answer.
        let src = "resource \"aws_s3_bucket_public_access_block\" \"a\" {\n  block_public_policy = false\n  policy = <<EOF\n  block_public_policy = false\n  restrict_public_buckets = false\nEOF\n  /* block_public_policy = false\n     restrict_public_buckets = false */\n  restrict_public_buckets = false\n}\nresource \"aws_s3_access_point\" \"b\" {\n  restrict_public_buckets = false\n}\n";
        let offsets: Vec<usize> = PUBLIC_ACCESS_OFF
            .find_iter(src)
            .map(|m| m.start())
            .collect();
        let mut walk = HclWalk::default();
        for &at in offsets.iter().chain(offsets.iter().rev()) {
            assert_eq!(walk.block_at(src, at), HclWalk::default().block_at(src, at));
        }
    }

    #[test]
    fn remote_script_skips_comment_lines() {
        for (path, src, want) in [
            (
                "i.sh",
                concat!(
                    "#!/bin/sh\n",
                    "# curl https://x.io/i.sh | bash\n",
                    "  # sh -c \"$(curl https://x.io/i.sh)\"\n",
                    "curl https://x.io/i.sh | sh\n",
                    "curl -fsSL https://example.com/install.sh -o install.sh  # or: curl -fsSL https://example.com/install.sh | sh\n",
                    "curl -fsSL https://example.com/install.sh -o install.sh;# or: curl -fsSL https://example.com/install.sh | sh\n",
                    "echo hi # sh -c \"$(curl -fsSL https://example.com/i.sh)\"\n",
                    "curl -fsSL \"https://example.com/i.sh#v1\" | sh\n",
                    "curl -fsSL 'https://example.com/i.sh#v1' | sh\n",
                    "curl -fsSL https://example.com/i.sh#v1 | sh\n",
                    "curl -fsSL https://example.com/i.sh | sh # install\n",
                    "curl -fsSL https://example.com/i.sh \\# | sh\n",
                    "bash -c \"$(curl -H \"X-Note: a # b\" https://example.com/i.sh)\"\n",
                    "curl -fsSL https://example.com/i.sh -o install.sh # | sh\n",
                    "curl -fsSL https://example.com/i.sh |\n",
                    "  sh\n",
                    "bash -c \"$(\n",
                    "  curl -fsSL https://example.com/i.sh\n",
                    ")\"\n",
                    "printf '%s\\n' $'it\\'s # text'; curl https://example.com/i.sh | sh\n",
                    "curl https://example.com/${v/ #/-}.sh | sh\n",
                    "echo \"${v:-\"a # b\"}\"; curl https://example.com/i.sh | sh\n",
                    "curl -fsSL https://x.io/i.sh -o i.sh\t# sh -c \"$(curl https://x.io/i.sh)\"\n",
                    "echo \"see docs\" # curl https://x.io/i.sh | bash\n",
                    "curl -fsSL https://x.io/i.sh | sh -s -- \"$#\" # install\n",
                    "sh -c \"$(curl -fsSL https://x.io/i.sh)\" # install\n",
                    "echo it\\'s fine; curl -fsSL https://x.io/i.sh | sh\n",
                ),
                vec![4, 8, 9, 10, 11, 12, 13, 15, 17, 20, 21, 22, 25, 26, 27],
            ),
            (
                "i.ps1",
                concat!(
                    "# irm https://x.io/i.ps1 | iex\n",
                    "irm https://x.io/i.ps1 -OutFile i.ps1 # or: irm https://x.io/i.ps1 | iex\n",
                    "irm \"https://x.io/i.ps1#v1\" | iex\n",
                    "irm https://x.io/i.ps1 | iex # install\n",
                    "echo \"C:\\tmp\\\" # irm https://x.io/i.ps1 | iex\n",
                    "<# note #> irm https://x.io/i.ps1 | iex\n",
                    "#> irm https://x.io/i.ps1 | iex\n",
                    "irm \"https://x.io/i.ps1?a=$(Get-Date -f \"yyyy # x\")\" | iex\n",
                    "irm https://x.io/i.ps1 |\n",
                    "  iex\n",
                ),
                vec![3, 4, 6, 7, 8, 9],
            ),
            (
                "Dockerfile",
                concat!(
                    "# RUN curl https://x.io/i.sh | sh\n",
                    "RUN curl -fsSL https://x.io/i.sh -o i.sh # or: curl https://x.io/i.sh | sh\n",
                    "RUN curl https://x.io/i.sh | sh\n",
                ),
                vec![3],
            ),
            (
                "Makefile",
                concat!(
                    "# curl https://x.io/i.sh | sh\n",
                    "all:\n",
                    "\tcurl -fsSL https://x.io/i.sh -o i.sh # or: curl https://x.io/i.sh | sh\n",
                    "\tcurl https://x.io/i.sh | sh\n",
                ),
                vec![4],
            ),
            (
                "justfile",
                concat!(
                    "install:\n",
                    "    curl -fsSL https://x.io/i.sh -o i.sh # or: curl https://x.io/i.sh | sh\n",
                    "    curl https://x.io/i.sh | sh\n",
                ),
                vec![3],
            ),
            (
                ".github/workflows/ci.yml",
                concat!(
                    "jobs:\n",
                    "  build:\n",
                    "    steps:\n",
                    "      - run: curl -fsSL https://x.io/i.sh -o i.sh # or: curl https://x.io/i.sh | sh\n",
                    "      - run: curl -fsSL https://x.io/i.sh | sh # install\n",
                    "      - shell: pwsh\n",
                    "        run: |\n",
                    "          Write-Host \"a`\" # text\"; irm https://example.com/i.ps1 | iex\n",
                ),
                vec![5, 8],
            ),
        ] {
            let lines: Vec<usize> = crate::rules::check(&FileInfo::new(path), src, true)
                .into_iter()
                .filter(|f| f.rule == "config.remote-script")
                .map(|f| f.line)
                .collect();
            assert_eq!(lines, want, "{path}");
        }
    }
}
