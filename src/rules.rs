use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::{Family, Finding, Severity};

pub mod agent;
mod code;
mod config;
mod mobile;
pub mod secrets;

pub struct FileInfo {
    pub rel: String,
    pub name: String,
    pub ext: String,
}

impl FileInfo {
    pub fn new(rel: &str) -> Self {
        let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
        let ext = name
            .rsplit_once('.')
            .map(|(_, e)| e.to_string())
            .unwrap_or_default();
        Self {
            rel: rel.to_string(),
            name,
            ext,
        }
    }

    pub fn ext_in(&self, exts: &[&str]) -> bool {
        exts.contains(&self.ext.as_str())
    }

    pub fn is_test(&self) -> bool {
        const DIRS: &[&str] = &[
            "test",
            "tests",
            "__tests__",
            "spec",
            "specs",
            "cypress",
            "e2e",
            "fixtures",
            "__mocks__",
            "testdata",
            "mocks",
        ];
        let mut parts = self.rel.split('/');
        parts.next_back();
        parts.any(|p| DIRS.contains(&p.to_ascii_lowercase().as_str()))
            || [".spec.", ".test.", "_test.", "_spec.", ".cy."]
                .iter()
                .any(|m| self.name.contains(m))
            || self.name.starts_with("test_")
    }

    pub fn under(&self, dir: &str) -> bool {
        self.rel.starts_with(dir) || self.rel.contains(&format!("/{dir}"))
    }
}

pub struct Rule {
    pub id: &'static str,
    pub family: Family,
    pub severity: Severity,
    pub files: fn(&FileInfo) -> bool,
    pub pattern: &'static str,
    pub unless: Option<&'static str>,
    pub message: &'static str,
    pub fix: &'static str,
}

struct Compiled {
    rule: &'static Rule,
    re: Regex,
    unless: Option<Regex>,
}

static RULES: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    [
        code::RULES,
        secrets::RULES,
        agent::RULES,
        mobile::RULES,
        config::RULES,
    ]
    .into_iter()
    .flatten()
    .map(|rule| Compiled {
        rule,
        re: Regex::new(rule.pattern).unwrap_or_else(|e| panic!("{}: {e}", rule.id)),
        unless: rule
            .unless
            .map(|u| Regex::new(u).unwrap_or_else(|e| panic!("{} unless: {e}", rule.id))),
    })
    .collect()
});

pub fn all() -> impl Iterator<Item = &'static Rule> {
    RULES.iter().map(|c| c.rule)
}

pub struct Text<'a> {
    pub src: &'a str,
    starts: Vec<usize>,
    /// What the `safe-anything:ignore` markers on each line cover, read once per line: a long
    /// line can hold many findings.
    marks: RefCell<HashMap<usize, Cover>>,
}

impl<'a> Text<'a> {
    pub fn new(src: &'a str) -> Self {
        let mut starts = vec![0];
        starts.extend(src.match_indices('\n').map(|(i, _)| i + 1));
        Self {
            src,
            starts,
            marks: RefCell::default(),
        }
    }

    pub fn line_of(&self, offset: usize) -> usize {
        self.starts.partition_point(|&s| s <= offset)
    }

    pub fn line_start(&self, n: usize) -> usize {
        self.starts[n - 1]
    }

    pub fn line(&self, n: usize) -> &'a str {
        let start = self.starts[n - 1];
        let end = self.starts.get(n).map(|e| e - 1).unwrap_or(self.src.len());
        self.src[start..end].trim_end_matches('\r')
    }

    /// Whether a `safe-anything:ignore` marker on line `n` or the line above covers `rule`.
    pub fn suppressed(&self, n: usize, rule: &str) -> bool {
        self.ignores(n, rule) || (n > 1 && self.ignores(n - 1, rule))
    }

    fn ignores(&self, n: usize, rule: &str) -> bool {
        self.marks
            .borrow_mut()
            .entry(n)
            .or_insert_with(|| Cover::of(self.line(n)))
            .covers(rule)
    }
}

/// The rules the `safe-anything:ignore` markers on a line cover.
///
/// A bare marker covers every rule. A marker followed by rule ids
/// (`safe-anything:ignore code.weak-hash, code.eval`) covers only the known ones among them, so a
/// typo like `code.weak-hashh` covers nothing and the finding stays in the report.
#[derive(Default)]
struct Cover {
    all: bool,
    ids: Vec<&'static str>,
}

impl Cover {
    fn of(line: &str) -> Self {
        const MARK: &str = "safe-anything:ignore";
        let mut cover = Self::default();
        // Splitting at the markers reads each part of the line once, however many it holds.
        for after in line.split(MARK).skip(1) {
            match marker_ids(after) {
                None => {
                    cover.all = true;
                    break;
                }
                Some(ids) => {
                    for id in ids {
                        if !cover.ids.contains(&id) {
                            cover.ids.push(id);
                        }
                    }
                }
            }
        }
        cover
    }

    fn covers(&self, rule: &str) -> bool {
        self.all || self.ids.contains(&rule)
    }
}

/// The known rule ids a marker lists, or `None` when it lists none and so is bare. `after` is the
/// text after the marker, up to the next one.
///
/// The list ends at `*/` or `-->` (the rest of the comment is not part of it). It must be set
/// apart from the marker by whitespace or `:`; `safe-anything:ignore,` is bare. Words are split at
/// whitespace and commas and read from the start while they look like rule ids (`family.name`);
/// one trailing `.`, `;` or `:` is dropped and ends the list.
fn marker_ids(after: &str) -> Option<Vec<&'static str>> {
    static KNOWN: LazyLock<std::collections::HashSet<&'static str>> =
        LazyLock::new(|| crate::rules().into_iter().map(|r| r.id).collect());
    let end = ["*/", "-->", "%>", "*@"]
        .iter()
        .filter_map(|closer| after.find(closer))
        .min()
        .unwrap_or(after.len());
    let list = &after[..end];
    let list = match list.strip_prefix(':') {
        Some(rest) => rest,
        None if list.is_empty() || list.starts_with(char::is_whitespace) => list,
        None => return None,
    };
    let mut ids = Vec::new();
    let mut listed = false;
    for word in list
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
    {
        let (id, last) = match word.strip_suffix(['.', ';', ':']) {
            Some(id) => (id, true),
            None => (word, false),
        };
        if !looks_like_id(id) {
            break;
        }
        listed = true;
        if let Some(&known) = KNOWN.get(id) {
            ids.push(known);
        }
        if last {
            break;
        }
    }
    listed.then_some(ids)
}

/// `family.name` for one of the rule families, the name starting with a letter or digit and going
/// on with letters, digits, `_` or `-`. Case and a plural family (`Code.Eval`, `secrets.x`) still
/// look like an id, so such a typo covers nothing instead of silencing every rule.
fn looks_like_id(word: &str) -> bool {
    const FAMILIES: [Family; 6] = [
        Family::Code,
        Family::Secret,
        Family::Agent,
        Family::Mobile,
        Family::Config,
        Family::Dependency,
    ];
    let Some((family, name)) = word.split_once('.') else {
        return false;
    };
    let family = family.to_ascii_lowercase();
    let alnum = |c: char| c.is_ascii_alphanumeric();
    (family == "dependencies"
        || FAMILIES
            .iter()
            .any(|f| family == f.as_str() || family == format!("{}s", f.as_str())))
        && name.starts_with(alnum)
        && name.chars().all(|c| alnum(c) || c == '_' || c == '-')
}

pub struct Meta<'a> {
    pub id: &'a str,
    pub family: Family,
    pub severity: Severity,
    pub message: &'a str,
    pub fix: &'a str,
    pub secret: Option<&'a str>,
}

pub fn finding(file: &FileInfo, text: &Text, line: usize, meta: Meta) -> Finding {
    let raw = text.line(line).trim();
    let snippet = match meta.secret {
        // A name-only rule's "secret" is the rest of the line after the name: hide all of it
        // (operators and quotes too, as they can be part of the value), only at the line's end.
        Some(rest) if !rest.is_empty() && secrets::NAME_ONLY.contains(&meta.id) => {
            match raw.strip_suffix(rest) {
                Some(before) => shorten(&format!("{before}****")),
                // Not expected: the rest of the line should end the line. Print nothing of it.
                None => "****".to_string(),
            }
        }
        Some(secret) if !secret.is_empty() => shorten(&raw.replace(secret, &mask(secret))),
        _ => shorten(raw),
    };
    Finding::new(
        meta.id,
        meta.family,
        meta.severity,
        file.rel.clone(),
        line,
        meta.message.to_string(),
        meta.fix.to_string(),
        snippet,
    )
}

fn shorten(s: &str) -> String {
    if s.chars().count() > 160 {
        format!("{}…", s.chars().take(160).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Everything after a variable name on its own line, as the part to hide. The value may be
/// written in many ways (`=v`, `: v`, `=> 'v'`, `|| "v"`, `"] = "v"`, `ENV NAME v`), so all of
/// it is hidden rather than parsed. None when nothing is assigned: nothing follows, only `=` or
/// `:` with nothing after it (`NAME=`), or only closing punctuation without any `=` or `:`
/// (`NAME;`, `process.env.NAME)`, `env["NAME"]`).
fn after_name(rest: &str) -> Option<&str> {
    let tail = rest.lines().next().unwrap_or("").trim();
    let nothing = matches!(tail, "" | "=" | ":")
        || tail
            .chars()
            .all(|c| c.is_whitespace() || ";,)]}\"'`".contains(c));
    (!nothing).then_some(tail)
}

/// The secret with all but its start hidden. At most 4 characters are kept, and never more
/// than a third of the value, so a short password is not printed whole.
fn mask(secret: &str) -> String {
    let n = secret.chars().count();
    let keep: String = secret.chars().take(4.min(n / 3)).collect();
    format!("{keep}****")
}

pub fn check(file: &FileInfo, src: &str, include_tests: bool) -> Vec<Finding> {
    let text = Text::new(src);
    let test_file = !include_tests && file.is_test();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for c in RULES.iter() {
        if !(c.rule.files)(file) {
            continue;
        }
        if test_file && !(c.rule.family == Family::Secret && c.rule.severity == Severity::Critical)
        {
            continue;
        }
        for caps in c.re.captures_iter(src) {
            let m = caps.get(0).expect("whole match");
            // A name-only rule matches a variable name; what follows it on the line holds the
            // value. It is read only for the finding that is kept (one per rule and line), so a
            // long line with many names is not read again for each of them.
            let name_only = secrets::NAME_ONLY.contains(&c.rule.id);
            let secret = if c.rule.family != Family::Secret || name_only {
                None
            } else {
                Some(
                    caps.iter()
                        .skip(1)
                        .flatten()
                        .last()
                        .unwrap_or(m)
                        .as_str()
                        .lines()
                        .next()
                        .unwrap_or(""),
                )
            };
            let line = text.line_of(m.start());
            if text.suppressed(line, c.rule.id) {
                continue;
            }
            if c.rule.family == Family::Code
                && (is_comment(text.line(line)) || is_prose(text.line(line)))
            {
                continue;
            }
            if let Some(unless) = &c.unless
                && unless.is_match(text.line(line))
            {
                continue;
            }
            if !secrets::plausible(c.rule.id, secret, &src[m.end()..]) {
                continue;
            }
            if seen.insert((c.rule.id.to_string(), line)) {
                out.push(finding(
                    file,
                    &text,
                    line,
                    Meta {
                        id: c.rule.id,
                        family: c.rule.family,
                        severity: c.rule.severity,
                        message: c.rule.message,
                        fix: c.rule.fix,
                        secret: if name_only {
                            after_name(&src[m.end()..])
                        } else {
                            secret
                        },
                    },
                ));
            }
        }
    }
    let mut hcl = config::HclWalk::default();
    out.retain(|f| config::keep(file, &text, f, &mut hcl));
    for f in agent::structured(file, &text)
        .into_iter()
        .filter(|_| !test_file)
    {
        if !text.suppressed(f.line, &f.rule) && seen.insert((f.rule.clone(), f.line)) {
            out.push(f);
        }
    }
    out
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    ["//", "#", "/*", "* ", "--", "<!--"]
        .iter()
        .any(|p| t.starts_with(p))
        || t == "*"
}

fn is_prose(line: &str) -> bool {
    line.contains("**") || line.contains('⚠') || line.contains("\\b")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_marker_with_rule_ids() {
        let cases = [
            ("x // safe-anything:ignore", "code.eval", true),
            ("x <!-- safe-anything:ignore -->", "code.eval", true),
            ("x /* safe-anything:ignore*/", "code.eval", true),
            (
                "x /* safe-anything:ignore */ // see code.eval",
                "code.weak-hash",
                true,
            ),
            (
                "x // safe-anything:ignore false positive, reviewed",
                "code.eval",
                true,
            ),
            (
                "x // safe-anything:ignore not code.eval",
                "code.weak-hash",
                true,
            ),
            (
                "x // safe-anything:ignore - code.eval",
                "code.weak-hash",
                true,
            ),
            // A case or plural typo still looks like an id, so it covers nothing.
            ("x // safe-anything:ignore Code.Eval", "code.eval", false),
            (
                "x // safe-anything:ignore code.weakHash",
                "code.eval",
                false,
            ),
            (
                "x // safe-anything:ignore secrets.hardcoded-password",
                "secret.hardcoded-password",
                false,
            ),
            // ERB and Razor comment closers end the list.
            (
                "<%# safe-anything:ignore code.eval%><% eval(x) %>",
                "code.eval",
                true,
            ),
            (
                "<%# safe-anything:ignore code.eval%><% eval(x) %>",
                "code.weak-hash",
                false,
            ),
            ("@* safe-anything:ignore code.eval*@", "code.eval", true),
            (
                "x // uses safe-anything:ignore, code.eval is fine",
                "code.weak-hash",
                true,
            ),
            (
                "x // safe-anything:ignored code.eval",
                "code.weak-hash",
                true,
            ),
            ("x // safe-anything:ignorefoo", "code.eval", true),
            ("x // safe-anything:ignore code.eval", "code.eval", true),
            (
                "x // safe-anything:ignore code.eval",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore\tcode.eval",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore code.weak-hash,code.eval",
                "code.eval",
                true,
            ),
            (
                "x // safe-anything:ignore code.weak-hash, code.eval",
                "code.eval",
                true,
            ),
            (
                "x // safe-anything:ignore code.weak-hash code.eval",
                "code.weak-hash",
                true,
            ),
            (
                "x // safe-anything:ignore code.weak-hash code.eval",
                "secret.aws-access-key",
                false,
            ),
            ("x // safe-anything:ignore: code.eval", "code.eval", true),
            (
                "x // safe-anything:ignore: code.eval",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore:code.eval",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore code.weak-hash: checksum",
                "code.weak-hash",
                true,
            ),
            (
                "x // safe-anything:ignore code.weak-hash: checksum",
                "code.eval",
                false,
            ),
            (
                "x // safe-anything:ignore code.eval.",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore code.eval; code.weak-hash",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore code.eval - unlike secret.hardcoded-password this is safe",
                "code.eval",
                true,
            ),
            (
                "x // safe-anything:ignore code.eval - unlike secret.hardcoded-password this is safe",
                "secret.hardcoded-password",
                false,
            ),
            (
                "x // safe-anything:ignore code.eval reviewed by ü",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore code.eval — geprüft",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore secret.aws_access_key, code.eval",
                "code.eval",
                true,
            ),
            (
                "x // safe-anything:ignore secret.aws_access_key, code.eval",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore code.eval, secret.aws_access_key, code.weak-hash",
                "code.weak-hash",
                true,
            ),
            ("x /* safe-anything:ignore code.eval*/", "code.eval", true),
            (
                "x /* safe-anything:ignore code.eval*/",
                "code.weak-hash",
                false,
            ),
            (
                "x /* safe-anything:ignore code.eval */",
                "code.weak-hash",
                false,
            ),
            (
                "x /* safe-anything:ignore code.eval*/eval(y)",
                "code.eval",
                true,
            ),
            (
                "x /* safe-anything:ignore code.eval*/eval(y)",
                "code.weak-hash",
                false,
            ),
            (
                "x /* safe-anything:ignore code.eval*/ code.weak-hash",
                "code.weak-hash",
                false,
            ),
            (
                "x <!-- safe-anything:ignore code.xss-v-html--><div>",
                "code.xss-v-html",
                true,
            ),
            (
                "x <!-- safe-anything:ignore code.xss-v-html--><div>",
                "code.eval",
                false,
            ),
            (
                "x <!-- safe-anything:ignore code.xss-v-html -->",
                "code.eval",
                false,
            ),
            (
                "x // safe-anything:ignore code.weak-hashh",
                "code.weak-hash",
                false,
            ),
            (
                "x // safe-anything:ignore code.weak-hashh",
                "code.eval",
                false,
            ),
            ("x {/* safe-anything:ignore code.x*/}", "code.eval", false),
            (
                "x // safe-anything:ignore code.js is generated",
                "code.eval",
                false,
            ),
            (
                "x # safe-anything:ignore code.eval # safe-anything:ignore",
                "code.weak-hash",
                true,
            ),
            (
                "x # safe-anything:ignore code.eval safe-anything:ignore code.weak-hash",
                "code.weak-hash",
                true,
            ),
            (
                "x # safe-anything:ignore code.eval safe-anything:ignore code.weak-hash",
                "code.eval",
                true,
            ),
            (
                "x # safe-anything:ignore code.eval safe-anything:ignore code.weak-hash",
                "secret.aws-access-key",
                false,
            ),
            ("x // nothing to see", "code.eval", false),
        ];
        let wrong: Vec<_> = cases
            .iter()
            .filter(|&&(line, rule, want)| Cover::of(line).covers(rule) != want)
            .collect();
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn ignore_marker_on_the_line_above_with_rule_ids() {
        let text = Text::new("// safe-anything:ignore code.eval\nx\ny\n");
        assert!(!text.suppressed(1, "code.weak-hash"));
        assert!(text.suppressed(2, "code.eval"));
        assert!(!text.suppressed(2, "code.weak-hash"));
        assert!(!text.suppressed(3, "code.eval"));
    }

    #[test]
    fn ignore_rule_ids_in_an_mcp_config() {
        let src = r#"{
  "mcp": {
    "x": {
      "type": "local",
      // safe-anything:ignore agent.mcp-unpinned
      "command": ["npx", "-y", "some-mcp"],
      // safe-anything:ignore agent.mcp-unpinned
      "environment": { "API_TOKEN": "example-plaintext-value" }
    }
  }
}"#;
        let found: Vec<(usize, String)> = check(&FileInfo::new("opencode.jsonc"), src, false)
            .into_iter()
            .filter(|f| f.family == Family::Agent)
            .map(|f| (f.line, f.rule))
            .collect();
        assert_eq!(found, vec![(8, "agent.mcp-plaintext-secret".to_string())]);
    }
}
