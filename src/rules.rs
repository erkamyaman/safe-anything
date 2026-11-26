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

    fn trimmed_line_range(&self, n: usize) -> (usize, &'a str) {
        let full = self.line(n);
        let line_start = self.line_start(n);
        let trimmed_start = full.trim_start();
        let lead = full.len() - trimmed_start.len();
        let raw = trimmed_start.trim_end();
        (line_start + lead, raw)
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
}

pub fn finding(file: &FileInfo, text: &Text, line: usize, meta: Meta) -> Finding {
    let raw = text.line(line).trim();
    let raw = if secrets::ENV_VALUE_RULES.contains(&meta.id) {
        secrets::strip_env_comment(raw)
    } else {
        raw
    };
    Finding::new(
        meta.id,
        meta.family,
        meta.severity,
        file.rel.clone(),
        line,
        meta.message.to_string(),
        meta.fix.to_string(),
        shorten(raw),
    )
}

const SNIPPET_LIMIT: usize = 160;

fn shorten(s: &str) -> String {
    if s.chars().count() > SNIPPET_LIMIT {
        format!("{}…", s.chars().take(SNIPPET_LIMIT).collect::<String>())
    } else {
        s.to_string()
    }
}

/// A byte range within a trimmed line to hide in snippets. `keep_prefix` masks via `mask()`;
/// `false` hides the whole slice as `****`, used for name-only rules (`secret.public-env-secret`).
#[derive(Clone, Copy)]
struct Redact {
    start: usize,
    end: usize,
    keep_prefix: bool,
}

#[derive(Default)]
struct LineRedactions {
    spans: Vec<(usize, usize)>,
    tail_from: Option<usize>,
    tail_checked: bool,
    literals: std::collections::HashSet<String>,
}

impl LineRedactions {
    fn is_empty(&self) -> bool {
        self.spans.is_empty() && self.tail_from.is_none() && self.literals.is_empty()
    }
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn merge_spans(raw_len: usize, spans: &mut Vec<Redact>) {
    spans.retain(|s| s.start < s.end && s.end <= raw_len);
    spans.sort_unstable_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
    let mut write = 0;
    for read in 0..spans.len() {
        let s = spans[read];
        if write > 0 && s.start < spans[write - 1].end {
            spans[write - 1].end = spans[write - 1].end.max(s.end);
            spans[write - 1].keep_prefix = spans[write - 1].keep_prefix && s.keep_prefix;
        } else {
            spans[write] = s;
            write += 1;
        }
    }
    spans.truncate(write);
}

/// Render up to `SNIPPET_LIMIT` characters from `raw`, pulling spans from `rest` (stored in
/// reverse start order) into `active` as needed. Returns the snippet and the plain-text byte
/// ranges of `raw` that were emitted unmasked.
fn render_step(
    raw: &str,
    active: &mut Vec<Redact>,
    rest: &mut Vec<Redact>,
    short_needles: &[&str],
) -> (String, Vec<(usize, usize)>) {
    let mut out = String::with_capacity(raw.len().min(SNIPPET_LIMIT + 4));
    let mut gaps: Vec<(usize, usize)> = Vec::new();
    let mut count = 0;
    let mut pos = 0;
    let mut idx = 0;

    loop {
        let s = if idx < active.len() {
            let s = active[idx];
            idx += 1;
            Some(s)
        } else if let Some(s) = rest.pop() {
            active.push(s);
            idx += 1;
            Some(s)
        } else {
            None
        };

        let gap_end = s.map_or(raw.len(), |s| s.start);
        if pos < gap_end {
            let mut emitted_end = gap_end;
            let mut hit_limit = false;
            for (rel, ch) in raw[pos..gap_end].char_indices() {
                if count == SNIPPET_LIMIT {
                    out.push('…');
                    emitted_end = pos + rel;
                    hit_limit = true;
                    break;
                }
                out.push(ch);
                count += 1;
            }
            if pos < emitted_end {
                gaps.push((pos, emitted_end));
            }
            if hit_limit {
                return (out, gaps);
            }
        }

        let Some(s) = s else {
            return (out, gaps);
        };
        let replacement = if s.keep_prefix {
            mask(&raw[s.start..s.end], short_needles)
        } else {
            "****".to_string()
        };
        for ch in replacement.chars() {
            if count == SNIPPET_LIMIT {
                out.push('…');
                return (out, gaps);
            }
            out.push(ch);
            count += 1;
        }
        pos = s.end;
    }
}

fn parse_json_escape(slice: &str, i: usize) -> Option<(char, usize)> {
    let b = slice.as_bytes();
    let next = *b.get(i + 1)?;
    let simple = match next {
        b'"' => Some('"'),
        b'\\' => Some('\\'),
        b'/' => Some('/'),
        b'b' => Some('\x08'),
        b'f' => Some('\x0c'),
        b'n' => Some('\n'),
        b'r' => Some('\r'),
        b't' => Some('\t'),
        _ => None,
    };
    if let Some(ch) = simple {
        return Some((ch, 2));
    }
    if next != b'u' {
        return None;
    }
    let hex1 = slice.get(i + 2..i + 6)?;
    let u1 = u16::from_str_radix(hex1, 16).ok()?;
    if (0xD800..=0xDBFF).contains(&u1)
        && slice.get(i + 6..i + 8) == Some(r"\u")
        && let Some(hex2) = slice.get(i + 8..i + 12)
        && let Ok(u2) = u16::from_str_radix(hex2, 16)
        && (0xDC00..=0xDFFF).contains(&u2)
    {
        let cp = 0x10000 + (((u1 as u32 - 0xD800) << 10) | (u2 as u32 - 0xDC00));
        return char::from_u32(cp).map(|ch| (ch, 12));
    }
    char::from_u32(u1 as u32).map(|ch| (ch, 6))
}

/// Decode JSON escape sequences in `slice`, returning the decoded string along with the source
/// byte range `[raw_starts[d], raw_ends[d])` in `slice` that produced each decoded byte `d`.
fn decode_json_escapes(slice: &str) -> (String, Vec<usize>, Vec<usize>) {
    let b = slice.as_bytes();
    let mut decoded = String::with_capacity(slice.len());
    let mut raw_starts = Vec::with_capacity(slice.len());
    let mut raw_ends = Vec::with_capacity(slice.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && let Some((ch, esc_len)) = parse_json_escape(slice, i)
        {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            decoded.push_str(s);
            for _ in 0..s.len() {
                raw_starts.push(i);
                raw_ends.push(i + esc_len);
            }
            i += esc_len;
            continue;
        }
        let ch = slice[i..].chars().next().unwrap();
        let clen = ch.len_utf8();
        decoded.push(ch);
        for _ in 0..clen {
            raw_starts.push(i);
            raw_ends.push(i + clen);
        }
        i += clen;
    }
    (decoded, raw_starts, raw_ends)
}

/// Apply every redaction recorded for one line, also masking any repeated copies (including
/// JSON-escaped spellings such as `\/` or `\uXXXX`) that touch a rendered plain-text gap in the
/// 160-character snippet.
fn render_redacted_line(raw: &str, raw_start: usize, lr: &LineRedactions) -> String {
    const MAX_ROUNDS: usize = 8;
    let raw_end = raw_start + raw.len();
    let mut initial: Vec<Redact> =
        Vec::with_capacity(lr.spans.len() + usize::from(lr.tail_from.is_some()));
    let mut needles: Vec<&str> = Vec::new();
    let mut seen_needles: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for &(abs_start, abs_end) in &lr.spans {
        let start = abs_start.clamp(raw_start, raw_end) - raw_start;
        let end = abs_end.clamp(raw_start, raw_end) - raw_start;
        if start < end {
            initial.push(Redact {
                start,
                end,
                keep_prefix: true,
            });
            let slice = &raw[start..end];
            if seen_needles.insert(slice) {
                needles.push(slice);
            }
        }
    }
    if let Some(tail_abs) = lr.tail_from {
        let start = tail_abs.clamp(raw_start, raw_end) - raw_start;
        if start < raw.len() {
            initial.push(Redact {
                start,
                end: raw.len(),
                keep_prefix: false,
            });
        }
    }
    for lit in &lr.literals {
        if !lit.is_empty() && seen_needles.insert(lit.as_str()) {
            needles.push(lit.as_str());
        }
    }
    let max_esc_pad = needles.iter().map(|n| n.len()).max().unwrap_or(0).min(512) * 6;
    let short_needles: Vec<&str> = needles
        .iter()
        .copied()
        .filter(|n| !n.is_empty() && n.chars().take(5).count() <= 4)
        .collect();

    merge_spans(raw.len(), &mut initial);
    initial.reverse();
    let mut rest = initial;
    let mut active: Vec<Redact> = Vec::new();
    let mut checked_end = 0usize;

    for round in 0..MAX_ROUNDS {
        let (snippet, gaps) = render_step(raw, &mut active, &mut rest, &short_needles);
        let new_gaps: Vec<(usize, usize)> = gaps
            .into_iter()
            .filter_map(|(s, e)| {
                let s = s.max(checked_end);
                (s < e).then_some((s, e))
            })
            .collect();
        if new_gaps.is_empty() {
            return snippet;
        }
        let mut new_spans: Vec<Redact> = Vec::new();
        for &needle in &needles {
            if needle.is_empty() {
                continue;
            }
            let pad = needle.len() - 1;
            for &(g_start, g_end) in &new_gaps {
                let win_start = ceil_char_boundary(raw, g_start.saturating_sub(pad));
                let win_end = ceil_char_boundary(raw, g_end.saturating_add(pad));
                for (rel, _) in raw[win_start..win_end].match_indices(needle) {
                    let idx = win_start + rel;
                    let end = idx + needle.len();
                    if idx < g_end && end > g_start {
                        new_spans.push(Redact {
                            start: idx,
                            end,
                            keep_prefix: true,
                        });
                    }
                }
            }
        }
        if max_esc_pad > 0 {
            for &(g_start, g_end) in &new_gaps {
                let scan_start = ceil_char_boundary(raw, g_start.saturating_sub(max_esc_pad));
                let scan_end = ceil_char_boundary(raw, g_end.saturating_add(max_esc_pad));
                let window = &raw[scan_start..scan_end];
                if !window.contains('\\') {
                    continue;
                }
                let (decoded, raw_starts, raw_ends) = decode_json_escapes(window);
                for &needle in &needles {
                    if needle.is_empty() {
                        continue;
                    }
                    for (d_idx, _) in decoded.match_indices(needle) {
                        let idx = scan_start + raw_starts[d_idx];
                        let end = scan_start + raw_ends[d_idx + needle.len() - 1];
                        if idx < g_end && end > g_start {
                            new_spans.push(Redact {
                                start: idx,
                                end,
                                keep_prefix: true,
                            });
                        }
                    }
                }
            }
        }
        if new_spans.is_empty() {
            return snippet;
        }
        let min_new_start = new_spans.iter().map(|s| s.start).min().unwrap_or(0);
        let max_new_end = new_spans.iter().map(|s| s.end).max().unwrap_or(0);
        checked_end = checked_end.max(min_new_start);
        while rest.last().is_some_and(|s| s.start < max_new_end) {
            active.push(rest.pop().unwrap());
        }
        active.extend(new_spans);
        merge_spans(raw.len(), &mut active);

        if round + 1 == MAX_ROUNDS {
            // Everything before `checked_end` is already clean, and any span covering
            // `checked_end` is masked through its end; stop there so no unchecked gap prints.
            let safe_end = active
                .iter()
                .find(|s| s.start <= checked_end && checked_end < s.end)
                .map_or(checked_end, |s| s.end)
                .min(raw.len());
            let mut clamped: Vec<Redact> = active
                .into_iter()
                .filter_map(|s| {
                    let end = s.end.min(safe_end);
                    (s.start < end).then_some(Redact { end, ..s })
                })
                .collect();
            let mut empty = Vec::new();
            let (mut out, _) =
                render_step(&raw[..safe_end], &mut clamped, &mut empty, &short_needles);
            if safe_end < raw.len() && !out.ends_with('…') {
                out.push('…');
            }
            return out;
        }
    }
    unreachable!("MAX_ROUNDS > 0")
}

/// Absolute byte offset where the non-empty tail after a variable name starts on its line, or
/// `None` when nothing is assigned: nothing follows, only `=` or `:` with nothing after it
/// (`NAME=`), or only closing punctuation without any `=` or `:` (`NAME;`, `process.env.NAME)`,
/// `env["NAME"]`).
fn after_name_offset(src: &str, after_pos: usize) -> Option<usize> {
    let line_rest = src[after_pos..].lines().next().unwrap_or("");
    let trimmed_start = line_rest.trim_start();
    let tail = trimmed_start.trim_end();
    let nothing = matches!(tail, "" | "=" | ":")
        || tail
            .chars()
            .all(|c| c.is_whitespace() || ";,)]}\"'`".contains(c));
    (!nothing).then_some(after_pos + (line_rest.len() - trimmed_start.len()))
}

/// The secret with all but its start hidden. At most 4 characters are kept, and never more
/// than a third of the value, so a short password is not printed whole. If keeping that prefix
/// would expose another short secret recorded on the same line, drop the prefix.
fn mask(secret: &str, short_needles: &[&str]) -> String {
    let n = secret.chars().take(12).count();
    let keep: String = secret.chars().take(4.min(n / 3)).collect();
    if !keep.is_empty() && short_needles.iter().any(|s| keep.contains(s)) {
        return "****".to_string();
    }
    format!("{keep}****")
}

pub fn check(file: &FileInfo, src: &str, include_tests: bool) -> Vec<Finding> {
    let text = Text::new(src);
    let test_file = !include_tests && file.is_test();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut redactions: HashMap<usize, LineRedactions> = HashMap::new();
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
            // value. It is read at most once per line, so a long line with many names is not read
            // again for each of them.
            let name_only = secrets::NAME_ONLY.contains(&c.rule.id);
            let secret_match = if c.rule.family != Family::Secret || name_only {
                None
            } else {
                Some(caps.iter().skip(1).flatten().last().unwrap_or(m))
            };
            let secret = secret_match.map(|sm| sm.as_str().lines().next().unwrap_or(""));
            let line = text.line_of(m.start());
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
            // Record secret spans before suppression so an ignore marker silences the finding
            // without letting another finding on the same line print the secret in full.
            if let (Some(sm), Some(first_line)) = (secret_match, secret)
                && !first_line.is_empty()
            {
                let secret_line = text.line_of(sm.start());
                redactions
                    .entry(secret_line)
                    .or_default()
                    .spans
                    .push((sm.start(), sm.start() + first_line.len()));
                if secret_line != line {
                    redactions
                        .entry(line)
                        .or_default()
                        .literals
                        .insert(first_line.to_string());
                }
            }
            if name_only {
                let entry = redactions.entry(line).or_default();
                if !entry.tail_checked {
                    entry.tail_checked = true;
                    entry.tail_from = after_name_offset(src, m.end());
                }
            }
            if text.suppressed(line, c.rule.id) {
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
                    },
                ));
            }
        }
    }
    let mut hcl = config::HclWalk::default();
    out.retain(|f| config::keep(file, &text, f, &mut hcl));
    if !test_file {
        for (f, secret) in agent::structured(file, &text) {
            if let Some(secret) = secret {
                let mut value_line = None;
                if let Some((start, end)) = secret.span
                    && start < end
                {
                    let secret_line = text.line_of(start);
                    value_line = Some(secret_line);
                    redactions
                        .entry(secret_line)
                        .or_default()
                        .spans
                        .push((start, end));
                    if secret_line != f.line {
                        let raw_val = text.src[start..end].lines().next().unwrap_or("");
                        if !raw_val.is_empty() {
                            redactions
                                .entry(f.line)
                                .or_default()
                                .literals
                                .insert(raw_val.to_string());
                        }
                    }
                }
                if !secret.literal.is_empty() {
                    if let Some(secret_line) = value_line
                        && secret_line != f.line
                    {
                        redactions
                            .entry(secret_line)
                            .or_default()
                            .literals
                            .insert(secret.literal.clone());
                    }
                    redactions
                        .entry(f.line)
                        .or_default()
                        .literals
                        .insert(secret.literal);
                }
            }
            if !text.suppressed(f.line, &f.rule) && seen.insert((f.rule.clone(), f.line)) {
                out.push(f);
            }
        }
    }
    if !redactions.is_empty() {
        let mut rendered: HashMap<(usize, bool), String> = HashMap::new();
        for f in &mut out {
            if let Some(lr) = redactions.get(&f.line)
                && !lr.is_empty()
            {
                let strip_comment = secrets::ENV_VALUE_RULES.contains(&f.rule.as_str());
                let snippet = rendered.entry((f.line, strip_comment)).or_insert_with(|| {
                    let (raw_start, raw) = text.trimmed_line_range(f.line);
                    let raw = if strip_comment {
                        secrets::strip_env_comment(raw)
                    } else {
                        raw
                    };
                    render_redacted_line(raw, raw_start, lr)
                });
                f.snippet.clone_from(snippet);
            }
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

    #[test]
    fn multiple_secrets_on_one_line_are_all_masked() {
        let gh1 = ["gh", "p_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"].concat();
        let gh2 = ["gh", "p_", "9876543210ZyXwVuTsRqPoNmLkJiHgFeDcBa"].concat();
        let aws = ["AK", "IA", "IOSFODNN7ABCDEFG"].concat();
        let pass = ["Sup3r", "S3cr3t", "Pass99"].concat();
        let mcp1 = ["FirstMcp", "Plaintext", "Token11"].concat();
        let mcp2 = ["SecondMcp", "Plaintext", "Secret22"].concat();

        // Two tokens matching the same rule on one line.
        let same_rule = format!("const keys = [\"{gh1}\", \"{gh2}\"];\n");
        let found = check(&FileInfo::new("app.js"), &same_rule, false);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].snippet,
            "const keys = [\"ghp_****\", \"ghp_****\"];"
        );

        // Two tokens matching different secret rules on one line.
        let diff_rules = format!("{{\"aws\": \"{aws}\", \"gh\": \"{gh1}\"}}\n");
        let found = check(&FileInfo::new("cfg.json"), &diff_rules, false);
        assert_eq!(found.len(), 2);
        for f in &found {
            assert_eq!(f.snippet, "{\"aws\": \"AKIA****\", \"gh\": \"ghp_****\"}");
        }

        // A secret and a non-secret code rule on the same line.
        let with_code = format!("eval(\"{gh1}\");\n");
        let found = check(&FileInfo::new("app.js"), &with_code, false);
        assert!(found.iter().any(|f| f.rule == "code.eval"));
        assert!(found.iter().any(|f| f.rule == "secret.github-token"));
        for f in &found {
            assert!(
                !f.snippet.contains(&gh1[4..]),
                "leaked in {}: {}",
                f.rule,
                f.snippet
            );
            assert_eq!(f.snippet, "eval(\"ghp_****\");");
        }

        // A regular secret before a name-only public env secret on the same line.
        let pub_pw = ["VITE", "_ADMIN_PASSWORD"].concat();
        let before_public = format!("const t = \"{gh1}\"; {pub_pw}={pass}\n");
        let found = check(&FileInfo::new("app.js"), &before_public, false);
        assert_eq!(found.len(), 2);
        for f in &found {
            assert_eq!(f.snippet, format!("const t = \"ghp_****\"; {pub_pw}****"));
        }

        // Overlapping name-only tail and token value keeps the stricter hide-all mask.
        let pub_sec = ["VITE", "_ADMIN_SECRET"].concat();
        let overlap_public = format!("{pub_sec}=\"{gh1}\"\n");
        let found = check(&FileInfo::new("app.js"), &overlap_public, false);
        assert_eq!(found.len(), 2);
        for f in &found {
            assert_eq!(f.snippet, format!("{pub_sec}****"));
        }

        // Overlapping URL credential and GitHub token merges cleanly without leaking either.
        let url = format!(
            "const u = \"{}admin:{gh1}@git.internal/repo\";\n",
            "https://"
        );
        let found = check(&FileInfo::new("app.js"), &url, false);
        assert_eq!(found.len(), 2);
        for f in &found {
            assert!(
                !f.snippet.contains(&gh1[4..]),
                "leaked in {}: {}",
                f.rule,
                f.snippet
            );
            assert!(
                !f.snippet.contains("admin"),
                "user leaked in {}: {}",
                f.rule,
                f.snippet
            );
        }

        // Repeated occurrence of the same password on one line is also masked.
        let masked_pass = "Sup3****";
        let repeated = format!("password = \"{pass}\"; log(\"{pass}\");\n");
        let found = check(&FileInfo::new("app.js"), &repeated, false);
        assert_eq!(found.len(), 1);
        assert!(!found[0].snippet.contains(&pass));
        assert_eq!(
            found[0].snippet,
            format!("password = \"{masked_pass}\"; log(\"{masked_pass}\");")
        );

        // Single-line MCP config with two plaintext secrets and an unpinned command.
        let mcp_json = format!(
            "{{\"mcpServers\":{{\"s\":{{\"command\":\"npx\",\"args\":[\"-y\",\"pkg\"],\"env\":{{\"API_TOKEN\":\"{mcp1}\",\"DB_PASSWORD\":\"{mcp2}\"}}}}}}}}\n"
        );
        let found = check(&FileInfo::new(".mcp.json"), &mcp_json, false);
        assert!(found.iter().any(|f| f.rule == "agent.mcp-unpinned"));
        assert!(found.iter().any(|f| f.rule == "agent.mcp-plaintext-secret"));
        for f in &found {
            assert!(
                !f.snippet.contains(&mcp1[4..]),
                "mcp1 leaked in {}: {}",
                f.rule,
                f.snippet
            );
            assert!(
                !f.snippet.contains(&mcp2[4..]),
                "mcp2 leaked in {}: {}",
                f.rule,
                f.snippet
            );
        }

        // Long line over 4096 bytes with an unmatched copy of the secret before the match.
        let padding = " ".repeat(12_000);
        let long_line = format!("login(\"{pass}\");var cfg={{password:\"{pass}\"}};{padding}x\n");
        let found = check(&FileInfo::new("app.js"), &long_line, false);
        assert_eq!(found.len(), 1);
        assert!(!found[0].snippet.contains(&pass));
        let want_long = format!("login(\"{masked_pass}\");var cfg={{password:\"{masked_pass}\"}};");
        assert!(
            found[0].snippet.starts_with(&want_long),
            "unexpected snippet: {}",
            found[0].snippet
        );

        // Suppressed secret still stays masked in another finding on the same line.
        let suppressed_code =
            format!("eval(x); const t = \"{gh1}\"; // safe-anything:ignore secret.github-token\n");
        let found = check(&FileInfo::new("app.js"), &suppressed_code, false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "code.eval");
        assert!(!found[0].snippet.contains(&gh1[4..]));
        assert!(found[0].snippet.contains("ghp_****"));

        // Suppressed MCP secret stays masked in agent.mcp-unpinned on the same line.
        let suppressed_mcp = format!(
            "// safe-anything:ignore agent.mcp-plaintext-secret\n{{\"mcpServers\":{{\"s\":{{\"command\":\"npx\",\"args\":[\"-y\",\"pkg\"],\"env\":{{\"API_TOKEN\":\"{mcp1}\"}}}}}}}}\n"
        );
        let found = check(&FileInfo::new("opencode.jsonc"), &suppressed_mcp, false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "agent.mcp-unpinned");
        assert!(!found[0].snippet.contains(&mcp1[4..]));

        // MCP values with JSON escapes (\/, \uXXXX, \u001F, \") and escaped keys stay masked.
        let escaped_raw = [r"tok\/", r"\u004d", r"\u00e9", r"\u001F", "Tail99"].concat();
        let escaped_mcp = format!(
            "{{\"mcpServers\":{{\"s\":{{\"command\":\"npx\",\"args\":[\"-y\",\"pkg\"],\"env\":{{\"\\u0041PI_TOKEN\":\"{escaped_raw}\"}}}}}}}}\n"
        );
        let found = check(&FileInfo::new(".mcp.json"), &escaped_mcp, false);
        assert!(found.iter().any(|f| f.rule == "agent.mcp-plaintext-secret"));
        assert!(found.iter().any(|f| f.rule == "agent.mcp-unpinned"));
        for f in &found {
            assert!(
                !f.snippet.contains("Tail99"),
                "escaped MCP secret leaked in {}: {}",
                f.rule,
                f.snippet
            );
        }

        // MCP value on the line after its key is masked on the value's line too.
        let split_mcp = format!(
            "{{\n  \"mcpServers\": {{\n    \"s\": {{\n      \"env\": {{\n        \"API_TOKEN\":\n          \"{mcp1}\" // {gh1}\n      }}\n    }}\n  }}\n}}\n"
        );
        let found = check(&FileInfo::new("opencode.jsonc"), &split_mcp, false);
        for f in &found {
            assert!(
                !f.snippet.contains(&mcp1[4..]),
                "split-line MCP value leaked in {}: {}",
                f.rule,
                f.snippet
            );
            assert!(
                !f.snippet.contains(&gh1[4..]),
                "gh1 leaked in {}: {}",
                f.rule,
                f.snippet
            );
        }

        // CRLF line endings and multi-byte UTF-8 text around secrets render cleanly.
        let utf8_crlf =
            format!("  // ümlaut 日本語\r\n  const x = \"é {gh1} é\", y = \"ñ {aws} ñ\";\r\n");
        let found = check(&FileInfo::new("app.js"), &utf8_crlf, false);
        assert_eq!(found.len(), 2);
        for f in &found {
            assert_eq!(
                f.snippet,
                "const x = \"é ghp_**** é\", y = \"ñ AKIA**** ñ\";"
            );
        }

        // Many repeated matches on one line stay fast and bounded without leaking.
        let many = format!("{}\n", vec![aws.as_str(); 500].join(" "));
        let found = check(&FileInfo::new("keys.txt"), &many, false);
        assert_eq!(found.len(), 1);
        assert!(!found[0].snippet.contains(&aws[4..]));

        // Duplicate MCP key on one line masks the real value without clobbering the placeholder.
        let dup_mcp = format!(
            "{{\"mcpServers\":{{\"s\":{{\"env\":{{\"API_TOKEN\":\"${{API_TOKEN}}\",\"API_TOKEN\":\"{mcp1}\"}}}}}}}}\n"
        );
        let found = check(&FileInfo::new(".mcp.json"), &dup_mcp, false);
        assert_eq!(found.len(), 1);
        assert!(!found[0].snippet.contains(&mcp1[4..]));
        assert!(found[0].snippet.contains("${API_TOKEN}"));

        // MCP value on the next line also masks a plain copy on the key line.
        let split_copy_mcp = format!(
            "{{\"mcpServers\":{{\"s\":{{\"args\":[\"--t={mcp1}\"],\"env\":{{\"API_TOKEN\":\n\"{mcp1}\"}}}}}}}}\n"
        );
        let found = check(&FileInfo::new(".mcp.json"), &split_copy_mcp, false);
        assert_eq!(found.len(), 1);
        assert!(!found[0].snippet.contains(&mcp1[4..]));

        // Escaped MCP value in env and plain copy in args on one line are both masked.
        let esc_val_raw = [r"esc\/", "PlainCopy99"].concat();
        let esc_val_plain = ["esc/", "PlainCopy99"].concat();
        let mixed_esc_mcp = format!(
            "{{\"mcpServers\":{{\"s\":{{\"args\":[\"--t={esc_val_plain}\"],\"env\":{{\"API_TOKEN\":\"{esc_val_raw}\"}}}}}}}}\n"
        );
        let found = check(&FileInfo::new(".mcp.json"), &mixed_esc_mcp, false);
        assert_eq!(found.len(), 1);
        assert!(!found[0].snippet.contains("PlainCopy99"));

        // Plain MCP value in env and JSON-escaped (\/ or \uXXXX) copy in args on one line.
        let tok_plain = ["tok/", "enSecret99"].concat();
        let tok_slash = [r"tok\/", "enSecret99"].concat();
        let tok_uni = [r"tok\u002f", "enSecret99"].concat();
        for arg_copy in [&tok_slash, &tok_uni] {
            let escaped_arg_mcp = format!(
                "{{\"mcpServers\":{{\"s\":{{\"command\":\"npx\",\"args\":[\"-y\",\"pkg\",\"--t={arg_copy}\"],\"env\":{{\"API_TOKEN\":\"{tok_plain}\"}}}}}}}}\n"
            );
            let found = check(&FileInfo::new(".mcp.json"), &escaped_arg_mcp, false);
            assert!(found.iter().any(|f| f.rule == "agent.mcp-unpinned"));
            assert!(found.iter().any(|f| f.rule == "agent.mcp-plaintext-secret"));
            for f in &found {
                assert!(
                    !f.snippet.contains("enSecret99"),
                    "JSON-escaped copy leaked in {}: {}",
                    f.rule,
                    f.snippet
                );
            }
        }

        // A longer secret's 4-char mask prefix must not expose a shorter multi-byte secret on the same line.
        let short_mb = ["日", "本", "語"].concat();
        let long_mb = format!("{short_mb}ABCDEFGHIJ");
        let prefix_leak_mcp = format!(
            "{{\"mcpServers\":{{\"s\":{{\"env\":{{\"API_TOKEN\":\"{short_mb}\",\"DB_PASSWORD\":\"{long_mb}\"}}}}}}}}\n"
        );
        let found = check(&FileInfo::new(".mcp.json"), &prefix_leak_mcp, false);
        assert_eq!(found.len(), 1);
        assert!(
            !found[0].snippet.contains(&short_mb),
            "short multi-byte secret leaked via another secret's prefix: {}",
            found[0].snippet
        );

        // Multi-line password assignment also masks a copy on the assignment's first line.
        let multiline_pw = format!("log(\"{pass}\"); password =\n  \"{pass}\";\n");
        let found = check(&FileInfo::new("app.js"), &multiline_pw, false);
        assert_eq!(found.len(), 1);
        assert!(!found[0].snippet.contains(&pass));
        assert!(found[0].snippet.contains("Sup3****"));

        // Many distinct tokens behind a public-env name stay fast and masked.
        let distinct_tokens: String = (0..1000)
            .map(|i| format!(" {}{:016}", ["AK", "IA"].concat(), i))
            .collect();
        let pub_many = format!("{pub_pw}=x{distinct_tokens}\n");
        let found = check(&FileInfo::new("app.js"), &pub_many, false);
        assert!(found.iter().any(|f| f.rule == "secret.public-env-secret"));
        for f in &found {
            assert_eq!(f.snippet, format!("{pub_pw}****"));
        }

        // Split-line escaped MCP value masks both plain copy on value line and escaped copy on key line.
        let split_esc_val_line = format!(
            "{{\"mcpServers\":{{\"s\":{{\"command\":\"npx\",\"env\":{{\"API_TOKEN\":\n\"{esc_val_raw}\"}},\"args\":[\"-y\",\"pkg\",\"--t={esc_val_plain}\"]}}}}}}\n"
        );
        let found = check(&FileInfo::new(".mcp.json"), &split_esc_val_line, false);
        assert!(found.iter().any(|f| f.rule == "agent.mcp-unpinned"));
        for f in &found {
            assert!(
                !f.snippet.contains("PlainCopy99"),
                "leaked in {}: {}",
                f.rule,
                f.snippet
            );
        }

        let split_esc_key_line = format!(
            "{{\"mcpServers\":{{\"s\":{{\"args\":[\"--t={esc_val_raw}\"],\"env\":{{\"API_TOKEN\":\n\"{esc_val_raw}\"}}}}}}}}\n"
        );
        let found = check(&FileInfo::new(".mcp.json"), &split_esc_key_line, false);
        assert_eq!(found.len(), 1);
        assert!(!found[0].snippet.contains("PlainCopy99"));

        // Overlapping copies of a secret starting with a multi-byte character are fully masked.
        let mb_pw = ["éABCDE", "FGHIJKé"].concat();
        let mb_overlap = format!("password=\"{mb_pw}\"; x = \"{}ABCDEFGHIJKé\";\n", mb_pw);
        let found = check(&FileInfo::new("app.js"), &mb_overlap, false);
        assert_eq!(found.len(), 1);
        assert!(
            !found[0].snippet.contains("FGHIJK"),
            "multi-byte overlap leaked: {}",
            found[0].snippet
        );

        // Repeating overlapping password followed by many distinct keys stays fast and masked.
        let rep_pw = ["abab", "ababa"].concat();
        let rep_keys: String = (0..10_000)
            .map(|i| format!(" {}{:016}", ["AK", "IA"].concat(), i))
            .collect();
        let rep_line = format!("password=\"{rep_pw}\"; {}{rep_keys}\n", "ab".repeat(50_000));
        let found = check(&FileInfo::new("app.js"), &rep_line, false);
        assert!(!found.is_empty());
        for f in &found {
            assert!(
                !f.snippet.contains(&rep_pw),
                "repeating password leaked in {}: {}",
                f.rule,
                f.snippet
            );
        }
    }

    #[test]
    fn render_redacted_line_respects_snippet_limit() {
        let exact = "a".repeat(SNIPPET_LIMIT);
        assert_eq!(
            render_redacted_line(&exact, 0, &LineRedactions::default()),
            exact
        );
        let over = "a".repeat(SNIPPET_LIMIT + 1);
        assert_eq!(
            render_redacted_line(&over, 0, &LineRedactions::default()),
            format!("{exact}…")
        );

        // Secret starting right near the 160-char boundary never leaks raw tail characters.
        let prefix = "x".repeat(SNIPPET_LIMIT - 2);
        let secret = ["Sup3r", "S3cr3t", "BoundaryVal"].concat();
        let line = format!("{prefix}{secret}");
        let lr = LineRedactions {
            spans: vec![(prefix.len(), line.len())],
            ..LineRedactions::default()
        };
        let out = render_redacted_line(&line, 0, &lr);
        assert_eq!(out, format!("{prefix}Su…"));
        assert!(!out.contains(&secret[4..]));
    }
}
