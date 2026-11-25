use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::rules::FileInfo;
use crate::{Family, Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
    pub fixed: Option<String>,
}

pub trait Advisories: Send + Sync {
    fn lookup(&self, packages: &[Package]) -> Result<HashMap<usize, Vec<Advisory>>, String>;
}

fn pkg(eco: &str, name: &str, version: &str, file: &FileInfo, line: usize) -> Package {
    Package {
        ecosystem: eco.to_string(),
        name: name.to_string(),
        version: version.trim_start_matches(['v', '=']).to_string(),
        path: file.rel.clone(),
        line,
    }
}

pub fn parse_lockfile(file: &FileInfo, text: &str) -> Vec<Package> {
    match file.name.as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => npm_lock(file, text),
        "yarn.lock" => yarn_lock(file, text),
        "pnpm-lock.yaml" => pnpm_lock(file, text),
        "cargo.lock" => toml_packages(file, text, "crates.io", true),
        "poetry.lock" | "uv.lock" | "pdm.lock" => toml_packages(file, text, "PyPI", false),
        "go.mod" => go_mod(file, text),
        "gemfile.lock" => gemfile_lock(file, text),
        "composer.lock" => composer_lock(file, text),
        "pubspec.lock" => pubspec_lock(file, text),
        n if n.starts_with("requirements") && n.ends_with(".txt") => requirements(file, text),
        _ => Vec::new(),
    }
}

fn npm_lock(file: &FileInfo, text: &str) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = 0;
    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        for (key, p) in packages {
            let Some(name) = key.rsplit_once("node_modules/").map(|(_, n)| n) else {
                continue;
            };
            if p.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let Some(version) = p.get("version").and_then(Value::as_str) else {
                continue;
            };
            let at = find_from(text, &mut cursor, &format!("\"{key}\""));
            let line = line_of(text, find_after(text, at, "\"version\""));
            out.push(pkg("npm", name, version, file, line));
        }
    } else if let Some(deps) = json.get("dependencies").and_then(Value::as_object) {
        for (name, p) in deps {
            if let Some(version) = p.get("version").and_then(Value::as_str) {
                let at = find_from(text, &mut cursor, &format!("\"{name}\""));
                out.push(pkg("npm", name, version, file, line_of(text, at)));
            }
        }
    }
    out
}

fn yarn_lock(file: &FileInfo, text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        if !line.starts_with(' ') && line.ends_with(':') && !line.starts_with('#') {
            let first = line
                .trim_end_matches(':')
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            // A workspace, link, portal or file descriptor (e.g. `my-app@workspace:.`) is not a
            // package fetched from the registry. Its `version` is a local placeholder like
            // `0.0-0-use.local`, and sending the name to OSV can match an unrelated public
            // package. `npm_lock` already skips `link: true`; do the same here.
            let local = ["@workspace:", "@link:", "@portal:", "@file:"]
                .iter()
                .any(|sep| first.contains(sep));
            current = if local {
                None
            } else {
                first
                    .rfind('@')
                    .filter(|&i| i > 0)
                    .map(|i| first[..i].to_string())
            };
        } else if let (Some(name), Some(v)) = (&current, line.trim().strip_prefix("version ")) {
            out.push(pkg("npm", name, v.trim_matches('"'), file, i + 1));
            current = None;
        } else if let (Some(name), Some(v)) = (&current, line.trim().strip_prefix("version: ")) {
            out.push(pkg("npm", name, v.trim_matches('"'), file, i + 1));
            current = None;
        }
    }
    out
}

fn pnpm_lock(file: &FileInfo, text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_packages = false;
    for (i, line) in text.lines().enumerate() {
        // pnpm puts a blank line after `packages:` and between entries; it does not end the section.
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            in_packages = line.starts_with("packages:");
            continue;
        }
        if !in_packages || line.starts_with("    ") {
            continue;
        }
        let key = line
            .trim()
            .trim_end_matches(':')
            .trim_matches(['\'', '"'])
            .trim_start_matches('/');
        let key = key.split('(').next().unwrap_or(key);
        if let Some(at) = key.rfind('@').filter(|&a| a > 0) {
            out.push(pkg("npm", &key[..at], &key[at + 1..], file, i + 1));
        }
    }
    out
}

fn toml_packages(file: &FileInfo, text: &str, eco: &str, need_source: bool) -> Vec<Package> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "[[package]]" {
            let (mut name, mut version, mut vline, mut source, mut local) =
                (None, None, 0, false, false);
            let mut j = i + 1;
            while j < lines.len() && !lines[j].trim_start().starts_with('[') {
                let l = lines[j].trim();
                if let Some(v) = l.strip_prefix("name = ") {
                    name = Some(v.trim_matches('"').to_string());
                } else if let Some(v) = l.strip_prefix("version = ") {
                    version = Some(v.trim_matches('"').to_string());
                    vline = j + 1;
                } else if l.starts_with("source = ") {
                    source = l.contains("registry");
                    local = ["editable =", "virtual =", "path ="]
                        .iter()
                        .any(|key| l.contains(key));
                }
                j += 1;
            }
            if let (Some(n), Some(v)) = (name, version)
                && (source || !need_source)
                && !local
            {
                out.push(pkg(eco, &n, &v, file, vline));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn go_mod(file: &FileInfo, text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut block = false;
    for (i, line) in text.lines().enumerate() {
        let l = line.split("//").next().unwrap_or("").trim();
        if l == "require (" {
            block = true;
            continue;
        }
        if block && l == ")" {
            block = false;
            continue;
        }
        let spec = if block {
            l
        } else if let Some(s) = l.strip_prefix("require ") {
            s.trim()
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        if let (Some(name), Some(v)) = (parts.next(), parts.next()) {
            out.push(pkg("Go", name, v, file, i + 1));
        }
    }
    out
}

fn gemfile_lock(file: &FileInfo, text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    // Only a `GEM` section lists gems from a gem server. `GIT` and `PATH`
    // sections list gems built from a git repository or a local folder.
    let mut in_gem = false;
    let mut in_specs = false;
    for (i, line) in text.lines().enumerate() {
        if !line.starts_with(' ') {
            in_gem = line.trim_end() == "GEM";
            in_specs = false;
            continue;
        }
        if line.trim() == "specs:" {
            in_specs = in_gem;
            continue;
        }
        if in_specs
            && line.starts_with("    ")
            && !line.starts_with("     ")
            && let Some((name, rest)) = line.trim().split_once(" (")
        {
            let v = rest.trim_end_matches(')').split('-').next().unwrap_or("");
            out.push(pkg("RubyGems", name, v, file, i + 1));
        }
    }
    out
}

fn composer_lock(file: &FileInfo, text: &str) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = 0;
    for key in ["packages", "packages-dev"] {
        for p in json
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let (Some(n), Some(v)) = (
                p.get("name").and_then(Value::as_str),
                p.get("version").and_then(Value::as_str),
            ) {
                let at = find_from(text, &mut cursor, &format!("\"{n}\""));
                out.push(pkg(
                    "Packagist",
                    n,
                    v,
                    file,
                    line_of(text, find_after(text, at, "\"version\"")),
                ));
            }
        }
    }
    out
}

fn pubspec_lock(file: &FileInfo, text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut sdk = HashSet::new();
    let mut in_packages = false;
    let mut name = "";
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages || line.starts_with("     ") {
            continue;
        }
        let l = line.trim();
        if !line.starts_with("    ") {
            name = l.trim_end_matches(':').trim_matches('"');
        } else if let Some(v) = l.strip_prefix("version: ") {
            out.push(pkg("Pub", name, v.trim_matches('"'), file, i + 1));
        } else if l == "source: sdk" {
            sdk.insert(name);
        }
    }
    out.retain(|p| !sdk.contains(p.name.as_str()));
    out
}

fn requirements(file: &FileInfo, text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let l = line
            .split('#')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if let Some((name, v)) = l.split_once("==") {
            let name = name.split('[').next().unwrap_or(name).trim();
            let v = v.split([',', ' ']).next().unwrap_or("").trim();
            if !name.is_empty() && !v.is_empty() {
                out.push(pkg("PyPI", name, v, file, i + 1));
            }
        }
    }
    out
}

fn find_from(text: &str, cursor: &mut usize, needle: &str) -> usize {
    let at = text[*cursor..]
        .find(needle)
        .map(|i| *cursor + i)
        .or_else(|| text.find(needle))
        .unwrap_or(0);
    *cursor = at + needle.len().min(text.len() - at);
    at
}

fn find_after(text: &str, at: usize, needle: &str) -> usize {
    text[at..].find(needle).map(|i| at + i).unwrap_or(at)
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

pub fn findings(packages: &[Package], found: HashMap<usize, Vec<Advisory>>) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, advisories) in found {
        let Some(p) = packages.get(i) else { continue };
        if advisories.is_empty() {
            continue;
        }
        let severity = advisories
            .iter()
            .map(|a| a.severity)
            .max()
            .unwrap_or(Severity::Medium);
        let list = advisories
            .iter()
            .map(|a| {
                if a.summary.is_empty() {
                    a.id.clone()
                } else {
                    format!("{} ({})", a.id, a.summary)
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        let fixed = advisories
            .iter()
            .filter_map(|a| a.fixed.clone())
            .max_by(|a, b| version_cmp(a, b));
        out.push(Finding::new(
            "dependency.known-vulnerability",
            Family::Dependency,
            severity,
            p.path.clone(),
            p.line,
            format!("{} {} has known vulnerabilities: {list}", p.name, p.version),
            match fixed {
                Some(v) => format!("Upgrade {} to {v} or later.", p.name),
                None => "No fixed version is published yet; read the advisory for workarounds or replace the package.".into(),
            },
            format!("{}@{} ({})", p.name, p.version, p.ecosystem),
        ));
    }
    out
}

fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| {
        s.split(|c: char| !c.is_ascii_digit())
            .filter_map(|p| p.parse::<u64>().ok())
            .collect::<Vec<_>>()
    };
    parse(a).cmp(&parse(b))
}

pub struct OsvClient {
    pub endpoint: String,
}

impl Default for OsvClient {
    fn default() -> Self {
        Self {
            endpoint: "https://api.osv.dev/v1".into(),
        }
    }
}

impl OsvClient {
    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .user_agent(concat!("safe-anything/", env!("CARGO_PKG_VERSION")))
            .build()
            .into()
    }

    fn details(&self, agent: &ureq::Agent, id: &str) -> Option<Value> {
        agent
            .get(&format!("{}/vulns/{id}", self.endpoint))
            .call()
            .ok()?
            .body_mut()
            .read_json::<Value>()
            .ok()
    }
}

impl Advisories for OsvClient {
    fn lookup(&self, packages: &[Package]) -> Result<HashMap<usize, Vec<Advisory>>, String> {
        let agent = Self::agent();
        let mut ids_for: HashMap<usize, Vec<String>> = HashMap::new();
        for (chunk_no, chunk) in packages.chunks(1000).enumerate() {
            let queries: Vec<Value> = chunk
                .iter()
                .map(|p| json!({"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}))
                .collect();
            let mut resp = agent
                .post(&format!("{}/querybatch", self.endpoint))
                .send_json(json!({ "queries": queries }))
                .map_err(|e| format!("OSV query failed: {e}"))?;
            let body: Value = resp
                .body_mut()
                .read_json()
                .map_err(|e| format!("OSV answer unreadable: {e}"))?;
            for (i, result) in body["results"].as_array().into_iter().flatten().enumerate() {
                let ids: Vec<String> = result["vulns"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v["id"].as_str().map(String::from))
                    .collect();
                if !ids.is_empty() {
                    ids_for.insert(chunk_no * 1000 + i, ids);
                }
            }
        }
        let unique: Vec<String> = ids_for
            .values()
            .flatten()
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let details: HashMap<String, Value> = std::thread::scope(|s| {
            let workers: Vec<_> = unique
                .chunks(unique.len().div_ceil(8).max(1))
                .map(|ids| {
                    let agent = agent.clone();
                    s.spawn(move || {
                        ids.iter()
                            .filter_map(|id| self.details(&agent, id).map(|d| (id.clone(), d)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|w| w.join().unwrap_or_default())
                .collect()
        });
        let mut out = HashMap::new();
        for (i, ids) in ids_for {
            let p = &packages[i];
            let mut list: Vec<Advisory> = ids
                .iter()
                .filter(|id| {
                    !details.get(*id).is_some_and(|d| {
                        d["aliases"].as_array().into_iter().flatten().any(|a| {
                            a.as_str().is_some_and(|a| {
                                ids.iter().any(|o| o == a && o.as_str() < id.as_str())
                            })
                        })
                    })
                })
                .map(|id| advisory(id, details.get(id), &p.name, &p.version))
                .collect();
            list.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
            out.insert(i, list);
        }
        Ok(out)
    }
}

fn advisory(id: &str, d: Option<&Value>, name: &str, current: &str) -> Advisory {
    let Some(d) = d else {
        return Advisory {
            id: id.into(),
            summary: String::new(),
            severity: Severity::Medium,
            fixed: None,
        };
    };
    let sev = d["database_specific"]["severity"]
        .as_str()
        .map(str::to_ascii_uppercase)
        .and_then(|s| match s.as_str() {
            "CRITICAL" => Some(Severity::Critical),
            "HIGH" => Some(Severity::High),
            "MODERATE" | "MEDIUM" => Some(Severity::Medium),
            "LOW" => Some(Severity::Low),
            _ => None,
        })
        .unwrap_or(Severity::Medium);
    let fixed = d["affected"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| {
            a["package"]["name"]
                .as_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
        .flat_map(|a| a["ranges"].as_array().into_iter().flatten())
        .flat_map(|r| r["events"].as_array().into_iter().flatten())
        .filter_map(|e| e["fixed"].as_str().map(String::from))
        .collect::<Vec<_>>();
    let fixed = fixed
        .iter()
        .filter(|f| version_cmp(f, current).is_gt())
        .min_by(|a, b| version_cmp(a, b))
        .or_else(|| fixed.iter().max_by(|a, b| version_cmp(a, b)))
        .cloned();
    Advisory {
        id: id.into(),
        summary: d["summary"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(120)
            .collect(),
        severity: sev,
        fixed,
    }
}
