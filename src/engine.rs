use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

use ignore::{WalkBuilder, WalkState};

use crate::Finding;
use crate::deps::{self, Package};
use crate::rules::{self, FileInfo};

const MAX_BYTES: u64 = 2 * 1024 * 1024;
/// Lockfiles get a larger limit: a mid-size monorepo's package-lock.json is
/// several MB, and the dependency check is only as good as the lockfile it reads.
pub(crate) const MAX_LOCK_BYTES: u64 = 64 * 1024 * 1024;
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".next",
    ".venv",
    "venv",
    "__pycache__",
    "Pods",
    ".gradle",
];

/// Extensions of binary formats that are skipped without opening the file.
/// Real files of each kind have a zero byte in their first 8 KB, so
/// `read_text` would skip them anyway. Formats that can be plain text are
/// left out: `pdf` and `svg` often have no zero byte, and a `.so` can be a
/// linker script.
const BINARY_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "icns", "bmp", "tif", "tiff", "avif", "heic",
    "psd", "woff", "woff2", "ttf", "otf", "ttc", "zip", "jar", "gz", "tgz", "bz2", "xz", "zst",
    "7z", "rar", "mp3", "mp4", "m4a", "mov", "wav", "flac", "exe", "dll", "class", "wasm", "pyc",
];

/// Minified bundles, source maps, logs, JSONL data and known binary formats,
/// decided from the name alone.
fn skipped_by_name(info: &FileInfo) -> bool {
    info.name.ends_with(".min.js")
        || info.ext_in(&["map", "jsonl", "log"])
        || info.ext_in(BINARY_EXTS)
}

/// A file `read_text` could read. `None` from it means binary or unreadable.
enum Contents {
    Text(Vec<u8>),
    /// The file grew past the limit after its size was checked.
    TooLarge,
}

/// Reads a file whose first 8 KB hold no zero byte. A binary file is left
/// after those 8 KB instead of being read in full. `len` is the size from the
/// file's metadata; a file that has grown past `max` since is reported as `TooLarge`.
fn read_text(path: &Path, len: u64, max: u64) -> Option<Contents> {
    const HEAD: u64 = 8192;
    let mut file = File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(usize::try_from(len.min(HEAD)).ok()?);
    (&mut file).take(HEAD).read_to_end(&mut bytes).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    // Fewer than 8 KB means the end of the file was reached already.
    if bytes.len() as u64 == HEAD {
        let rest = usize::try_from(len.min(max).saturating_sub(HEAD)).ok()?;
        bytes.reserve(rest);
        file.take(max + 1 - HEAD).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > max {
            return Some(Contents::TooLarge);
        }
    }
    Some(Contents::Text(bytes))
}

pub struct Scanned {
    pub files: usize,
    pub findings: Vec<Finding>,
    pub packages: Vec<Package>,
    pub env_files: Vec<String>,
    /// Lockfiles left out of the dependency check because they are over `MAX_LOCK_BYTES`.
    pub lockfiles_too_large: Vec<String>,
}

pub fn scan_files(root: &Path, include_tests: bool) -> Scanned {
    let out = Mutex::new(Scanned {
        files: 0,
        findings: Vec::new(),
        packages: Vec::new(),
        env_files: Vec::new(),
        lockfiles_too_large: Vec::new(),
    });
    let single_file = root.is_file();
    let base = if single_file {
        root.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        root.to_path_buf()
    };
    WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .require_git(false)
        .add_custom_ignore_filename(".safe-anything-ignore")
        .filter_entry(|e| {
            if !e.file_type().is_some_and(|t| t.is_dir()) {
                return true;
            }
            let name = e.file_name().to_string_lossy();
            let agent_copy = name == "worktrees"
                && e.path()
                    .parent()
                    .and_then(|p| p.file_name())
                    .is_some_and(|p| p == ".claude");
            !(SKIP_DIRS.contains(&name.as_ref()) || agent_copy)
        })
        .build_parallel()
        .run(|| {
            let out = &out;
            let base = &base;
            Box::new(move |entry| {
                let Ok(entry) = entry else {
                    return WalkState::Continue;
                };
                if !entry.file_type().is_some_and(|t| t.is_file()) {
                    return WalkState::Continue;
                }
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let info = FileInfo::new(&rel);
                if skipped_by_name(&info) {
                    return WalkState::Continue;
                }
                let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let lockfile = deps::is_lockfile(&info);
                let max = if lockfile { MAX_LOCK_BYTES } else { MAX_BYTES };
                if len > max {
                    if lockfile {
                        out.lock().unwrap().lockfiles_too_large.push(rel);
                    }
                    return WalkState::Continue;
                }
                let bytes = match read_text(path, len, max) {
                    Some(Contents::Text(bytes)) => bytes,
                    Some(Contents::TooLarge) => {
                        if lockfile {
                            out.lock().unwrap().lockfiles_too_large.push(rel);
                        }
                        return WalkState::Continue;
                    }
                    None => return WalkState::Continue,
                };
                let text = String::from_utf8_lossy(&bytes);
                // A lockfile over the usual limit is read for its packages only,
                // as no file that size was checked by the rules before.
                let findings = if info.ext == "lock" || bytes.len() as u64 > MAX_BYTES {
                    Vec::new()
                } else {
                    rules::check(&info, &text, include_tests)
                };
                let packages = deps::parse_lockfile(&info, &text);
                let mut out = out.lock().unwrap();
                out.files += 1;
                out.findings.extend(findings);
                out.packages.extend(packages);
                if rules::secrets::is_env(&info.name) && !info.is_test() {
                    out.env_files.push(rel.clone());
                }
                WalkState::Continue
            })
        });
    let mut scanned = out.into_inner().unwrap();
    scanned.packages.sort();
    scanned.packages.dedup();
    scanned.lockfiles_too_large.sort();
    scanned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_text_stops_at_the_size_limit() {
        let dir =
            std::env::temp_dir().join(format!("safe-anything-read-text-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("grown.txt");
        let max = usize::try_from(MAX_BYTES).unwrap();
        let text_len = |len: u64| match read_text(&path, len, MAX_BYTES) {
            Some(Contents::Text(bytes)) => Some(bytes.len()),
            _ => None,
        };
        // The metadata said 100 bytes, but the file is now over the limit.
        std::fs::write(&path, "x".repeat(max + 1)).unwrap();
        assert!(matches!(
            read_text(&path, 100, MAX_BYTES),
            Some(Contents::TooLarge)
        ));
        std::fs::write(&path, "x".repeat(max)).unwrap();
        assert_eq!(text_len(100), Some(max));
        std::fs::write(&path, "x".repeat(10)).unwrap();
        assert_eq!(text_len(MAX_BYTES), Some(10));
        // A binary file is neither text nor too large.
        std::fs::write(&path, b"x\0y").unwrap();
        assert!(read_text(&path, 3, MAX_BYTES).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
