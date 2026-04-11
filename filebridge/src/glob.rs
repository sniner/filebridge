//! Glob pattern matching against remote files.
//!
//! Supports `*`, `?`, `[seq]`, and recursive `**` patterns, analogous to
//! the Python client's `Location.glob()` method.  Pattern expansion happens
//! client-side: directories are listed via the Filebridge REST API and
//! entries are matched segment-by-segment.

use crate::location::FileBridgeLocation;
use crate::models::Metadata;
use crate::Result;

/// A single entry returned by a glob operation.
#[derive(Debug, Clone)]
pub struct GlobEntry {
    /// Relative path from the glob root (e.g. `"sub/file.txt"`).
    pub path: String,
    /// Server-reported metadata for the entry.
    pub metadata: Metadata,
}

/// Collect all remote entries whose paths match `pattern`.
///
/// The pattern is split on `/` and matched segment-by-segment against the
/// remote directory tree.  Supported wildcards:
///
/// - `*`  — any number of characters (excluding `/`)
/// - `?`  — exactly one character
/// - `[abc]`, `[a-z]` — character class
/// - `**` — zero or more directory levels (recursive)
pub async fn glob(loc: &FileBridgeLocation<'_>, pattern: &str) -> Result<Vec<GlobEntry>> {
    let pattern = pattern.trim_start_matches('/');
    let parts: Vec<&str> = pattern.split('/').collect();
    if parts.is_empty() || (parts.len() == 1 && parts[0].is_empty()) {
        return Ok(Vec::new());
    }
    let mut results = Vec::new();
    recursive_glob(loc, String::new(), &parts, &mut results).await?;
    Ok(results)
}

/// Recursive core: walk directories segment-by-segment.
fn recursive_glob<'a>(
    loc: &'a FileBridgeLocation<'_>,
    current_path: String,
    pattern_parts: &'a [&'a str],
    results: &'a mut Vec<GlobEntry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
    if pattern_parts.is_empty() {
        return Ok(());
    }

    let pattern = pattern_parts[0];
    let remaining = &pattern_parts[1..];

    // --- Recursive wildcard ** -------------------------------------------
    if pattern == "**" {
        let items = list_at(loc, &current_path).await?;

        // Apply remaining pattern at current depth (** matches zero dirs)
        if !remaining.is_empty() {
            recursive_glob(loc, current_path.clone(), remaining, results).await?;
        } else {
            // Bare ** without remainder: collect everything recursively
            walk_all(loc, &current_path, &items, results).await?;
            return Ok(());
        }

        // Recurse into subdirectories and continue ** there
        for item in &items {
            if item.is_dir {
                let child = join_path(&current_path, &item.name);
                recursive_glob(loc, child, pattern_parts, results).await?;
            }
        }
        return Ok(());
    }

    // --- Literal segment (no wildcards) — skip listing --------------------
    if !is_glob(pattern) {
        let child = join_path(&current_path, pattern);
        if remaining.is_empty() {
            // Leaf: try to get info directly instead of listing the parent
            match loc.info(&child).await {
                Ok(meta) => {
                    results.push(GlobEntry {
                        path: child,
                        metadata: meta,
                    });
                }
                Err(crate::Error::Api(status, _)) if status.as_u16() == 404 => {
                    // Not found — no match, that's fine
                }
                Err(e) => return Err(e),
            }
        } else {
            // Not a leaf: recurse (the segment must be a directory)
            recursive_glob(loc, child, remaining, results).await?;
        }
        return Ok(());
    }

    // --- Wildcard segment ------------------------------------------------
    let items = list_at(loc, &current_path).await?;

    for item in &items {
        if match_segment(pattern, &item.name) {
            let child = join_path(&current_path, &item.name);
            if remaining.is_empty() {
                results.push(GlobEntry {
                    path: child,
                    metadata: item.clone(),
                });
            } else if item.is_dir {
                recursive_glob(loc, child, remaining, results).await?;
            }
        }
    }

    Ok(())
    })
}

/// Yield all entries below `path` recursively (for bare `**`).
fn walk_all<'a>(
    loc: &'a FileBridgeLocation<'_>,
    base: &'a str,
    items: &'a [Metadata],
    results: &'a mut Vec<GlobEntry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        for item in items {
            let path = join_path(base, &item.name);
            results.push(GlobEntry {
                path: path.clone(),
                metadata: item.clone(),
            });
            if item.is_dir {
                let children = list_at(loc, &path).await?;
                walk_all(loc, &path, &children, results).await?;
            }
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// List a directory, returning an empty vec for the root path.
async fn list_at(loc: &FileBridgeLocation<'_>, path: &str) -> Result<Vec<Metadata>> {
    let path_opt = if path.is_empty() { None } else { Some(path) };
    loc.list(path_opt).await
}

/// Join two path segments, avoiding a leading `/`.
fn join_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{base}/{name}")
    }
}

/// Check whether a segment contains glob meta-characters.
fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Match a single filename against a glob pattern (fnmatch-style).
///
/// - `*`  matches any sequence of characters
/// - `?`  matches exactly one character
/// - `[abc]` matches one of a, b, c
/// - `[a-z]` matches a range
/// - `[!a-z]` / `[^a-z]` matches anything *not* in the range
fn match_segment(pattern: &str, name: &str) -> bool {
    match_impl(pattern.as_bytes(), name.as_bytes())
}

fn match_impl(pat: &[u8], name: &[u8]) -> bool {
    let (mut pi, mut ni) = (0usize, 0usize);
    // For back-tracking on `*`
    let mut star_pi: Option<usize> = None;
    let mut star_ni: usize = 0;

    while ni < name.len() {
        if pi < pat.len() {
            match pat[pi] {
                b'?' => {
                    pi += 1;
                    ni += 1;
                    continue;
                }
                b'*' => {
                    star_pi = Some(pi);
                    star_ni = ni;
                    pi += 1;
                    continue;
                }
                b'[' => {
                    if let Some((matched, end)) = match_bracket(&pat[pi..], name[ni])
                        && matched
                    {
                        pi += end;
                        ni += 1;
                        continue;
                    }
                    // No match — try back-tracking
                }
                c if c == name[ni] => {
                    pi += 1;
                    ni += 1;
                    continue;
                }
                _ => {}
            }
        }

        // Back-track to last `*`
        if let Some(sp) = star_pi {
            star_ni += 1;
            ni = star_ni;
            pi = sp + 1;
        } else {
            return false;
        }
    }

    // Consume trailing `*`s in pattern
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }

    pi == pat.len()
}

/// Try to match a bracket expression `[...]` against a single byte.
/// Returns `Some((matched, bytes_consumed))` or `None` if the bracket is malformed.
fn match_bracket(pat: &[u8], ch: u8) -> Option<(bool, usize)> {
    debug_assert!(pat[0] == b'[');
    let mut i = 1;
    let negate = if i < pat.len() && (pat[i] == b'!' || pat[i] == b'^') {
        i += 1;
        true
    } else {
        false
    };

    let mut matched = false;
    let start = i;

    while i < pat.len() && (pat[i] != b']' || i == start) {
        if i + 2 < pat.len() && pat[i + 1] == b'-' && pat[i + 2] != b']' {
            // Range: a-z
            let lo = pat[i];
            let hi = pat[i + 2];
            if ch >= lo && ch <= hi {
                matched = true;
            }
            i += 3;
        } else {
            if pat[i] == ch {
                matched = true;
            }
            i += 1;
        }
    }

    if i >= pat.len() {
        return None; // Unterminated bracket
    }
    // pat[i] == b']'
    Some((matched ^ negate, i + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_match() {
        assert!(match_segment("hello", "hello"));
        assert!(!match_segment("hello", "world"));
    }

    #[test]
    fn star_wildcard() {
        assert!(match_segment("*.txt", "readme.txt"));
        assert!(!match_segment("*.txt", "readme.md"));
        assert!(match_segment("file*", "file123"));
        assert!(match_segment("*", "anything"));
        assert!(match_segment("f*e", "file"));
        assert!(match_segment("f*e", "fe"));
    }

    #[test]
    fn question_mark() {
        assert!(match_segment("?.txt", "a.txt"));
        assert!(!match_segment("?.txt", "ab.txt"));
        assert!(match_segment("a?c", "abc"));
    }

    #[test]
    fn bracket_class() {
        assert!(match_segment("[abc].txt", "a.txt"));
        assert!(match_segment("[abc].txt", "c.txt"));
        assert!(!match_segment("[abc].txt", "d.txt"));
    }

    #[test]
    fn bracket_range() {
        assert!(match_segment("[a-z].txt", "m.txt"));
        assert!(!match_segment("[a-z].txt", "M.txt"));
    }

    #[test]
    fn bracket_negation() {
        assert!(!match_segment("[!a-z].txt", "m.txt"));
        assert!(match_segment("[!a-z].txt", "M.txt"));
        assert!(match_segment("[^0-9]x", "ax"));
        assert!(!match_segment("[^0-9]x", "5x"));
    }

    #[test]
    fn multiple_stars() {
        assert!(match_segment("*.*", "file.txt"));
        assert!(!match_segment("*.*", "noext"));
    }

    #[test]
    fn empty_cases() {
        assert!(match_segment("*", ""));
        assert!(!match_segment("?", ""));
        assert!(match_segment("", ""));
    }

    #[test]
    fn is_glob_detection() {
        assert!(is_glob("*.txt"));
        assert!(is_glob("file?"));
        assert!(is_glob("[abc]"));
        assert!(!is_glob("plain"));
        assert!(!is_glob("no-wildcards.txt"));
    }
}
