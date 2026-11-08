//! Keeps the docs honest: the code in them is the starter's own code, every
//! relative link resolves, and nothing in them is a real address or path.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The two new guides.
fn guides() -> Vec<PathBuf> {
    ["docs/getting-started.md", "docs/coding-assistants.md"]
        .iter()
        .map(|p| root().join(p))
        .collect()
}

/// The guides and the README, which points at them.
fn docs() -> Vec<PathBuf> {
    let mut all = guides();
    all.push(root().join("README.md"));
    all
}

/// Every `](target)` in `text`, outside fenced code blocks.
fn links(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut in_fence = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let mut rest = line;
        while let Some(i) = rest.find("](") {
            rest = &rest[i + 2..];
            if let Some(end) = rest.find(')') {
                found.push(rest[..end].to_string());
                rest = &rest[end..];
            }
        }
    }
    found
}

#[test]
fn every_relative_link_resolves() {
    for doc in docs() {
        let text = read(&doc);
        for link in links(&text) {
            if link.starts_with("http://") || link.starts_with("https://") || link.starts_with('#')
            {
                continue;
            }
            let path = link.split('#').next().unwrap();
            let target = doc.parent().unwrap().join(path);
            assert!(
                target.exists(),
                "{}: the link ({link}) does not resolve",
                doc.display()
            );
        }
    }
}

/// The text of a source file as a list of trimmed, non-blank lines, with doc
/// comment markers removed, so a doc example can be matched against it.
fn normalised(path: &Path) -> Vec<String> {
    read(path)
        .lines()
        .map(|l| {
            let l = l.trim();
            let l = l.strip_prefix("//!").unwrap_or(l);
            l.trim().to_string()
        })
        .filter(|l| !l.is_empty())
        .collect()
}

/// The ```rust blocks in `text`, each as trimmed, non-blank lines.
fn rust_blocks(text: &str) -> Vec<Vec<String>> {
    let mut blocks = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for line in text.lines() {
        let t = line.trim();
        match (&mut current, t) {
            (None, "```rust") => current = Some(Vec::new()),
            (Some(_), "```") => blocks.push(current.take().unwrap()),
            (Some(block), _) if !t.is_empty() => block.push(t.to_string()),
            _ => {}
        }
    }
    blocks
}

#[test]
fn every_rust_block_in_the_docs_is_an_exact_excerpt_of_the_starter() {
    let sources: Vec<(PathBuf, Vec<String>)> = [
        "examples/starter/src/lib.rs",
        "examples/starter/src/main.rs",
        "examples/starter/src/wire.rs",
        "examples/starter/tests/loopback.rs",
    ]
    .iter()
    .map(|p| (root().join(p), normalised(&root().join(p))))
    .collect();
    let mut checked = 0;
    for doc in guides() {
        for block in rust_blocks(&read(&doc)) {
            let found = sources
                .iter()
                .any(|(_, lines)| lines.windows(block.len()).any(|w| w == block.as_slice()));
            assert!(
                found,
                "{}: a rust block is not an excerpt of the starter source:\n{}",
                doc.display(),
                block.join("\n")
            );
            checked += 1;
        }
    }
    assert!(checked >= 4, "the docs should carry the starter's snippets");
}

#[test]
fn the_docs_hold_no_personal_paths_or_real_addresses() {
    for doc in docs() {
        let text = read(&doc);
        // Spelled in pieces so this file does not itself look like such a path.
        for bad in [
            format!("/{}/", "home"),
            format!("/{}/", "Users"),
            format!("C:\\{}", "Users"),
        ] {
            assert!(!text.contains(&bad), "{}: contains {bad}", doc.display());
        }
        // Dotted quads: only loopback and the RFC 5737 documentation ranges.
        for word in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
            let parts: Vec<&str> = word.split('.').collect();
            if parts.len() != 4 || parts.iter().any(|p| p.is_empty() || p.len() > 3) {
                continue;
            }
            let allowed = word.starts_with("127.")
                || word.starts_with("192.0.2.")
                || word.starts_with("198.51.100.")
                || word.starts_with("203.0.113.");
            assert!(
                allowed,
                "{}: an address that is not for documentation: {word}",
                doc.display()
            );
        }
    }
}
