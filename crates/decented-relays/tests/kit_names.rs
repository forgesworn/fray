//! KIT rule 10: no game names in kit crates.
//!
//! Every `crates/decented-*/src/**/*.rs` file must be free of the game's name
//! (case-insensitive `twang`) outside `#[cfg(test)]` items. Test fixtures in a
//! `#[cfg(test)]` module (or on a `#[cfg(test)]` item) may use it; code after
//! that item is scanned again. Files named `tests.rs` or
//! `fake_ws.rs`, and anything under a `vectors` directory, are test material
//! and are skipped.

use std::fs;
use std::path::{Path, PathBuf};

const GAME: &str = "twang";

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "vectors") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && !path
                .file_name()
                .is_some_and(|n| n == "tests.rs" || n == "fake_ws.rs")
        {
            out.push(path);
        }
    }
}

/// What the scanner is inside while it reads code, so braces in strings,
/// comments and char literals do not count.
#[derive(Clone, Copy, PartialEq)]
enum Lex {
    Code,
    Str,
    /// A raw string closed by `"` and this many `#`.
    Raw(usize),
    Block(usize),
}

/// The structural characters of one line, in order, outside strings, comments
/// and char literals: braces, parentheses, brackets and semicolons.
fn structure(line: &str, lex: &mut Lex) -> Vec<char> {
    let c: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        match *lex {
            Lex::Str => {
                if c[i] == '\\' {
                    i += 1;
                } else if c[i] == '"' {
                    *lex = Lex::Code;
                }
            }
            Lex::Raw(h) => {
                if c[i] == '"'
                    && c.len() >= i + 1 + h
                    && c[i + 1..i + 1 + h].iter().all(|x| *x == '#')
                {
                    i += h;
                    *lex = Lex::Code;
                }
            }
            Lex::Block(d) => {
                if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    i += 1;
                    *lex = if d == 1 { Lex::Code } else { Lex::Block(d - 1) };
                } else if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    i += 1;
                    *lex = Lex::Block(d + 1);
                }
            }
            Lex::Code => match c[i] {
                '/' if c.get(i + 1) == Some(&'/') => break,
                '/' if c.get(i + 1) == Some(&'*') => {
                    i += 1;
                    *lex = Lex::Block(1);
                }
                '"' => *lex = Lex::Str,
                'r' if i == 0 || !(c[i - 1].is_alphanumeric() || c[i - 1] == '_') => {
                    let mut j = i + 1;
                    while c.get(j) == Some(&'#') {
                        j += 1;
                    }
                    if c.get(j) == Some(&'"') {
                        *lex = Lex::Raw(j - i - 1);
                        i = j;
                    }
                }
                '\'' => {
                    // A char literal ('{', '\n', '\''), not a lifetime.
                    if c.get(i + 1) == Some(&'\\') {
                        let mut j = i + 2;
                        while j < c.len() && c[j] != '\'' {
                            j += 1;
                        }
                        i = j;
                    } else if c.get(i + 2) == Some(&'\'') {
                        i += 2;
                    }
                }
                ch @ ('{' | '}' | ';' | '(' | ')' | '[' | ']') => out.push(ch),
                _ => {}
            },
        }
        i += 1;
    }
    out
}

/// Which lines (0-based) belong to a `#[cfg(test)]` item: the attribute, any
/// further attributes, and the item itself up to its closing brace (an inline
/// `mod tests { .. }` included) or its `;` (`mod x;`, a `use`, a `const`).
/// Everything after that item is production code again.
fn test_item_lines(lines: &[&str], path: &str) -> Vec<bool> {
    let mut skip = vec![false; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        let Some(rest) = t.strip_prefix("#[cfg(test)]") else {
            i += 1;
            continue;
        };
        skip[i] = true;
        let mut lex = Lex::Code;
        let (mut depth, mut parens, mut opened) = (0usize, 0usize, false);
        // The item may share the attribute's line.
        let mut k = i;
        let mut first = Some(rest);
        let end = 'item: loop {
            let text = match first.take() {
                Some(r) => r,
                None => {
                    k += 1;
                    if k >= lines.len() {
                        panic!("{path}: a #[cfg(test)] item that never ends");
                    }
                    lines[k]
                }
            };
            skip[k] = true;
            let tt = text.trim_start();
            if !opened && (tt.is_empty() || tt.starts_with("#[") || tt.starts_with("//")) {
                continue; // blank, a further attribute, or a comment
            }
            for ch in structure(text, &mut lex) {
                match ch {
                    '{' => {
                        opened = true;
                        depth += 1;
                    }
                    '}' => depth = depth.saturating_sub(1),
                    '(' | '[' => parens += 1,
                    ')' | ']' => parens = parens.saturating_sub(1),
                    ';' if !opened && parens == 0 => break 'item k,
                    _ => {}
                }
                if opened && depth == 0 {
                    break 'item k;
                }
            }
        };
        i = end + 1;
    }
    skip
}

/// Lines (1-based) outside `#[cfg(test)]` items that name the game.
fn hits(text: &str, path: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let skip = test_item_lines(&lines, path);
    lines
        .iter()
        .enumerate()
        .filter(|(i, l)| !skip[*i] && l.to_lowercase().contains(GAME))
        .map(|(i, l)| (i + 1, l.trim().to_string()))
        .collect()
}

#[test]
fn the_scan_itself_works() {
    // An inline test module is skipped, and what follows it is scanned again.
    let text = "//! fine\nfn a() {}\n    // a Twang mention\n#[cfg(test)]\nmod t {\n    const X: &str = \"twangthang\";\n    fn f() { let _ = '}'; let _ = \"}\"; }\n}\nconst Y: &str = \"TWANG\";\n";
    assert_eq!(
        hits(text, "x"),
        vec![
            (3, "// a Twang mention".to_string()),
            (9, "const Y: &str = \"TWANG\";".to_string())
        ]
    );
    // A cfg(test) on one item skips only that item: code after it is scanned.
    let text =
        "#[cfg(test)]\nfn helper() {\n    let _ = \"twang\";\n}\nconst X: &str = \"twang\";\n";
    assert_eq!(
        hits(text, "x"),
        vec![(5, "const X: &str = \"twang\";".to_string())]
    );
    // `mod x;`, a use, an attribute stack and an item on the attribute's line.
    let text = "#[cfg(test)]\nmod fake;\nconst A: &str = \"twang\";\n#[cfg(test)]\n#[allow(dead_code)]\nuse twang::x;\n#[cfg(test)] fn g() { twang(); }\nconst B: &str = \"twang\";\n";
    let got: Vec<usize> = hits(text, "x").iter().map(|h| h.0).collect();
    assert_eq!(got, vec![3, 8]);
    // An indented cfg(test) inside an impl skips just that method.
    let text = "impl A {\n    #[cfg(test)]\n    fn t() { twang(); }\n    fn p() { twang(); }\n}\n";
    assert_eq!(
        hits(text, "x").iter().map(|h| h.0).collect::<Vec<_>>(),
        vec![4]
    );
    // A `;` inside an array type does not end the item early.
    let text = "#[cfg(test)]\nfn f(a: [u8; 4]) {\n    twang();\n}\nfn p() { twang(); }\n";
    assert_eq!(
        hits(text, "x").iter().map(|h| h.0).collect::<Vec<_>>(),
        vec![5]
    );
}

#[test]
fn no_game_names_in_kit_crates() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    let mut kit_crates = 0;
    for entry in fs::read_dir(&crates_dir).expect("crates dir").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("decented-") {
            kit_crates += 1;
            rust_files(&entry.path().join("src"), &mut files);
        }
    }
    assert!(
        kit_crates >= 2 && !files.is_empty(),
        "found no kit sources under {crates_dir:?}"
    );
    files.sort();
    let mut report = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap_or_default();
        for (line, text) in hits(&text, &f.display().to_string()) {
            let rel = f.strip_prefix(&crates_dir).unwrap_or(f);
            report.push(format!("{}:{line}: {text}", rel.display()));
        }
    }
    assert!(
        report.is_empty(),
        "game names in kit crates (KIT rule 10):\n{}",
        report.join("\n")
    );
}
