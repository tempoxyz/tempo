//! The spec lint: the `# Invariants` section of every TIP (`tips/*.md`) and zone spec
//! (`zones/specs/*.md`) lists its invariants in one format, each tied to what checks it.
//!
//! Each top-level bullet of the section (up to the next `# ` heading) is exactly
//!
//! ```text
//! - `TEMPO-<AREA>-<NAME>`: <one sentence statement>
//!   - Since: <fork, e.g. T14>          (optional)
//!   - Checked by: <coverage>
//! ```
//!
//! where the coverage is `check` (a check in [`tempo_invariants::all`] whose doc is the statement
//! and whose `since` is the `Since`), `` `<path>.rs::<fn>` `` (a Rust test), `` `<path>.sol:<function>` ``
//! (a Foundry test or invariant), or `none` (not covered yet, counted). Paragraphs, numbered lists
//! and tables may go with the bullets; no other bullet may. The section is the one headed
//! `Invariants` at any level, up to the next heading of that level or above.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use tempo_invariants::{all, fork_position};

/// TIPs whose `# Invariants` section is not in the format yet. The lint skips them, and fails once
/// one passes, so the list only shrinks.
const UNMIGRATED: &[&str] = &[];

/// The process docs, whose `Invariants` section explains the format with an example in a code
/// block and lists no invariant itself.
const PROCESS: &[&str] = &["tips/tip-0000.md", "tips/tip_template.md"];

/// One invariant a spec lists.
#[derive(Debug, PartialEq, Eq)]
struct Invariant {
    id: String,
    statement: String,
    since: Option<String>,
    coverage: Coverage,
    /// The bullet's line in its file, from 1.
    line: usize,
}

/// What checks an invariant.
#[derive(Debug, PartialEq, Eq)]
enum Coverage {
    /// A check in `tempo_invariants::all()` with the invariant's ID.
    Check,
    /// A Rust test: a repo-relative `.rs` file and a function in it.
    Rust { path: String, function: String },
    /// A Foundry test or invariant: a repo-relative `.sol` file and a function in it.
    Solidity { path: String, function: String },
    /// Nothing yet.
    None,
}

#[test]
fn every_spec_lists_its_invariants_in_the_format() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let checks: BTreeMap<_, _> = all().map(|check| (check.id(), check.meta())).collect();
    let mut errors = Vec::new();
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    let mut uncovered = Vec::new();
    let mut listed = 0;
    let mut checked = BTreeSet::new();
    let unmigrated: BTreeSet<&str> = UNMIGRATED.iter().copied().collect();

    for file in specs(&root) {
        let name = file
            .strip_prefix(&root)
            .expect("specs are under the root")
            .to_string_lossy()
            .into_owned();
        let markdown = fs::read_to_string(&file).expect("specs are readable");
        let Some(section) = section(&markdown) else {
            if unmigrated.contains(name.as_str()) {
                errors.push(format!(
                    "{name}: has no # Invariants section; remove it from UNMIGRATED"
                ));
            }
            continue;
        };
        // A section that lists no invariant as a bullet is not in the format yet.
        let parsed = parse(&section).and_then(|invariants| {
            if invariants.is_empty() && !PROCESS.contains(&name.as_str()) && !withdrawn(&markdown) {
                Err(vec![format!(
                    "{}: the section lists no invariant as a \"- `TEMPO-<AREA>-<NAME>`: <statement>\" bullet",
                    section.first().map_or(0, |(number, _)| *number)
                )])
            } else {
                Ok(invariants)
            }
        });
        if unmigrated.contains(name.as_str()) {
            if parsed.is_ok() {
                errors.push(format!(
                    "{name}: is in the format; remove it from UNMIGRATED"
                ));
            }
            continue;
        }
        let invariants = match parsed {
            Ok(invariants) => invariants,
            Err(found) => {
                errors.extend(found.into_iter().map(|error| format!("{name}:{error}")));
                continue;
            }
        };
        for invariant in invariants {
            let at = format!("{name}:{}: {}", invariant.line, invariant.id);
            listed += 1;
            if let Some(first) = ids.insert(invariant.id.clone(), at.clone()) {
                errors.push(format!("{at}: also listed at {first}"));
            }
            if let Some(since) = &invariant.since
                && fork_position(since).is_none()
            {
                errors.push(format!("{at}: Since {since} is not a Tempo fork"));
            }
            match &invariant.coverage {
                Coverage::Check => match checks.get(invariant.id.as_str()) {
                    None => errors.push(format!("{at}: is not a check in tempo_invariants::all()")),
                    Some(meta) => {
                        checked.insert(invariant.id.clone());
                        if meta.doc != invariant.statement {
                            errors.push(format!(
                                "{at}: the statement differs from the check's doc\n  spec:  {}\n  check: {}",
                                invariant.statement, meta.doc
                            ));
                        }
                        if meta.since != invariant.since.as_deref() {
                            errors.push(format!(
                                "{at}: Since {:?} differs from the check's since {:?}",
                                invariant.since, meta.since
                            ));
                        }
                    }
                },
                Coverage::Rust { path, function } => {
                    if let Err(error) = defines_rust_test(&root, path, function) {
                        errors.push(format!("{at}: {path}::{function}: {error}"));
                    }
                }
                Coverage::Solidity { path, function } => {
                    if let Err(error) = defines_solidity(&root, path, function) {
                        errors.push(format!("{at}: {path}:{function}: {error}"));
                    }
                }
                Coverage::None => uncovered.push(at),
            }
        }
    }

    println!(
        "{listed} invariants listed, {} checked by a check, {} not covered (Checked by: none), {} TIPs not migrated",
        checked.len(),
        uncovered.len(),
        UNMIGRATED.len()
    );
    for at in &uncovered {
        println!("  none: {at}");
    }
    for id in checks.keys().filter(|id| !checked.contains(**id)) {
        println!("  check no spec lists: {id}");
    }
    assert!(
        errors.is_empty(),
        "{} spec lint errors:\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// The specs the lint reads: `tips/*.md` and `zones/specs/*.md`, in order.
/// Whether a TIP's front matter marks it cancelled or withdrawn, so nothing implements it and its
/// section may state no invariants.
fn withdrawn(markdown: &str) -> bool {
    markdown.lines().take(20).any(|line| {
        let line = line.trim().to_ascii_lowercase();
        line == "status: cancelled" || line == "status: withdrawn"
    })
}

fn specs(root: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = ["tips", "zones/specs"]
        .iter()
        .filter_map(|dir| fs::read_dir(root.join(dir)).ok())
        .flatten()
        .map(|entry| entry.expect("spec directories are readable").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
        .collect();
    files.sort();
    files
}

/// Whether the repo-relative `path` holds one of `found`.
/// `source` with its comments blanked, line for line, so a commented-out function is not found.
fn uncommented(source: &str) -> Vec<String> {
    #[derive(PartialEq)]
    enum In {
        Code,
        Str,
        Block,
    }
    let mut state = In::Code;
    source
        .lines()
        .map(|line| {
            let chars: Vec<char> = line.chars().collect();
            let mut out = String::new();
            let mut i = 0;
            while i < chars.len() {
                let c = chars[i];
                let next = chars.get(i + 1).copied();
                match state {
                    In::Block => {
                        if c == '*' && next == Some('/') {
                            state = In::Code;
                            i += 1;
                        }
                    }
                    In::Str => {
                        out.push(c);
                        if c == '\\' {
                            if let Some(escaped) = next {
                                out.push(escaped);
                                i += 1;
                            }
                        } else if c == '"' {
                            state = In::Code;
                        }
                    }
                    In::Code => match (c, next) {
                        ('/', Some('/')) => break,
                        ('/', Some('*')) => {
                            state = In::Block;
                            i += 1;
                        }
                        ('"', _) => {
                            out.push(c);
                            state = In::Str;
                        }
                        // A character literal such as '"' or '\'', not a lifetime.
                        ('\'', Some(_)) => {
                            let end = if next == Some('\\') { i + 3 } else { i + 2 };
                            if chars.get(end) == Some(&'\'') {
                                out.extend(&chars[i..=end]);
                                i = end;
                            } else {
                                out.push(c);
                            }
                        }
                        _ => out.push(c),
                    },
                }
                i += 1;
            }
            out
        })
        .collect()
}

/// Whether `path` defines `function` as a Rust test: an uncommented `fn` whose attributes,
/// right above it, include a test attribute (`#[test]`, `#[tokio::test]`, ...). A helper a test calls
/// does not count.
fn defines_rust_test(root: &Path, path: &str, function: &str) -> Result<(), &'static str> {
    let source = fs::read_to_string(root.join(path)).map_err(|_| "no such file")?;
    let lines = uncommented(&source);
    let signatures = [format!("fn {function}("), format!("fn {function}<")];
    let mut found = false;
    for (index, line) in lines.iter().enumerate() {
        if !signatures
            .iter()
            .any(|signature| line.contains(signature.as_str()))
        {
            continue;
        }
        found = true;
        let attributes = lines[..index]
            .iter()
            .rev()
            .map(|line| line.trim())
            .take_while(|line| {
                line.is_empty()
                    || line.starts_with("#[")
                    || line.ends_with(']')
                    || line.ends_with(',')
            });
        if attributes
            .into_iter()
            .any(|line| line.starts_with("#[") && line.contains("test"))
        {
            return Ok(());
        }
    }
    Err(if found {
        "the function is not a test"
    } else {
        "no such function in the file"
    })
}

/// Whether `path`, a Foundry test file, defines `function` outside a comment.
fn defines_solidity(root: &Path, path: &str, function: &str) -> Result<(), &'static str> {
    if !path.ends_with(".t.sol") {
        return Err("not a Foundry test file (*.t.sol)");
    }
    let source = fs::read_to_string(root.join(path)).map_err(|_| "no such file")?;
    let signature = format!("function {function}(");
    if uncommented(&source)
        .iter()
        .any(|line| line.contains(signature.as_str()))
    {
        Ok(())
    } else {
        Err("no such function in the file")
    }
}

/// The lines of `markdown`'s `Invariants` section, at any heading level (`# Invariants`, `## Invariants`...),
/// up to the next heading of its level or above, with their line numbers from 1; `None` when it has
/// none. Headings inside code blocks do not count.
fn section(markdown: &str) -> Option<Vec<(usize, &str)>> {
    let mut fenced = false;
    let mut lines = markdown.lines().enumerate().map(move |(index, line)| {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        let level = if fenced { None } else { heading_level(line) };
        (index + 1, line, level)
    });
    let (_, _, level) = lines.find(|(_, line, level)| {
        level.is_some() && line.trim_start_matches('#').trim() == "Invariants"
    })?;
    let level = level?;
    Some(
        lines
            .take_while(|(_, _, heading)| heading.is_none_or(|heading| heading > level))
            .map(|(number, line, _)| (number, line))
            .collect(),
    )
}

/// How many `#` open `line`, when it is a heading.
fn heading_level(line: &str) -> Option<usize> {
    let hashes = line.len() - line.trim_start_matches('#').len();
    (hashes > 0 && line[hashes..].starts_with(' ')).then_some(hashes)
}

/// The invariants a section lists, or every way it breaks the format, each as `<line>: <error>`.
fn parse(section: &[(usize, &str)]) -> Result<Vec<Invariant>, Vec<String>> {
    let mut invariants: Vec<Invariant> = Vec::new();
    let mut errors = Vec::new();
    // Whether the last bullet still takes sub-bullets, and whether it has its `Checked by`.
    let mut open = false;
    let mut covered = true;
    let mut fenced = false;
    let close = |open: &mut bool, covered: &mut bool, errors: &mut Vec<String>, line: usize| {
        if *open && !*covered {
            errors.push(format!(
                "{line}: the invariant above has no \"Checked by:\""
            ));
        }
        *open = false;
        *covered = true;
    };
    for &(number, line) in section {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            close(&mut open, &mut covered, &mut errors, number);
            continue;
        }
        if fenced || line.trim().is_empty() {
            continue;
        }
        if let Some(bullet) = line.strip_prefix("- ") {
            close(&mut open, &mut covered, &mut errors, number);
            match parse_bullet(bullet) {
                Ok((id, statement)) => {
                    invariants.push(Invariant {
                        id,
                        statement,
                        since: None,
                        coverage: Coverage::None,
                        line: number,
                    });
                    open = true;
                    covered = false;
                }
                Err(error) => errors.push(format!("{number}: {error}: {line}")),
            }
            continue;
        }
        if line.starts_with("* ") || line.starts_with("+ ") {
            close(&mut open, &mut covered, &mut errors, number);
            errors.push(format!("{number}: invariants are \"- \" bullets: {line}"));
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let sub = line.trim_start();
            let Some(invariant) = invariants.last_mut().filter(|_| open) else {
                // A numbered list's or a paragraph's continuation is prose; a bullet is not.
                if ["- ", "* ", "+ "]
                    .iter()
                    .any(|bullet| sub.starts_with(bullet))
                {
                    errors.push(format!(
                        "{number}: a sub-bullet outside an invariant: {line}"
                    ));
                }
                continue;
            };
            if let Some(since) = sub.strip_prefix("- Since: ") {
                if invariant.since.is_some() || covered {
                    errors.push(format!(
                        "{number}: \"Since:\" comes once, before \"Checked by:\""
                    ));
                }
                invariant.since = Some(since.trim().to_string());
            } else if let Some(coverage) = sub.strip_prefix("- Checked by: ") {
                if covered {
                    errors.push(format!("{number}: \"Checked by:\" comes once"));
                }
                covered = true;
                match parse_coverage(coverage.trim()) {
                    Ok(coverage) => invariant.coverage = coverage,
                    Err(error) => errors.push(format!("{number}: {error}: {line}")),
                }
            } else {
                errors.push(format!(
                    "{number}: an invariant takes only \"- Since:\" and \"- Checked by:\" sub-bullets, \
                     its statement one line: {line}"
                ));
            }
            continue;
        }
        // Prose: a paragraph, a numbered list, a table or a subheading.
        close(&mut open, &mut covered, &mut errors, number);
    }
    let end = section.last().map_or(0, |(number, _)| *number);
    close(&mut open, &mut covered, &mut errors, end);
    if errors.is_empty() {
        Ok(invariants)
    } else {
        Err(errors)
    }
}

/// A bullet's ID and statement, from `` `TEMPO-<AREA>-<NAME>`: <statement> `` (without the `- `).
fn parse_bullet(bullet: &str) -> Result<(String, String), &'static str> {
    let (id, statement) = bullet
        .strip_prefix('`')
        .and_then(|rest| rest.split_once("`: "))
        .ok_or("not \"- `TEMPO-<AREA>-<NAME>`: <statement>\"")?;
    let well_formed = id.starts_with("TEMPO-")
        && !id.ends_with('-')
        && !id.contains("--")
        && id
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-');
    if !well_formed {
        return Err(
            "the ID is not TEMPO- followed by uppercase letters, digits and single hyphens",
        );
    }
    let statement = statement.trim();
    if statement.is_empty() {
        return Err("the statement is empty");
    }
    if !statement.ends_with('.') {
        return Err("the statement is one sentence, ending with a period");
    }
    Ok((id.to_string(), statement.to_string()))
}

/// What `Checked by:` names.
fn parse_coverage(coverage: &str) -> Result<Coverage, &'static str> {
    match coverage {
        "check" => return Ok(Coverage::Check),
        "none" => return Ok(Coverage::None),
        _ => {}
    }
    let test = coverage
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .ok_or("coverage is check, none, `<path>.rs::<fn>` or `<path>.sol:<function>`")?;
    let identifier = |name: &str| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if let Some((path, function)) = test.split_once(".rs::") {
        return identifier(function)
            .then(|| Coverage::Rust {
                path: format!("{path}.rs"),
                function: function.to_string(),
            })
            .ok_or("a Rust test is `<path>.rs::<fn>`");
    }
    if let Some((path, function)) = test.split_once(".sol:") {
        return identifier(function)
            .then(|| Coverage::Solidity {
                path: format!("{path}.sol"),
                function: function.to_string(),
            })
            .ok_or("a Foundry test is `<path>.sol:<function>`");
    }
    Err("coverage is check, none, `<path>.rs::<fn>` or `<path>.sol:<function>`")
}

/// `markdown`'s section, parsed.
fn invariants(markdown: &str) -> Result<Vec<Invariant>, Vec<String>> {
    parse(&section(markdown).expect("the example has an Invariants section"))
}

#[test]
fn the_parser_reads_every_coverage_and_a_since() {
    let markdown = "\
# Threat Model

- `TEMPO-NOT-HERE`: outside the section, not read.

# Invariants

- `TEMPO-A-ONE`: The first holds.
  - Since: T14
  - Checked by: check
- `TEMPO-A-TWO`: The second holds.
  - Checked by: `crates/x/src/lib.rs::holds`
- `TEMPO-A-THREE`: The third holds.
  - Checked by: `tips/verify/test/X.t.sol:invariant_holds`
- `TEMPO-A-FOUR`: The fourth is not covered.
  - Checked by: none

Tests must cover the edge cases:

1. An empty pool,
   with no liquidity.
2. A full pool.

| Case | Covered |
|---|---|

## A subheading inside the section

- `TEMPO-A-FIVE`: Under a subheading.
  - Checked by: none

```text
# not a heading
- not an invariant
```

# Next
- `TEMPO-NOT-HERE-EITHER`: after the section.
";
    let parsed = invariants(markdown).expect("the example is in the format");
    let summary: Vec<_> = parsed
        .iter()
        .map(|i| (i.id.as_str(), i.since.as_deref(), &i.coverage, i.line))
        .collect();
    assert_eq!(
        summary,
        [
            ("TEMPO-A-ONE", Some("T14"), &Coverage::Check, 7),
            (
                "TEMPO-A-TWO",
                None,
                &Coverage::Rust {
                    path: "crates/x/src/lib.rs".into(),
                    function: "holds".into()
                },
                10
            ),
            (
                "TEMPO-A-THREE",
                None,
                &Coverage::Solidity {
                    path: "tips/verify/test/X.t.sol".into(),
                    function: "invariant_holds".into()
                },
                12
            ),
            ("TEMPO-A-FOUR", None, &Coverage::None, 14),
            ("TEMPO-A-FIVE", None, &Coverage::None, 28),
        ]
    );
    assert_eq!(parsed[0].statement, "The first holds.");
}

#[test]
fn a_section_at_a_lower_level_ends_at_a_heading_of_its_level() {
    let markdown = "# Specification

## Invariants

### Pools

- `TEMPO-A-ONE`: Holds.
  - Checked by: none

## Next

- `TEMPO-NOT-HERE`: after the section.
";
    let ids: Vec<_> = invariants(markdown)
        .expect("the example is in the format")
        .into_iter()
        .map(|invariant| invariant.id)
        .collect();
    assert_eq!(ids, ["TEMPO-A-ONE"]);
}

#[test]
fn the_parser_rejects_what_breaks_the_format() {
    let cases = [
        ("- The pool is solvent.", "not \"- `TEMPO-"),
        (
            "- `TEMPO-lower`: Holds.\n  - Checked by: none",
            "the ID is not",
        ),
        ("- `AMM-1`: Holds.\n  - Checked by: none", "the ID is not"),
        ("- `TEMPO-A-B`: Holds.", "has no \"Checked by:\""),
        (
            "- `TEMPO-A-B`: Holds.\n  - Checked by: maybe",
            "coverage is check",
        ),
        (
            "- `TEMPO-A-B`: Holds.\n  - Checked by: `a.rs::`",
            "a Rust test is",
        ),
        (
            "- `TEMPO-A-B`: Holds.\n  - Checked by: none\n  - Since: T3",
            "comes once, before",
        ),
        (
            "- `TEMPO-A-B`: Holds.\n  - Checked by: none\n  - Checked by: check",
            "comes once",
        ),
        (
            "- `TEMPO-A-B`: Holds.\n  - Severity: high\n  - Checked by: none",
            "only \"- Since:\"",
        ),
        (
            "- `TEMPO-A-B`: Holds.\n  Across two lines.\n  - Checked by: none",
            "only \"- Since:\"",
        ),
        (
            "* `TEMPO-A-B`: Holds.\n  - Checked by: none",
            "\"- \" bullets",
        ),
        (
            "- `TEMPO-A-B`: Holds\n  - Checked by: none",
            "ending with a period",
        ),
        ("Prose.\n  - Checked by: none", "outside an invariant"),
        ("1. A case.\n   - A sub-bullet.", "outside an invariant"),
    ];
    for (body, error) in cases {
        let markdown = format!("# Invariants\n\n{body}\n");
        let errors = invariants(&markdown).expect_err(body);
        assert!(
            errors.iter().any(|found| found.contains(error)),
            "{body:?}: expected an error with {error:?}, got {errors:?}"
        );
    }
}

#[test]
fn commented_out_functions_and_helpers_are_not_tests() {
    let dir = std::env::temp_dir().join(format!("specs-lint-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("a.rs"),
        "// #[test]\n// fn commented() {}\n/* #[test]\nfn blocked() {} */\nfn helper() {}\n#[test]\nfn real() {}\n#[tokio::test(flavor = \"multi_thread\")]\nasync fn real_async() {}\n",
    )
    .unwrap();
    fs::write(
        dir.join("b.rs"),
        "const A: &str = \"/* not a comment // either\";\nconst B: char = '\"';\n#[test]\nfn after_strings() {}\n",
    )
    .unwrap();
    assert!(defines_rust_test(&dir, "b.rs", "after_strings").is_ok());
    fs::write(
        dir.join("a.t.sol"),
        "// function testGone() public {}\nfunction testHere() public {}\n",
    )
    .unwrap();
    fs::write(dir.join("a.sol"), "function testHere() public {}\n").unwrap();
    assert!(defines_rust_test(&dir, "a.rs", "commented").is_err());
    assert!(defines_rust_test(&dir, "a.rs", "blocked").is_err());
    assert_eq!(
        defines_rust_test(&dir, "a.rs", "helper"),
        Err("the function is not a test")
    );
    assert!(defines_rust_test(&dir, "a.rs", "real").is_ok());
    assert!(defines_rust_test(&dir, "a.rs", "real_async").is_ok());
    assert!(defines_solidity(&dir, "a.t.sol", "testGone").is_err());
    assert!(defines_solidity(&dir, "a.t.sol", "testHere").is_ok());
    assert!(defines_solidity(&dir, "a.sol", "testHere").is_err());
    fs::remove_dir_all(&dir).unwrap();
}
