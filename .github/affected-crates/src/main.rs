//! Prints the tempo workspace packages that a change affects, one per line, or `all` when it
//! affects every package. Changed paths, relative to the workspace root, are read from stdin.
//!
//! Usage: `git diff --name-only BASE HEAD | affected-crates <base checkout> <head checkout> <rules.toml>`

use std::{
    error::Error,
    io::{self, BufRead},
};

use determinator::{Determinator, rules::DeterminatorRules};
use guppy::{MetadataCommand, graph::DependencyDirection};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [old_dir, new_dir, rules_path] = args.as_slice() else {
        return Err("usage: affected-crates <base checkout> <head checkout> <rules.toml>".into());
    };

    let old = MetadataCommand::new().current_dir(old_dir).build_graph()?;
    let new = MetadataCommand::new().current_dir(new_dir).build_graph()?;
    let rules = DeterminatorRules::parse(&std::fs::read_to_string(rules_path)?)?;
    let changed_paths = io::stdin().lock().lines().collect::<Result<Vec<_>, _>>()?;

    let mut determinator = Determinator::new(&old, &new);
    determinator.set_rules(&rules)?;
    determinator.add_changed_paths(changed_paths.iter().map(String::as_str));
    let affected = determinator.compute().affected_set;

    if affected.len() == new.workspace().member_count() {
        println!("all");
    } else {
        for package in affected.packages(DependencyDirection::Forward) {
            println!("{}", package.name());
        }
    }
    Ok(())
}
