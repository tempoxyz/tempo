# tempo-xtask

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.

# Tempo xtask runner

This crate follows the [`xtask`](https://github.com/matklad/cargo-xtask) pattern for project automation.

Instead of adding complex scripts to CI or shell, we keep repeatable workflows as Rust code in this crate.

## Running tasks

From the repository root, you can discover available tasks with:

```bash
cargo run -p xtask -- --help
