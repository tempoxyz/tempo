# Tempo crates overview

This document is a living index for the Rust crates under the `crates/` directory.

## How to use this file

- When you add a new crate under `crates/`, add a one-line description below.
- When you rename or remove a crate, update this list in the same pull request.
- Keep descriptions short (one sentence) and focused on what the crate is responsible for.

## Conventions

- Prefer small, focused crates with a single responsibility.
- Share common types and utilities via dedicated shared crates instead of copy-pasting.
- Document any experimental or internal-only crates as such so contributors know whether they should rely on them.

## Known crates

Add or update entries in this section as the project evolves:

- `crates/<crate-name>` – short description of what this crate does.
- `crates/<another-crate>` – another one-line summary.
