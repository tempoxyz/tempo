```markdown
# External contributor checklist
```
This checklist is intended for contributors who are making their first pull request to Tempo.

## 1. Before you start

- Read the main `CONTRIBUTING.md` in the repository root.
- Pick an issue labeled `good first issue` or `A-help-wanted`, or open a new issue if you are proposing a larger change.

## 2. Local development

- Ensure you can run the basic local workflows:
  - `just` (or `cargo test` if `just` is not available)
  - `cargo fmt --all`
  - `cargo clippy --all-targets --all-features -- -D warnings`
If any of these fail, mention it in your pull request description.

## 3. Writing your change

- Keep the pull request focused on a single topic.
- Prefer small, incremental changes over "mega" PRs.
- Add or update tests when you change behavior.

## 4. Opening a PR

In your PR description, briefly include:

- What you changed
- Why the change is useful
- How you tested it (commands you ran locally)
This makes it easier for maintainers to review and merge contributions quickly.
