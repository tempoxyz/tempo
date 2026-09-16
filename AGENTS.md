# Tempo

Tempo is a blockchain node built on [Reth SDK](https://github.com/paradigmxyz/reth).

## Pull Requests

- Format Rust code with `cargo +nightly fmt`.

## TIPs (Tempo Improvement Proposals)

When creating a new TIP:

- Run `./scripts/setup-hooks.sh` once per clone so Git runs the TIP naming hook.
- Branch: `tip/XXXX` where `XXXX` is the next available TIP number (check `tips/` directory and existing branches).
- File: `tips/tip-XXXX.md` matching the branch number.
- Follow the template in `tips/tip_template.md`.
- Follow the process and quality gates in `tips/tip-0000.md`.

### Titles

Use [Conventional Commits](https://www.conventionalcommits.org/) with an optional scope:

```
<type>(<scope>): <short description>
```

**Types**: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`

**Scope** (optional): crate or area, e.g. `evm`, `consensus`, `rpc`, `tip-1017`

Examples:
- `fix(rpc): correct gas estimation for TIP-20 transfers`
- `perf: batch trie updates to reduce cursor overhead`
- `feat(consensus): add checkpoint guard for batched state ops`

### Descriptions

Use the repository PR template: **Problem**, **Changes**, and **Validation**.
Keep each section concise; one or two sentences is usually enough. Add **Rollout**
only for deployment steps, migrations, compatibility risks, or rollback details.

- Describe the concrete problem, the final behavioral change, and why it solves the problem.
- Link related issues or TIPs. Include benchmark results for performance changes when available.
- State checks actually run and their results. If none ran, explain why; distinguish proposed checks from completed validation.
- Before opening a PR, and after changing its implementation, compare the saved title and body with the full diff against its actual base branch. Remove stale claims and preserve human-written context.
- Do not list every changed file, repeat the title, or use filler such as "This PR introduces...".
- Read back the saved PR description after creating or updating it.

The `PR description structure` check checks required sections and common placeholders;
it does not establish that the description matches the code. Reviewers must still
check claims against the implementation and available test evidence.
