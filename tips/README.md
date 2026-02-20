# Tempo Improvement Proposals (TIPs)

## Title Standards

- **Title**: Max 44 characters, a few words (not a complete sentence), Title Case
- **Description**: Max 140 characters, one short sentence
- Neither should include the word "standard" or the TIP number (exceptions: TIP-20, TIP-403)

Examples:
- Good: "Compound Transfer Policies"
- Bad: "TIP-1015: A Standard for Compound Transfer Policies for TIP-20 Tokens"

## Creating a New TIP

1. Copy template: `cp tips/tip_template.md tips/draft-<slug>.md`
2. Fill in content, leaving `id: TIP-XXXX` as-is
3. Open PR

On PR open, a GitHub Action assigns the next sequential TIP number, renames the file to `tip-<N>.md`, and replaces all `TIP-XXXX` references in the content.

## Picking a Specific Number

To reserve a specific TIP number, name your file `tip-<N>.md` directly (e.g., `tip-1050.md`). CI validates the number is not already used on main or in another open PR.

## Updating an Existing TIP

Edit `tips/tip-<N>.md` directly and open a PR.

## Number Assignment Details

The assignment workflow:

1. Scans `tips/tip-*.md` on main to find the highest existing number
2. Scans open PRs for `tip-*.md` files to find any reserved numbers
3. Assigns `max(both) + 1` to the new TIP
4. Renames the file and updates content in-place
5. Pushes a commit to the PR branch

A concurrency group ensures two simultaneous PRs cannot receive the same number.
