# Tempo Improvement Proposals (TIPs)

## Creating a New TIP

1. Copy template: `cp tips/tip_template.md tips/draft-<slug>.md`
2. Fill in content (leave `id: TIP-XXXX` as-is)
3. Open PR — on merge, CI renames to `tip-<PR_NUMBER>.md`

## Updating an Existing TIP

Edit `tips/tip-<NUMBER>.md` directly and open a PR.

## How TIP Numbers Are Assigned

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Create draft                                                │
│     cp tips/tip_template.md tips/draft-my-feature.md            │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Open PR #2400                                               │
│     File: tips/draft-my-feature.md                              │
│     Frontmatter: id: TIP-XXXX                                   │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. PR merges → CI runs tip-number.yml                          │
│     • Renames draft-my-feature.md → tip-2400.md                 │
│     • Updates frontmatter: id: TIP-2400                         │
│     • Commits to main                                           │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Result                                                      │
│     File: tips/tip-2400.md                                      │
│     TIP number = PR number (guaranteed unique)                  │
└─────────────────────────────────────────────────────────────────┘
```

## Lifecycle

Draft → In Review → Approved → In Progress → Devnet → QA/Integration → Testnet → Mainnet → Deprecated
