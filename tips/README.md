# Tempo Improvement Proposals (TIPs)

This directory contains all Tempo Improvement Proposals.

## Creating a New TIP

1. **Copy the template:**
   ```bash
   cp tips/tip_template.md tips/draft-<your-slug>.md
   ```
   Example: `tips/draft-compound-transfer-policies.md`

2. **Fill in the content** - leave `id: TIP-XXXX` as-is in the frontmatter

3. **Open a Pull Request** - your TIP number will be assigned automatically based on the PR number

4. **On merge**, CI renames your file to `tip-<PR_NUMBER>.md` and updates the frontmatter

## Updating an Existing TIP

1. **Branch naming**: Include the TIP number in your branch name
   - Example: `fix/tip-1000-clarify-gas-limits`

2. **Edit the file directly**: `tips/tip-1000.md`

3. **Open a Pull Request**

## Why PR Numbers?

Using PR numbers as TIP numbers provides:

- **Zero collisions**: GitHub guarantees unique PR numbers
- **No coordination overhead**: No need to manually reserve numbers
- **Full traceability**: Every TIP links directly to its originating PR
- **Works at any velocity**: No bottleneck on number assignment

## TIP Lifecycle

```
Draft → In Review → Approved → In Progress → Devnet → QA/Integration → Testnet → Mainnet
                                                                                    ↓
                                                                              Deprecated
```

## File Naming

| Stage | Filename |
|-------|----------|
| Draft (in PR) | `draft-<slug>.md` |
| Merged | `tip-<PR_NUMBER>.md` |
