---
description: "Audit all SDK docs with parallel agents. Usage: /audit-all-tempo-ts-docs [module] (e.g., token, dex, amm)"
---

# Batch Audit All tempo.ts SDK Documentation

Audit all viem and wagmi action documentation files against the TypeScript source code using parallel agents.

## Usage

```
/audit-all-tempo-ts-docs $ARGUMENTS
```

- No argument: audit all modules (71 unique actions)
- With argument: audit only that module (e.g., `token`, `dex`, `amm`, `policy`, `reward`, `fee`, `faucet`)

## Workflow

### Step 1: Collect Unique Actions

Find all action documentation files and extract unique `module.function` pairs.

**Viem files:** `pages/sdk/typescript/viem/*.mdx`
- Exclude: `actions.mdx`, `setup.mdx`, `transports.mdx`, `withFeePayer.mdx`

If `$ARGUMENTS` is provided (e.g., `token`), filter to only files matching `{module}.*.mdx`.

Use Glob tool:
```
pages/sdk/typescript/viem/{module}.*.mdx
```

Extract `module.function` from each filename (e.g., `token.transfer.mdx` → `token transfer`).

### Step 2: Launch Parallel Agents

For each unique `module.function` pair, spawn a Task agent with `subagent_type: "general-purpose"`.

**IMPORTANT:** Launch agents in parallel batches. Use a single message with multiple Task tool calls.

Each agent prompt should be:

```
Audit and fix the tempo.ts SDK documentation for {module}.{function}.

## Instructions

1. Run type extraction:
   ```bash
   bun extract-sdk-types {module} {function}
   ```

2. Read the generated JSON from `.claude/sdk-types/{module}.{function}.json`

3. Read BOTH documentation files:
   - `pages/sdk/typescript/viem/{module}.{function}.mdx`
   - `pages/sdk/typescript/wagmi/actions/{module}.{function}.mdx`

4. Compare each doc against the extracted types:
   - Check all parameters are documented
   - Check types match (use `Address` for `0x${string}`, `Address | bigint` for `TokenIdOrAddress`)
   - Check optionality is correct (`optional: false` = required, `optional: true` = "(optional)")
   - For object types: use `- **Type:** \`object\`` with code block
   - For function types: use `- **Type:** \`function\`` with code block

5. **Automatically fix any issues found** - do not ask for confirmation

6. Return a summary:
   - Files checked
   - Issues found and fixed (list each)
   - Or "No issues found" if clean
```

### Step 3: Collect Results

Wait for all agents to complete using AgentOutputTool.

### Step 4: Generate Summary Report

Compile results from all agents into a summary:

```markdown
## Batch Audit Results

**Actions audited:** {count}
**Actions with fixes:** {count}
**Total fixes applied:** {sum}

### Results by Action

| Action | Viem | Wagmi | Fixes Applied |
|--------|------|-------|---------------|
| token.transfer | ✓ Fixed | ✓ Fixed | 2 |
| token.getBalance | ✓ OK | ✓ OK | 0 |
| dex.buy | ✓ Fixed | ✓ OK | 1 |
| ... | ... | ... | ... |

### Fix Details

#### token.transfer
- Added missing `from` parameter to viem doc
- Fixed `token` optionality in viem doc

#### dex.buy
- Added missing `args` filter parameter
```

## Parallelization Strategy

- **Batch size:** Launch up to 10 agents in parallel per message
- **For full audit (71 actions):** ~7-8 batches of parallel agents
- **For module audit (e.g., token with 25 actions):** 2-3 batches

Example for token module:
```
Message 1: Launch agents for token.transfer, token.getBalance, token.create, ... (10 agents)
Message 2: Launch agents for token.approve, token.allowance, ... (10 agents)
Message 3: Launch agents for remaining token actions (5 agents)
Wait for all agents, compile results
```

## Module Reference

| Module | Actions | Parallel Batches |
|--------|---------|------------------|
| token | 25 | 3 |
| dex | 16 | 2 |
| policy | 10 | 1 |
| amm | 9 | 1 |
| reward | 7 | 1 |
| fee | 3 | 1 |
| faucet | 1 | 1 |
| **Total** | **71** | **~8** |
