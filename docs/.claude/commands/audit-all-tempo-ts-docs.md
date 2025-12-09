---
description: "Audit all SDK docs with parallel agents. Usage: /audit-all-tempo-ts-docs [module] (e.g., token, dex, amm)"
---

# Batch Audit All tempo.ts SDK Documentation

Audit all **viem and wagmi action** documentation files against the TypeScript source code using parallel agents. Each agent will fix both the viem doc and corresponding wagmi action doc (if it exists).

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

**Wagmi action files:** `pages/sdk/typescript/wagmi/actions/*.mdx`
- Exclude: `index.mdx`

If `$ARGUMENTS` is provided (e.g., `token`), filter to only files matching `{module}.*.mdx`.

Use Glob tool:
```
pages/sdk/typescript/viem/{module}.*.mdx
```

Extract `module.function` from each filename (e.g., `token.transfer.mdx` → `token transfer`).

Note: The agent will handle both viem and wagmi docs for each action - no need to separately list wagmi files.

### Step 2: Launch Parallel Agents

For each unique `module.function` pair, spawn a Task agent with `subagent_type: "tempo-ts-sdk-doc-fixer"`.

**IMPORTANT:** Launch agents in parallel batches. Use a single message with multiple Task tool calls.

Each agent prompt should be:

```
Fix the tempo.ts SDK documentation for {module}.{function}.
```

### Step 3: Collect Results

Wait for all agents to complete using AgentOutputTool.

### Step 4: Generate Summary Report

Compile results from all agents into a summary:

```markdown
## Batch Audit Results

**Actions audited:** {count}
**Viem docs fixed:** {count}
**Wagmi docs fixed:** {count}
**Total fixes applied:** {sum}

### Results by Action

| Action | Viem | Wagmi Action | Fixes Applied |
|--------|------|--------------|---------------|
| token.transfer | ✓ Fixed | ✓ Fixed | 4 |
| token.getBalance | ✓ OK | ✓ OK | 0 |
| dex.buy | ✓ Fixed | — (no doc) | 1 |
| ... | ... | ... | ... |

Legend:
- ✓ OK = No issues found
- ✓ Fixed = Issues found and fixed
- — (no doc) = Wagmi action doc doesn't exist

### Fix Details

#### token.transfer
**Viem:**
- Added missing `from` parameter
- Fixed `token` optionality

**Wagmi Action:**
- Added missing `from` parameter
- Fixed `token` optionality

#### dex.buy
**Viem:**
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
