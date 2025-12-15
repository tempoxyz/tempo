---
description: "Fix a single SDK action's docs. Usage: /fix-tempo-ts-sdk-doc <module> <function> (e.g., token transfer)"
---

# Fix tempo.ts SDK Documentation

Fix existing documentation pages for both **viem** and **wagmi actions** by comparing them against the underlying TypeScript source code to ensure parameters and return values are accurate.

## Usage

Run this command with a module and function name:
```
/fix-tempo-ts-sdk-doc $ARGUMENTS
```

Where `$ARGUMENTS` is the module and function name (e.g., `token transfer`).

This will fix documentation for:
- **Viem:** `pages/sdk/typescript/viem/{module}.{function}.mdx`
- **Wagmi Actions:** `pages/sdk/typescript/wagmi/actions/{module}.{function}.mdx` (if exists)

## Workflow

### Step 1: Extract Types from Source Code

First, run the type extraction script to get the authoritative type information:

```bash
bun extract-sdk-types <module> <function>
```

For example, for `pages/sdk/typescript/viem/token.transfer.mdx`:
```bash
bun extract-sdk-types token transfer
```

This will output a JSON file to `.claude/sdk-types/<module>.<function>.json`.

**Read the generated JSON file** to get the authoritative parameter and return type information.

### Step 2: Understand the JSON Schema

The extracted JSON contains:

```typescript
interface TypeInfo {
  module: string           // e.g., "token"
  function: string         // e.g., "transfer"
  actionType: 'read' | 'write' | 'watch'
  hasSyncVariant: boolean  // true for write actions
  parameters: ParamInfo[]
  returnType: ReturnTypeInfo
  syncReturnType?: ReturnTypeInfo  // For write actions
  callbackArgs?: ReturnTypeInfo    // For watch actions
  sourceFile: string
}

interface ParamInfo {
  name: string
  type: string
  optional: boolean
  description?: string
  // For object types - expanded fields
  fields?: Record<string, ParamInfo>
  // For function types - expanded signature
  functionSignature?: {
    parameters: ParamInfo[]
    returnType: string
  }
}
```

### Step 3: Compare Against Documentation

Read **both** documentation files (if they exist) and compare against the extracted JSON:

1. **Viem doc:** `pages/sdk/typescript/viem/{module}.{function}.mdx`
2. **Wagmi action doc:** `pages/sdk/typescript/wagmi/actions/{module}.{function}.mdx`

Use Glob to check which files exist before reading them.

#### Action-Type Specific Checks

**Read Actions** (`actionType: "read"`):
- Should NOT have `*Sync` variant in examples
- Should use `<ReadParameters />` snippet OR `<ReadAccountParameters />` snippet (see below)
- Return type is usually a simple value (e.g., `bigint`)

**ReadParameters vs ReadAccountParameters:**
- `<ReadParameters />` includes an optional `account` parameter at the top
- `<ReadAccountParameters />` does NOT include account (only blockNumber, blockOverrides, blockTag, stateOverride)
- **IMPORTANT:** If the action has a **required** `account` parameter documented explicitly, use `<ReadAccountParameters />` to avoid duplicate account parameters
- If the action does NOT have a required `account` parameter, use `<ReadParameters />`

**Write Actions** (`actionType: "write"`):
- Should have `*Sync` variant (preferred in examples)
- Should use `<WriteParameters />` snippet
- `syncReturnType.fields` contains the return object shape
- Async variant returns `0x${string}` (transaction hash)

**Watch Actions** (`actionType: "watch"`):
- Return type is `() => void` (unsubscribe function)
- Has `onXxx` callback parameter with `functionSignature`
- `callbackArgs` describes what's passed to the callback
- May have optional `args` parameter for filtering

#### Parameters Checklist

For each parameter in `parameters`:

- [ ] Parameter is documented
- [ ] Type matches (see Type Mappings below)
- [ ] Optionality correct: `optional: false` = required, `optional: true` = "(optional)"
- [ ] If `fields` exists, nested properties should be documented
- [ ] If `functionSignature` exists, callback parameters should be documented

#### Type Display Rules

- **Simple types** (e.g., `bigint`, `Address`, `number`, `true`): Use inline format only
  ```mdx
  - **Type:** `bigint`
  ```

- **Object types** (parameter has `fields`): Use `object` label with code block expansion
  ```mdx
  - **Type:** `object`

  ```ts
  type Args = {
    /** Description from fields */
    fieldName: FieldType
  }
  ```
  ```

- **Function types** (parameter has `functionSignature`): Use `function` label with code block expansion
  ```mdx
  - **Type:** `function`

  ```ts
  declare function onTransfer(args: Args, log: Log): void

  type Args = {
    /** Description from fields */
    fieldName: FieldType
  }
  ```
  ```

#### Function Parameters (for callbacks)

When a parameter has `functionSignature`, document it as:

```mdx
### onTransfer

- **Type:** `function`

```ts
declare function onTransfer(args: Args, log: Log): void

type Args = {
  /** Description from fields */
  fieldName: FieldType
}
```

Description from the parameter.
```

#### Object Parameters

When a parameter has `fields`, document it as:

```mdx
### args (optional)

- **Type:** `object`

```ts
type Args = {
  /** Description */
  fieldName?: FieldType
}
```

Description from the parameter.
```

### Step 4: Report Findings

Create a table summarizing the audit for **each documentation file**:

```markdown
## Audit Results for `{module}.{function}`

### Viem Documentation

**File:** `pages/sdk/typescript/viem/{module}.{function}.mdx`

#### Parameters

| Parameter | Documentation | Source Code | Status |
|-----------|---------------|-------------|--------|
| param1 | `Type` (required) | `Type` (required) | OK |
| param2 | Missing | `Type` (optional) | Missing |

#### Issues Found
1. Issue description

---

### Wagmi Action Documentation

**File:** `pages/sdk/typescript/wagmi/actions/{module}.{function}.mdx`

#### Parameters

| Parameter | Documentation | Source Code | Status |
|-----------|---------------|-------------|--------|
| param1 | `Type` (required) | `Type` (required) | OK |

#### Issues Found
1. Issue description (or "No issues found")
```

If a wagmi action doc doesn't exist, note it in the report but don't create it.

### Step 5: Fix Issues

After presenting the audit results, ask the user if they want to fix the issues:

Use AskUserQuestion:
> "Found {N} issues across {viem/wagmi} documentation. Would you like me to fix them?"

Options:
- **Fix all** - Apply all fixes to both viem and wagmi docs automatically
- **Review each** - Show each fix before applying
- **Skip** - Don't make changes

Apply fixes to **both** documentation files where applicable.

## Type Mappings

When comparing JSON types to documentation types:

| JSON Type | Documentation Type |
|-----------|-------------------|
| `bigint` | `bigint` |
| `` `0x${string}` `` | `Address` or `Hex` |
| `TokenIdOrAddress` | `Address \| bigint` |
| `Account \| Address` | `Account \| Address` |
| `TransactionReceipt` | `TransactionReceipt` |
| `Log` | `Log` |
| `true` | `true` (literal type) |

## Documentation Templates

### Read Action Template

**Note:** If the action has a required `account` parameter, use `ReadAccountParameters` instead of `ReadParameters` to avoid duplicate account documentation.

```mdx
// Use ReadAccountParameters if action has required 'account' param:
import ReadAccountParameters from '../../../../snippets/read-account-parameters.mdx'
// Otherwise use ReadParameters:
import ReadParameters from '../../../../snippets/read-parameters.mdx'

# `{module}.{function}`

{Description of what this function does.}

## Usage

:::code-group

```ts twoslash [example.ts]
import { client } from './viem.config'

const result = await client.{module}.{function}({
  // required params
})

console.log('Result:', result)
```

```ts twoslash [viem.config.ts] filename="viem.config.ts"
// [!include ~/snippets/viem.config.ts:setup]
```

:::

## Return Type

```ts
type ReturnType = {returnType.type}
```

## Parameters

### {paramName}

- **Type:** `{type}`

{description}

// If action has required 'account' param:
<ReadAccountParameters />
// Otherwise:
<ReadParameters />
```

### Write Action Template

```mdx
import WriteParameters from '../../../../snippets/write-parameters.mdx'

# `{module}.{function}`

{Description of what this function does.}

## Usage

:::code-group

```ts twoslash [example.ts]
import { client } from './viem.config'

const { receipt } = await client.{module}.{functionSync}({
  // required params
})

console.log('Transaction hash:', receipt.transactionHash)
```

```ts twoslash [viem.config.ts] filename="viem.config.ts"
// [!include ~/snippets/viem.config.ts:setup]
```

:::

### Asynchronous Usage

The example above uses a `*Sync` variant of the action, that will wait for the transaction to be included before returning.

If you are optimizing for performance, you should use the non-sync `{module}.{function}` action and wait for inclusion manually:

```ts twoslash
import { Actions } from 'tempo.ts/viem'
import { client } from './viem.config'

const hash = await client.{module}.{function}({
  // required params
})
const receipt = await client.waitForTransactionReceipt({ hash })

const { args }
  = Actions.{module}.{function}.extractEvent(receipt.logs)
```

## Return Type

```ts
type ReturnType = {
  // Fields from syncReturnType.fields
}
```

## Parameters

### {paramName}

- **Type:** `{type}`

{description}

<WriteParameters />
```

### Watch Action Template

```mdx
# `{module}.{function}`

{Description of what this action watches.}

## Usage

:::code-group

```ts twoslash [example.ts]
import { client } from './viem.config'

const unwatch = client.{module}.{function}({
  onXxx: (args, log) => {
    // handle event
  },
})

// Later, stop watching
unwatch()
```

```ts twoslash [viem.config.ts] filename="viem.config.ts"
// [!include ~/snippets/viem.config.ts:setup]
```

:::

## Return Type

```ts
type ReturnType = () => void
```

Returns a function to unsubscribe from the event.

## Parameters

### onXxx

- **Type:** `function`

```ts
declare function onXxx(args: Args, log: Log): void

type Args = {
  // Fields from callbackArgs.fields or functionSignature.parameters[0].fields
}
```

{description}

### token

- **Type:** `Address | bigint`

Address or ID of the TIP20 token to watch.
```

## Wagmi Action Templates

Wagmi action docs follow the same structure as viem docs with these key differences:

### Wagmi Write Action Template

```mdx
import WriteParameters from '../../../../../snippets/write-parameters.mdx'

# `{module}.{function}`

{Description of what this function does.}

## Usage

:::code-group

```ts twoslash [example.ts]
import { Actions } from 'tempo.ts/wagmi'
import { config } from './wagmi.config'

const { receipt } = await Actions.{module}.{functionSync}(config, {
  // required params
})

console.log('Transaction hash:', receipt.transactionHash)
```

```ts twoslash [wagmi.config.ts] filename="wagmi.config.ts"
// @noErrors
// [!include ~/snippets/wagmi.config.ts:setup]
```

:::

### Asynchronous Usage

The example above uses a `*Sync` variant of the action, that will wait for the transaction to be included before returning.

If you are optimizing for performance, you should use the non-sync `{module}.{function}` action and wait for inclusion manually:

```ts twoslash
import { Actions } from 'tempo.ts/wagmi'
import { Actions as viem_Actions } from 'tempo.ts/viem'
import { waitForTransactionReceipt } from 'wagmi/actions'
import { config } from './wagmi.config'

const hash = await Actions.{module}.{function}(config, {
  // required params
})
const receipt = await waitForTransactionReceipt(config, { hash })

const { args }
  = viem_Actions.{module}.{function}.extractEvent(receipt.logs)
```

## Return Type

```ts
type ReturnType = {
  // Fields from syncReturnType.fields
}
```

## Parameters

### {paramName}

- **Type:** `{type}`

{description}

<WriteParameters wagmi />
```

### Wagmi Read Action Template

**Note:** If the action has a required `account` parameter, use `ReadAccountParameters` instead of `ReadParameters` to avoid duplicate account documentation.

```mdx
// Use ReadAccountParameters if action has required 'account' param:
import ReadAccountParameters from '../../../../../snippets/read-account-parameters.mdx'
// Otherwise use ReadParameters:
import ReadParameters from '../../../../../snippets/read-parameters.mdx'

# `{module}.{function}`

{Description of what this function does.}

## Usage

:::code-group

```ts twoslash [example.ts]
import { Actions } from 'tempo.ts/wagmi'
import { config } from './wagmi.config'

const result = await Actions.{module}.{function}(config, {
  // required params
})

console.log('Result:', result)
```

```ts twoslash [wagmi.config.ts] filename="wagmi.config.ts"
// @noErrors
// [!include ~/snippets/wagmi.config.ts:setup]
```

:::

## Return Type

```ts
type ReturnType = {returnType.type}
```

## Parameters

### {paramName}

- **Type:** `{type}`

{description}

// If action has required 'account' param:
<ReadAccountParameters wagmi />
// Otherwise:
<ReadParameters wagmi />
```

### Key Differences: Viem vs Wagmi

| Aspect | Viem | Wagmi |
|--------|------|-------|
| Import | `import { client } from './viem.config'` | `import { Actions } from 'tempo.ts/wagmi'` |
| Call style | `client.{module}.{function}(...)` | `Actions.{module}.{function}(config, ...)` |
| Config file | `viem.config.ts` | `wagmi.config.ts` |
| Snippet path | `../../../../snippets/` | `../../../../../snippets/` |
| Parameters snippet | `<WriteParameters />` | `<WriteParameters wagmi />` |

## Example Audit

For `token.transfer`:

1. Run: `bun extract-sdk-types token transfer`
2. Read `.claude/sdk-types/token.transfer.json`
3. Read both doc files:
   - `pages/sdk/typescript/viem/token.transfer.mdx`
   - `pages/sdk/typescript/wagmi/actions/token.transfer.mdx`
4. Compare parameters and return types against source
5. Report findings for each file
6. Fix discrepancies in both files
