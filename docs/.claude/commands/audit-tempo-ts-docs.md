---
description: "Audit a single SDK action's docs. Usage: /audit-tempo-ts-docs <module> <function> (e.g., token transfer)"
---

# Audit tempo.ts SDK Documentation

Audit an existing documentation page against the underlying TypeScript source code to ensure parameters and return values are accurate. Can also generate documentation from the extracted types.

## Usage

Run this command with a documentation file path:
```
/audit-tempo-ts-docs $ARGUMENTS
```

Where `$ARGUMENTS` is the path to the `.mdx` documentation file to audit (e.g., `pages/sdk/typescript/viem/token.transfer.mdx`).

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

Read the documentation file and compare against the extracted JSON.

#### Action-Type Specific Checks

**Read Actions** (`actionType: "read"`):
- Should NOT have `*Sync` variant in examples
- Should use `<ReadParameters />` snippet
- Return type is usually a simple value (e.g., `bigint`)

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

Create a table summarizing the audit:

```markdown
## Audit Results for `{module}.{function}`

### Parameters

| Parameter | Documentation | Source Code | Status |
|-----------|---------------|-------------|--------|
| param1 | `Type` (required) | `Type` (required) | OK |
| param2 | Missing | `Type` (optional) | Missing |
| param3 | `Type` (optional) | `Type` (required) | Wrong optionality |

### Return Type

| Field | Documentation | Source Code | Status |
|-------|---------------|-------------|--------|
| field1 | `Type` | `Type` | OK |

### Issues Found
1. Issue description
2. Issue description
```

### Step 5: Fix Issues

After presenting the audit results, ask the user if they want to fix the issues:

Use AskUserQuestion:
> "Found {N} issues in the documentation. Would you like me to fix them?"

Options:
- **Fix all** - Apply all fixes automatically
- **Review each** - Show each fix before applying
- **Skip** - Don't make changes

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

```mdx
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

## Example Audit

For `pages/sdk/typescript/viem/token.watchTransfer.mdx`:

1. Run: `bun extract-sdk-types token watchTransfer`
2. Read `.claude/sdk-types/token.watchTransfer.json`
3. Note: `actionType: "watch"`, check for:
   - `onTransfer` callback with `functionSignature`
   - `callbackArgs` for the Args type shape
   - Optional `args` parameter for filtering by `from`/`to`
4. Read the doc file
5. Compare and report findings:
   - Is `args` parameter documented? (optional filter parameter)
   - Is `onTransfer` callback signature correct?
   - Are all callback args fields documented?
6. Fix discrepancies
