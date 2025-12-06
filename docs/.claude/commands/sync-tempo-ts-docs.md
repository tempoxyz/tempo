# Sync tempo.ts SDK Documentation

This skill documents the process for adding missing documentation for tempo.ts SDK functions. Use this when new functions are added to the SDK or when documentation gaps are discovered.

## First: Review Previously Skipped Functions

Before searching for new undocumented functions, display the "Undocumented Functions" list at the bottom of this document to the user and ask:

> "The following functions were previously marked as 'not ready to document'. Would you like to document any of them now?"

Use the AskUserQuestion tool to let the user select which (if any) they want to document. If they select any, document those first following the templates below. If they want to keep skipping all of them, proceed to Step 1.

## Overview

The tempo.ts SDK has three layers that need documentation:
1. **Viem Actions** - Low-level viem client actions (`pages/sdk/typescript/viem/`)
2. **Wagmi Actions** - Wagmi-compatible actions (`pages/sdk/typescript/wagmi/actions/`)
3. **Wagmi Hooks** - React hooks wrapping wagmi actions (`pages/sdk/typescript/wagmi/hooks/`)

Each layer has corresponding source files in `node_modules/tempo.ts/src/`:
- `viem/Actions/{module}.ts`
- `wagmi/Actions/{module}.ts`
- `wagmi/Hooks/{module}.ts`

## Step 1: Identify Missing Documentation

Compare source files against existing documentation:

```bash
# Source locations
node_modules/tempo.ts/src/viem/Actions/{module}.ts
node_modules/tempo.ts/src/wagmi/Actions/{module}.ts
node_modules/tempo.ts/src/wagmi/Hooks/{module}.ts

# Documentation locations
pages/sdk/typescript/viem/{module}.{function}.mdx
pages/sdk/typescript/wagmi/actions/{module}.{function}.mdx
pages/sdk/typescript/wagmi/hooks/{module}.use{Function}.mdx

# Index files that list all functions
pages/sdk/typescript/viem/actions.mdx
pages/sdk/typescript/wagmi/actions/index.mdx
pages/sdk/typescript/wagmi/hooks/index.mdx
```

List all exported functions from each source file and compare against existing `.mdx` files.

### Handling New SDK Functions (not in docs)

For each function that exists in the SDK but has no documentation (and is not in the "Undocumented Functions" list), use the AskUserQuestion tool to ask:

> "Found new SDK function `{module}.{functionName}`: {brief description}. What would you like to do?"

Options:
- **Document it** - Create documentation following the templates below
- **Skip for now** - Add to the "Undocumented Functions" list at the bottom of this file

### Handling Stale Documentation (in docs but not in SDK)

For each function that has documentation but no longer exists in the SDK, use the AskUserQuestion tool to ask:

> "Found stale documentation for `{module}.{functionName}` - this function no longer exists in the SDK. What would you like to do?"

Options:
- **Keep docs** - The function may be coming back or exists elsewhere
- **Remove docs** - Delete the .mdx file and remove from index files and sidebar

## Step 2: Create Viem Action Documentation

### File naming
`pages/sdk/typescript/viem/{module}.{functionName}.mdx`

### Write action template
```mdx
import WriteParameters from '../../../../snippets/write-parameters.mdx'

# `{module}.{functionName}`

{Brief description of what the function does.}

## Usage

Use the `{module}.{functionName}` action on the Viem `client` to {description}.

:::code-group

```ts twoslash [example.ts]
import { client, token } from './viem.config'

const { field1, field2, receipt } = await client.{module}.{functionName}Sync({
  param1: value1,
  token,
})

console.log('Field1:', field1)
// @log: Field1: expectedValue
```

```ts twoslash [viem.config.ts] filename="viem.config.ts"
// [!include ~/snippets/viem.config.ts:setup]
```

:::

### Asynchronous Usage

The example above uses a `*Sync` variant of the action, that will wait for the transaction to be included before returning.

If you are optimizing for performance, you should use the non-sync `{module}.{functionName}` action and wait for inclusion manually:

```ts twoslash
import { Actions } from 'tempo.ts/viem'
import { client, token } from './viem.config'

const hash = await client.{module}.{functionName}({
  param1: value1,
  token,
})
const receipt = await client.waitForTransactionReceipt({ hash })

const { args: { field1, field2 } }
  = Actions.{module}.{functionName}.extractEvent(receipt.logs)
```

## Return Type

```ts
type ReturnType = {
  /** Description of field1 */
  field1: Type
  /** Transaction receipt */
  receipt: TransactionReceipt
}
```

## Parameters

### param1

- **Type:** `Type`

Description of the parameter.

### token

- **Type:** `Address`

Address of the TIP-20 token.

<WriteParameters />
```

### Read action template
```mdx
import ReadParameters from '../../../../snippets/read-parameters.mdx'

# `{module}.{functionName}`

{Brief description.}

## Usage

:::code-group

```ts twoslash [example.ts]
import { client, token } from './viem.config'

const result = await client.{module}.{functionName}({
  token,
})

console.log('Result:', result)
// @log: Result: expectedValue
```

```ts twoslash [viem.config.ts] filename="viem.config.ts"
// [!include ~/snippets/viem.config.ts:setup]
```

:::

## Return Type

```ts
type ReturnType = bigint // or appropriate type
```

## Parameters

### token

- **Type:** `Address`

Address of the TIP-20 token.

<ReadParameters />
```

### Watch action template
```mdx
# `{module}.watch{EventName}`

Watches for {event description} events.

## Usage

:::code-group

```ts twoslash [example.ts]
import { client, token } from './viem.config'

const unwatch = client.{module}.watch{EventName}({
  on{EventName}: (args, log) => {
    console.log('Field1:', args.field1)
    console.log('Field2:', args.field2)
  },
  token,
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

### on{EventName}

- **Type:**

```ts
declare function on{EventName}(args: Args, log: Log): void

type Args = {
  /** Description */
  field1: Type
  /** Description */
  field2: Type
}
```

Callback to invoke when the event occurs.

### token

- **Type:** `Address`

Address of the TIP-20 token to watch.

### filterField (optional)

- **Type:** `Address | undefined`

Filter events by this field.
```

## Step 3: Create Wagmi Action Documentation

### File naming
`pages/sdk/typescript/wagmi/actions/{module}.{functionName}.mdx`

### Write action template
```mdx
import WriteParameters from '../../../../../snippets/write-parameters.mdx'

# `{module}.{functionName}`

{Brief description.}

## Usage

:::code-group

```ts twoslash [example.ts]
import { Actions } from 'tempo.ts/wagmi'
import { config } from './wagmi.config'

const { field1, receipt } = await Actions.{module}.{functionName}Sync(config, {
  param1: value1,
  token: '0x20c0000000000000000000000000000000000000',
})

console.log('Field1:', field1)
// @log: Field1: expectedValue
```

```ts twoslash [wagmi.config.ts] filename="wagmi.config.ts"
// @noErrors
// [!include ~/snippets/wagmi.config.ts:setup]
```

:::

### Asynchronous Usage

The example above uses a `*Sync` variant of the action, that will wait for the transaction to be included before returning.

If you are optimizing for performance, you should use the non-sync `{module}.{functionName}` action and wait for inclusion manually:

```ts twoslash
import { Actions } from 'tempo.ts/wagmi'
import { Actions as viem_Actions } from 'tempo.ts/viem'
import { waitForTransactionReceipt } from 'wagmi/actions'
import { config } from './wagmi.config'

const hash = await Actions.{module}.{functionName}(config, {
  param1: value1,
  token: '0x20c0000000000000000000000000000000000000',
})
const receipt = await waitForTransactionReceipt(config, { hash })

const { args: { field1 } }
  = viem_Actions.{module}.{functionName}.extractEvent(receipt.logs)
```

## Return Type

```ts
type ReturnType = {
  /** Description */
  field1: Type
  /** Transaction receipt */
  receipt: TransactionReceipt
}
```

## Parameters

### param1

- **Type:** `Type`

Description.

### token

- **Type:** `Address`

Address of the TIP-20 token.

<WriteParameters wagmi />
```

### Read action template
```mdx
import ReadParameters from '../../../../../snippets/read-parameters.mdx'

# `{module}.{functionName}`

{Brief description.}

## Usage

:::code-group

```ts twoslash [example.ts]
import { Actions } from 'tempo.ts/wagmi'
import { config } from './wagmi.config'

const result = await Actions.{module}.{functionName}(config, {
  token: '0x20c0000000000000000000000000000000000000',
})

console.log('Result:', result)
// @log: Result: expectedValue
```

```ts twoslash [wagmi.config.ts] filename="wagmi.config.ts"
// @noErrors
// [!include ~/snippets/wagmi.config.ts:setup]
```

:::

## Return Type

```ts
type ReturnType = bigint // or appropriate type
```

## Parameters

### token

- **Type:** `Address`

Address of the TIP-20 token.

<ReadParameters wagmi />
```

### Watch action template
```mdx
# `{module}.watch{EventName}`

Watches for {event description} events.

## Usage

:::code-group

```ts twoslash [example.ts]
import { Actions } from 'tempo.ts/wagmi'
import { config } from './wagmi.config'

const unwatch = Actions.{module}.watch{EventName}(config, {
  on{EventName}: (args, log) => {
    console.log('Field1:', args.field1)
  },
  token: '0x20c0000000000000000000000000000000000000',
})

// Later, stop watching
unwatch()
```

```ts twoslash [wagmi.config.ts] filename="wagmi.config.ts"
// @noErrors
// [!include ~/snippets/wagmi.config.ts:setup]
```

:::

## Return Type

```ts
type ReturnType = () => void
```

Returns a function to unsubscribe from the event.

## Parameters

### on{EventName}

- **Type:**

```ts
declare function on{EventName}(args: Args, log: Log): void

type Args = {
  /** Description */
  field1: Type
}
```

Callback to invoke when the event occurs.

### token

- **Type:** `Address`

Address of the TIP-20 token to watch.
```

## Step 4: Create Wagmi Hook Documentation

### File naming
`pages/sdk/typescript/wagmi/hooks/{module}.use{FunctionName}.mdx`

### Mutation hook template (for write operations)
```mdx
# `{module}.use{FunctionName}`

{Brief description.}

## Usage

:::code-group

```ts twoslash [example.ts]
// @errors: 2322
import { config } from './wagmi.config'
declare module 'wagmi' {
  interface Register {
    config: typeof config
  }
}
// ---cut---
import { Hooks } from 'tempo.ts/wagmi'

const { data: result, mutate } = Hooks.{module}.use{FunctionName}Sync()

// Call `mutate` in response to user action (e.g. button click, form submission)
mutate({
  param1: value1,
  token: '0x20c0000000000000000000000000000000000000',
})

console.log('Field1:', result.field1)
// @log: Field1: expectedValue
```

```ts twoslash [wagmi.config.ts] filename="wagmi.config.ts"
// @noErrors
// [!include ~/snippets/wagmi.config.ts:setup]
```

:::

### Asynchronous Usage

The example above uses a `*Sync` variant of the action, that will wait for the transaction to be included before returning.

If you are optimizing for performance, you should use the non-sync `{module}.{functionName}` action and wait for inclusion manually:

```ts twoslash
// @errors: 2322
declare module 'wagmi' {
  interface Register {
    config: typeof config
  }
}
// ---cut---
import { Hooks } from 'tempo.ts/wagmi'
import { Actions } from 'tempo.ts/viem'
import { useWaitForTransactionReceipt } from 'wagmi'
import { config } from './wagmi.config'

const { data: hash, mutate } = Hooks.{module}.use{FunctionName}()
const { data: receipt } = useWaitForTransactionReceipt({ hash })

// Call `mutate` in response to user action
mutate({
  param1: value1,
  token: '0x20c0000000000000000000000000000000000000',
})

if (receipt) {
  const { args: { field1 } }
    = Actions.{module}.{functionName}.extractEvent(receipt.logs)
}
```

## Return Type

See [TanStack Query mutation docs](https://tanstack.com/query/v5/docs/framework/react/reference/useMutation) for more info hook return types.

### data

See [Wagmi Action `{module}.{functionName}` Return Type](/sdk/typescript/wagmi/actions/{module}.{functionName}#return-type)

### mutate/mutateAsync

See [Wagmi Action `{module}.{functionName}` Parameters](/sdk/typescript/wagmi/actions/{module}.{functionName}#parameters)

## Parameters

### config

`Config | undefined`

[`Config`](https://wagmi.sh/react/api/createConfig#config) to use instead of retrieving from the nearest [`WagmiProvider`](https://wagmi.sh/react/api/WagmiProvider).

### mutation

See the [TanStack Query mutation docs](https://tanstack.com/query/v5/docs/framework/react/reference/useMutation) for more info hook parameters.
```

### Query hook template (for read operations)
```mdx
# `{module}.use{FunctionName}`

{Brief description.}

## Usage

:::code-group

```ts twoslash [example.ts]
// @errors: 2322
import { config } from './wagmi.config'
declare module 'wagmi' {
  interface Register {
    config: typeof config
  }
}
// ---cut---
import { Hooks } from 'tempo.ts/wagmi'

const { data: result } = Hooks.{module}.use{FunctionName}({
  token: '0x20c0000000000000000000000000000000000000',
})

console.log('Result:', result)
// @log: Result: expectedValue
```

```ts twoslash [wagmi.config.ts] filename="wagmi.config.ts"
// @noErrors
// [!include ~/snippets/wagmi.config.ts:setup]
```

:::

## Return Type

See [TanStack Query query docs](https://tanstack.com/query/v5/docs/framework/react/reference/useQuery) for more info hook return types.

### data

See [Wagmi Action `{module}.{functionName}` Return Type](/sdk/typescript/wagmi/actions/{module}.{functionName}#return-type)

## Parameters

See [Wagmi Action `{module}.{functionName}` Parameters](/sdk/typescript/wagmi/actions/{module}.{functionName}#parameters)

### query

See the [TanStack Query query docs](https://tanstack.com/query/v5/docs/framework/react/reference/useQuery) for more info hook parameters.
```

### Watch hook template
```mdx
# `{module}.useWatch{EventName}`

Watches for {event description} events.

## Usage

:::code-group

```ts twoslash [example.ts]
// @errors: 2322
import { config } from './wagmi.config'
declare module 'wagmi' {
  interface Register {
    config: typeof config
  }
}
// ---cut---
import { Hooks } from 'tempo.ts/wagmi'

Hooks.{module}.useWatch{EventName}({
  on{EventName}: (args, log) => {
    console.log('Field1:', args.field1)
  },
  token: '0x20c0000000000000000000000000000000000000',
})
```

```ts twoslash [wagmi.config.ts] filename="wagmi.config.ts"
// @noErrors
// [!include ~/snippets/wagmi.config.ts:setup]
```

:::

## Parameters

See [Wagmi Action `{module}.watch{EventName}` Parameters](/sdk/typescript/wagmi/actions/{module}.watch{EventName}#parameters)

### config

`Config | undefined`

[`Config`](https://wagmi.sh/react/api/createConfig#config) to use instead of retrieving from the nearest [`WagmiProvider`](https://wagmi.sh/react/api/WagmiProvider).
```

## Step 5: Update Index Files

### Update `pages/sdk/typescript/viem/actions.mdx`

Add entries to the appropriate section in the table:

```mdx
| **{Module} Actions** | |
| [`{module}.{functionName}`](/sdk/typescript/viem/{module}.{functionName}) | {Description} |
```

### Update `pages/sdk/typescript/wagmi/actions/index.mdx`

Add entries to the appropriate section:

```mdx
| **{Module} Actions** | |
| [`{module}.{functionName}`](/sdk/typescript/wagmi/actions/{module}.{functionName}) | {Description} |
```

### Update `pages/sdk/typescript/wagmi/hooks/index.mdx`

Add entries to the appropriate section:

```mdx
| **{Module} Hooks** | |
| [`{module}.use{FunctionName}`](/sdk/typescript/wagmi/hooks/{module}.use{FunctionName}) | Hook for {description} |
```

## Step 6: Update Sidebar Configuration

Edit `vocs.config.tsx` to add entries to the sidebar.

### Viem Actions sidebar (around line 550-860)

Find the appropriate module section and add entries alphabetically:

```tsx
{
  text: '{Module}',
  items: [
    {
      text: '{functionName}',
      link: '/sdk/typescript/viem/{module}.{functionName}',
    },
    // ... other items alphabetically
  ],
},
```

### Wagmi Actions sidebar (around line 890-1170)

Find or create the module section between existing sections:

```tsx
{
  text: '{Module}',
  items: [
    {
      text: '{functionName}',
      link: '/sdk/typescript/wagmi/actions/{module}.{functionName}',
    },
    // ... other items alphabetically
  ],
},
```

### Wagmi Hooks sidebar (around line 1195-1475)

Find or create the module section:

```tsx
{
  text: '{Module}',
  items: [
    {
      text: 'use{FunctionName}',
      link: '/sdk/typescript/wagmi/hooks/{module}.use{FunctionName}',
    },
    // ... other items alphabetically
  ],
},
```

## Checklist

For each new function, ensure:

- [ ] Viem action doc created (`pages/sdk/typescript/viem/{module}.{function}.mdx`)
- [ ] Wagmi action doc created (`pages/sdk/typescript/wagmi/actions/{module}.{function}.mdx`)
- [ ] Wagmi hook doc created (`pages/sdk/typescript/wagmi/hooks/{module}.use{Function}.mdx`)
- [ ] Viem index updated (`pages/sdk/typescript/viem/actions.mdx`)
- [ ] Wagmi actions index updated (`pages/sdk/typescript/wagmi/actions/index.mdx`)
- [ ] Wagmi hooks index updated (`pages/sdk/typescript/wagmi/hooks/index.mdx`)
- [ ] Viem sidebar updated in `vocs.config.tsx`
- [ ] Wagmi actions sidebar updated in `vocs.config.tsx`
- [ ] Wagmi hooks sidebar updated in `vocs.config.tsx`

## Module Categories

Common module categories used in the SDK:
- `amm` - Fee AMM liquidity operations
- `dex` - Stablecoin Exchange operations
- `faucet` - Testnet faucet operations
- `fee` - Fee token preference operations
- `policy` - Transfer policy operations
- `reward` - Reward distribution operations
- `token` - TIP-20 token operations

## Undocumented Functions

The following functions exist in the SDK but are intentionally not documented yet. Skip these when comparing SDK source files to documentation:

### Viem Actions
- `account.verifyHash` - Verifies signature validity for hash/address (supports Secp256k1, P256, WebAuthn)
- `dex.getOrders` - Paginated orders query via RPC
- `dex.getOrderbook` - Orderbook info query
- `token.getRoleAdmin` - Gets admin role for a specific role
- `token.prepareUpdateQuoteToken` - Prepares quote token update (two-step process)
- `token.updateQuoteToken` - Completes quote token update (two-step process)
- `token.watchUpdateQuoteToken` - Watches for quote token update events

### Wagmi Actions
- `dex.getOrders` - Paginated orders query via RPC
- `dex.getOrderbook` - Orderbook info query
- `token.getRoleAdmin` - Gets admin role for a specific role
- `token.updateQuoteToken` - Completes quote token update

### Wagmi Hooks
- `dex.useGetOrders` - Hook for paginated orders query
- `dex.useOrderbook` - Hook for orderbook info query
- `dex.usePriceLevel` - Hook for price level info (maps to getTickLevel)
- `token.useGetRoleAdmin` - Hook for getting admin role
- `token.useUpdateQuoteToken` - Hook for completing quote token update
