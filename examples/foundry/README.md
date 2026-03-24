# Foundry TIP-20 Deployment Example

This example shows how to deploy a basic TIP-20 token on Tempo Moderato testnet,
mint an initial supply, and verify the deployed address in the explorer.

## Script

`scripts/DeployTip20Example.s.sol`

## Prerequisites

1. Foundry installed (`forge`, `cast`).
2. `forge-std` installed in your Foundry project.
3. A funded Tempo testnet account.

Get testnet funds:

```bash
cast rpc tempo_fundAddress <YOUR_ADDRESS> --rpc-url https://rpc.moderato.tempo.xyz
```

## Run

Copy the script into your Foundry project (example destination: `script/DeployTip20Example.s.sol`):

```bash
cp examples/foundry/scripts/DeployTip20Example.s.sol /path/to/your-foundry-project/script/
```

Export your private key:

```bash
export PRIVATE_KEY=<YOUR_PRIVATE_KEY_HEX>
```

From your Foundry project root, execute the script:

```bash
forge script script/DeployTip20Example.s.sol:DeployTip20Example \
  --rpc-url https://rpc.moderato.tempo.xyz \
  --broadcast
```

## Verify on Explorer

After broadcast, the script prints the token address and:

`https://explore.tempo.xyz/address/<TOKEN_ADDRESS>`

Open that URL to verify deployment and transaction activity.
