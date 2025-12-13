# Tempo SDK Examples

## Adding Tempo Testnet to wagmi/viem

Copy the code from the file `tempoTestnetChain.ts` into your project.

This file contains the official Tempo Testnet chain configuration for easy integration with wagmi or viem.

Example usage:

```ts
import { tempoTestnet } from './tempoTestnetChain'

createConfig({
  chains: [tempoTestnet],
  transports: {
    [tempoTestnet.id]: http(),
  },
})

cat > docs/examples/README.md << 'EOF'
# Tempo SDK Examples

## Adding Tempo Testnet to wagmi/viem

Copy the code from the file `tempoTestnetChain.ts` into your project.

This file contains the official Tempo Testnet chain configuration for easy integration with wagmi or viem.

Example usage:

```ts
import { tempoTestnet } from './tempoTestnetChain'

createConfig({
  chains: [tempoTestnet],
  transports: {
    [tempoTestnet.id]: http(),
  },
})
git add docs/examples
