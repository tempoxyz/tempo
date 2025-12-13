import { defineChain } from 'viem'

/**
 * Tempo Testnet configuration for viem and wagmi
 * 
 * Use this to add Tempo Testnet to your dApp:
 * 
 * import { tempoTestnet } from './tempoTestnetChain'
 * 
 * createConfig({
 *   chains: [tempoTestnet],
 *   ...
 * })
 */
export const tempoTestnet = defineChain({
  id: 42429,
  name: 'Tempo Testnet (Andantino)',
  nativeCurrency: {
    decimals: 18,
    name: 'USD',
    symbol: 'USD',
  },
  rpcUrls: {
    default: {
      http: ['https://rpc.testnet.tempo.xyz'],
      webSocket: ['wss://rpc.testnet.tempo.xyz'],
    },
  },
  blockExplorers: {
    default: {
      name: 'Tempo Explorer',
      url: 'https://explore.tempo.xyz',
    },
  },
  testnet: true,
})
