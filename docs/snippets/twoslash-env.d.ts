declare module 'tempo.ts/chains' {
  import type { Chain as viem_Chain } from 'viem'

  type Chain = viem_Chain & { feeToken: `0x${string}` }

  export function tempo(config: { feeToken: `0x${string}` }): Chain
  export const tempoAndantino: Chain
  export const tempoLocal: Chain
}
