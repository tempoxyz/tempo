import type { Connector } from 'wagmi'

const UNSUPPORTED_WALLET_IDS = new Set(['app.phantom'])
const UNSUPPORTED_WALLET_NAMES = new Set(['Phantom'])

export function filterSupportedInjectedConnectors(connectors: readonly Connector[]) {
  return connectors.filter(
    (connector) =>
      connector.id !== 'webAuthn' &&
      !UNSUPPORTED_WALLET_IDS.has(connector.id) &&
      !UNSUPPORTED_WALLET_NAMES.has(connector.name),
  )
}
