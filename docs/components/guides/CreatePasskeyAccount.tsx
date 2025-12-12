import { useAccount, useConnect, useConnectors, useDisconnect } from 'wagmi'

export function Connect() {
  const { connect } = useConnect()
  const connectors = useConnectors()

  const handleConnect =
    ({ type }: { type: 'sign-in' | 'sign-up' }) =>
    () => {
      const connector = connectors.find((c) => c.id === 'webAuthn')
      if (connector) {
        connect({ capabilities: { type }, connector })
      } else {
        console.error('webauthn connector not found')
      }
    }

  return (
    <div className="flex gap-3">
      <button
        type="button"
        onClick={handleConnect({ type: 'sign-in' })}
        className="px-3 py-1 bg-gray-200 hover:bg-gray-300 text-gray-900 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-gray-100 rounded-full font-medium transition-colors"
      >
        Log in
      </button>
      <button
        type="button"
        onClick={handleConnect({ type: 'sign-up' })}
        className="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white dark:bg-blue-500 dark:hover:bg-blue-600 rounded-full font-medium transition-colors"
      >
        Sign up
      </button>
    </div>
  )
}

export function ConnectAndDisconnect() {
  const { isConnected } = useAccount()
  const { connect } = useConnect()
  const connectors = useConnectors()
  const { disconnect } = useDisconnect()

  const handleConnect =
    ({ type }: { type: 'sign-in' | 'sign-up' }) =>
    () => {
      const connector = connectors.find((c) => c.id === 'webAuthn')
      if (connector) {
        connect({ capabilities: { type }, connector })
      } else {
        console.error('webauthn connector not found')
      }
    }

  const handleDisconnect = () => {
    disconnect()
  }

  if (!isConnected) {
    return (
      <div className="flex gap-3">
        <button
          type="button"
          onClick={handleConnect({ type: 'sign-in' })}
          className="px-2 py-1 bg-gray-200 hover:bg-gray-300 text-gray-900 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-gray-100 rounded-full font-medium transition-colors"
        >
          Log in
        </button>
        <button
          type="button"
          onClick={handleConnect({ type: 'sign-up' })}
          className="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white dark:bg-blue-500 dark:hover:bg-blue-600 rounded-full font-medium transition-colors"
        >
          Sign up
        </button>
      </div>
    )
  }

  return (
    <button
      type="button"
      onClick={handleDisconnect}
      className="px-2 py-1 bg-red-600 hover:bg-red-700 text-white dark:bg-red-500 dark:hover:bg-red-600 rounded-full font-medium transition-colors"
    >
      Disconnect
    </button>
  )
}
