import { useAccount, useConnect, useDisconnect } from 'wagmi'
import { Button, useWebAuthnConnector } from './Demo'

export function EmbedPasskeys() {
  const account = useAccount()
  const connect = useConnect()
  const connector = useWebAuthnConnector()
  const disconnect = useDisconnect()

  if (account.address)
    return (
      <div className="flex items-center gap-2">
        <Button onClick={() => disconnect.disconnect()} variant="destructive">
          Sign out
        </Button>
      </div>
    )
  if (connect.isPending)
    return (
      <div>
        <Button disabled>Check prompt</Button>
      </div>
    )
  if (!connector) return null
  return <SignInButtons />
}

export function SignInButtons() {
  const connect = useConnect()
  const connector = useWebAuthnConnector()
  const disconnect = useDisconnect()

  return (
    <div className="flex gap-1">
      <Button
        variant="accent"
        onClick={async () => {
          await disconnect.disconnectAsync().catch(() => {})
          connect.connect({
            connector,
            capabilities: {
              label: 'Tempo Docs',
              type: 'sign-up',
            },
          })
        }}
        type="button"
      >
        Sign up
      </Button>
      <Button
        variant="default"
        onClick={async () => {
          await disconnect.disconnectAsync().catch(() => {})
          connect.connect({ connector })
        }}
        type="button"
      >
        Sign in
      </Button>
    </div>
  )
}
