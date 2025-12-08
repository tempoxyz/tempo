import { useAccount, useWatchAsset } from 'wagmi'
import { Button } from './guides/Demo'

type Token = {
  address: `0x${string}`
  symbol: string
  decimals: number
  image?: string
}

export function AddToken({
  token,
  requireWallet = true,
}: {
  token: Token
  requireWallet?: boolean
}) {
  const { isConnected } = useAccount()
  const { watchAsset, isSuccess, isPending } = useWatchAsset()

  if (requireWallet && !isConnected) {
    return null
  }

  return (
    <div className="flex flex-col gap-2">
      <Button
        variant="default"
        className="w-fit"
        onClick={() =>
          watchAsset({
            type: 'ERC20',
            options: {
              address: token.address,
              symbol: token.symbol,
              decimals: token.decimals,
              image: token.image,
            },
          })
        }
        disabled={isPending || isSuccess}
      >
        {isSuccess
          ? `${token.symbol} Added!`
          : isPending
            ? 'Adding...'
            : `Add ${token.symbol} to Wallet`}
      </Button>
    </div>
  )
}

export function AddTokens({
  tokens,
  requireWallet = true,
}: {
  tokens: Token[]
  requireWallet?: boolean
}) {
  const { isConnected } = useAccount()

  if (requireWallet && !isConnected) {
    return null
  }

  return (
    <div className="flex flex-wrap gap-2">
      {tokens.map((token) => (
        <AddToken key={token.address} token={token} requireWallet={false} />
      ))}
    </div>
  )
}
