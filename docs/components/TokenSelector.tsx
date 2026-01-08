import type { Address } from 'viem'
import { Hooks } from 'wagmi/tempo'

type TokenSelectorProps = {
  tokens: Address[]
  value: Address
  onChange: (token: Address) => void
  name?: string
}

function TokenOption({ token }: { token: Address }) {
  const { data: metadata, isPending } = Hooks.token.useGetMetadata({
    token,
  })

  if (isPending || !metadata) {
    return <option value={token}>{token}</option>
  }

  return <option value={token}>{metadata.symbol}</option>
}

export function TokenSelector(props: TokenSelectorProps) {
  const { tokens, value, onChange, name } = props

  return (
    <select
      name={name}
      value={value}
      onChange={(e) => onChange(e.target.value as Address)}
      className="h-[34px] border border-gray4 px-3.25 rounded-lg text-[14px] font-normal -tracking-[2%] text-black dark:text-white"
    >
      {tokens.map((token) => (
        <TokenOption key={token} token={token} />
      ))}
    </select>
  )
}
