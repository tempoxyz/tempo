import * as React from 'react'
import { useQuery } from '@tanstack/react-query'

export function TokenListDemo() {
  
  const tokenList = useQuery({
    queryKey: ['tokenList'],
    queryFn: async () => {
      const response = await fetch('https://tokenlist.tempo.xyz/api/v1/tokenlist')
      const data = await response.json()
      if (!Object.hasOwn(data,'tokens')) throw new Error('Invalid token list')
      return data.tokens
    }
  })

  <ul className='list-none gap-2 flex flex-col justify-center'>
    {tokenList.data?.map(token => (
      <li key={token.address} title={token.address}>
        <a
          target='_blank'
          rel='noopener noreferrer'
          className='flex items-center gap-2 text-[#202020]'
          href={`https://tokenlist.tempo.xyz/asset/42429/${token.address}`}
        >
          <img
            src={token.logoURI}
            alt={token.name}
            className='size-8'
          />
          <span className='text-xl font-medium tracking-wider'>{token.name}</span>
        </a>
      </li>
    ))}
  </ul>
}
