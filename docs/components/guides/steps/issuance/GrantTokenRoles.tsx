import { useQueryClient } from '@tanstack/react-query'
import type { TokenRole } from 'ox/tempo'
import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { useConnection, useConnectionEffect } from 'wagmi'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'

import type { DemoStepProps } from '../types'

export function GrantTokenRoles(
  props: DemoStepProps & {
    roles: TokenRole.TokenRole[]
  },
) {
  const { stepNumber, roles, last = false } = props
  const { address } = useConnection()
  const { getData } = useDemoContext()
  const queryClient = useQueryClient()

  const [expanded, setExpanded] = React.useState(false)

  // Get the address of the token created in a previous step
  const tokenAddress = getData('tokenAddress')

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })

  // Check if user has each requested role
  const roleChecks = roles.map((role) =>
    Hooks.token.useHasRole({
      account: address,
      token: tokenAddress,
      role: role,
    }),
  )

  // Check if user has all roles
  const hasAllRoles = roleChecks.every((check) => check.data === true)

  const grant = Hooks.token.useGrantRolesSync({
    mutation: {
      onSettled() {
        queryClient.refetchQueries({ queryKey: ['hasRole'] })
      },
    },
  })
  useConnectionEffect({
    onDisconnect() {
      setExpanded(false)
      grant.reset()
    },
  })

  const handleGrant = async () => {
    if (!tokenAddress || !address) return

    await grant.mutate({
      token: tokenAddress,
      roles: roles,
      to: address,
      feeToken: alphaUsd,
    })
  }

  return (
    <Step
      active={
        !!tokenAddress && !hasAllRoles && (last ? true : !grant.isSuccess)
      }
      completed={grant.isSuccess || hasAllRoles}
      actions={
        expanded ? (
          <Button
            variant="default"
            onClick={() => setExpanded(false)}
            className="text-[14px] -tracking-[2%] font-normal"
            type="button"
          >
            Hide
          </Button>
        ) : (
          <Button
            variant={
              tokenAddress && !hasAllRoles
                ? grant.isSuccess
                  ? 'default'
                  : 'accent'
                : 'default'
            }
            disabled={!tokenAddress || hasAllRoles}
            onClick={() => setExpanded(true)}
            type="button"
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Enter details
          </Button>
        )
      }
      number={stepNumber}
      title={`Grant ${roles.join(', ')} role${roles.length > 1 ? 's' : ''} on ${metadata ? metadata.name : 'token'}.`}
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex gap-2 flex-col md:items-end md:flex-row pe-8 mt-2">
              <div className="flex flex-col flex-2">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="recipient"
                >
                  Grant role to yourself
                </label>
                <input
                  className="h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                  data-1p-ignore
                  type="text"
                  name="recipient"
                  value={address}
                  disabled={true}
                  onChange={() => {}}
                  placeholder="0x..."
                />
              </div>
              <Button
                variant={address ? 'accent' : 'default'}
                disabled={!address}
                onClick={handleGrant}
                type="button"
                className="text-[14px] -tracking-[2%] font-normal"
              >
                {grant.isPending ? 'Granting...' : 'Grant'}
              </Button>
            </div>
            {grant.isSuccess && grant.data && (
              <ExplorerLink hash={grant.data.receipt.transactionHash} />
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
