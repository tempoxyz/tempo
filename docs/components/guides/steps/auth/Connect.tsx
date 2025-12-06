import { useConnection } from 'wagmi'
import { Login, Logout, Step } from '../../Demo'
import type { DemoStepProps } from '../types'

export function Connect(props: DemoStepProps) {
  const { stepNumber = 1 } = props
  const { address } = useConnection()
  return (
    <Step
      active={!address}
      completed={Boolean(address)}
      actions={address ? <Logout /> : <Login />}
      number={stepNumber}
      title="Create an account, or use an existing one."
    />
  )
}
