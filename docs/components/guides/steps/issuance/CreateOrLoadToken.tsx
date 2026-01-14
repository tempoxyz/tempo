import { Hooks } from 'wagmi/tempo'
import { cx } from '../../../../cva.config'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import type { DemoStepProps } from '../types'
import { CreateToken } from './CreateToken'

export function CreateOrLoadToken(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { data: contextData, clearData } = useDemoContext()

  const { tokenAddress, tokenReceipt } = contextData

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })

  const handleClear = () => {
    clearData('tokenReceipt')
    clearData('tokenAddress')
  }

  if (last || !metadata || !tokenAddress) {
    return <CreateToken {...props} />
  }

  return (
    <Step
      active={false}
      completed={true}
      number={stepNumber}
      actions={
        <Button type="button" variant="default" onClick={handleClear}>
          Reset
        </Button>
      }
      title={`Using token ${metadata.name}`}
    >
      {tokenReceipt && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div
            className={cx(
              'bg-gray2 rounded-[10px] p-4 text-center text-gray9 font-normal text-[13px] -tracking-[2%] leading-snug flex flex-col items-center',
            )}
          >
            <div>
              Token{' '}
              <span className="text-primary font-medium">
                {' '}
                {metadata.name} ({metadata.symbol}){' '}
              </span>{' '}
              successfully created and deployed to Tempo!
            </div>
            <ExplorerLink hash={tokenReceipt.transactionHash ?? ''} />
          </div>
        </div>
      )}
    </Step>
  )
}
