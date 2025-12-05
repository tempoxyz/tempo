import type { DemoData } from '../../DemoContext'

export type DemoStepProps = {
  stepNumber: number
  // if this is the last step in a flow
  last?: boolean
  /**
   * Additional DemoContext keys required for this step in a specific demo flow.
   * Use this for per-demo prerequisites that vary between flows, NOT for
   * dependencies the component always needs (those should be handled internally).
   *
   * Example: ClaimReward always needs tokenAddress (handled internally),
   * but in the rewards flow it needs to stay inactive until rewardId is set on a previous step.
   */
  flowDependencies?: (keyof DemoData)[]
}
