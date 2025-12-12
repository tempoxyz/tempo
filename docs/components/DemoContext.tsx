import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useState,
} from 'react'
import type { Address, PrivateKeyAccount, TransactionReceipt } from 'viem'
import { useAccountEffect } from 'wagmi'

// Define your allowed keys and their types here
export interface DemoData {
  tokenAddress: Address
  tokenReceipt: TransactionReceipt
  sponsorAccount: PrivateKeyAccount
  transferId: string
  policyId: bigint
  orderId: bigint
  rewardId: bigint
}

interface DemoContextValue {
  setData: <K extends keyof DemoData>(key: K, value: DemoData[K]) => void
  getData: <K extends keyof DemoData>(key: K) => DemoData[K] | undefined
  clearData: <K extends keyof DemoData>(key?: K) => void
  checkFlowDependencies: (keys: (keyof DemoData)[]) => boolean
  data: Partial<DemoData>
}

const DemoContext = createContext<DemoContextValue | undefined>(undefined)

interface DemoContextProviderProps {
  children: ReactNode
}

export function DemoContextProvider({ children }: DemoContextProviderProps) {
  const [data, setDataState] = useState<Partial<DemoData>>({})

  const setData = useCallback(
    <K extends keyof DemoData>(key: K, value: DemoData[K]) => {
      setDataState((prev) => ({
        ...prev,
        [key]: value,
      }))
    },
    [],
  )

  const getData = useCallback(
    <K extends keyof DemoData>(key: K): DemoData[K] | undefined => {
      return data[key]
    },
    [data],
  )

  const clearData = useCallback(<K extends keyof DemoData>(key?: K) => {
    setDataState((prev) => {
      if (key === undefined) {
        return {}
      }
      const { [key]: _, ...rest } = prev
      return rest
    })
  }, [])

  const checkFlowDependencies = useCallback(
    (keys: (keyof DemoData)[]): boolean => {
      return keys.every((key) => data[key] !== undefined)
    },
    [data],
  )

  // Clear all data when account disconnects
  useAccountEffect({
    onDisconnect() {
      setDataState({})
    },
  })

  const value: DemoContextValue = {
    setData,
    getData,
    clearData,
    checkFlowDependencies,
    data,
  }

  return <DemoContext.Provider value={value}>{children}</DemoContext.Provider>
}

export function useDemoContext(): DemoContextValue {
  const context = useContext(DemoContext)
  if (context === undefined) {
    throw new Error('useDemoContext must be used within a DemoContextProvider')
  }
  return context
}
