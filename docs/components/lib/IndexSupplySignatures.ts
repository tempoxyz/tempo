import type { Abi, AbiEvent, AbiFunction } from 'abitype'
import { Abis } from 'viem/tempo'

export type SignatureInfo = {
  signature: string
  name: string
  contract: string
  type: 'event' | 'function'
}

function formatEventSignature(event: AbiEvent): string {
  const params = event.inputs
    .map((input) => {
      const indexed = input.indexed ? ' indexed' : ''
      return `${input.type}${indexed} ${input.name || ''}`
    })
    .join(', ')
  return `${event.name}(${params})`
}

function formatFunctionSignature(fn: AbiFunction): string {
  const inputs = fn.inputs
    .map((input) => `${input.type} ${input.name || ''}`)
    .join(', ')
  return `${fn.name}(${inputs})`
}

function extractSignaturesFromAbi(
  abi: Abi,
  contractName: string,
): SignatureInfo[] {
  const signatures: SignatureInfo[] = []

  for (const item of abi) {
    if (item.type === 'event') {
      signatures.push({
        signature: formatEventSignature(item),
        name: item.name,
        contract: contractName,
        type: 'event',
      })
    } else if (item.type === 'function') {
      signatures.push({
        signature: formatFunctionSignature(item),
        name: item.name,
        contract: contractName,
        type: 'function',
      })
    }
  }

  return signatures
}

export function getAllSignatures(): SignatureInfo[] {
  const allSignatures: SignatureInfo[] = []

  const abiMap: Record<string, Abi> = {
    tip20: Abis.tip20,
    stablecoinDex: Abis.stablecoinDex,
    tip20Factory: Abis.tip20Factory,
    tip403Registry: Abis.tip403Registry,
    feeManager: Abis.feeManager,
    feeAmm: Abis.feeAmm,
  }

  for (const [contractName, abi] of Object.entries(abiMap)) {
    allSignatures.push(...extractSignaturesFromAbi(abi, contractName))
  }

  return allSignatures
}

export function getSignaturesByContract(): Record<string, SignatureInfo[]> {
  const allSignatures = getAllSignatures()
  const byContract: Record<string, SignatureInfo[]> = {}

  for (const sig of allSignatures) {
    if (!byContract[sig.contract]) {
      byContract[sig.contract] = []
    }
    const contractSigs = byContract[sig.contract]
    if (contractSigs) {
      contractSigs.push(sig)
    }
  }

  return byContract
}

export function extractParameterNames(signature: string): string[] {
  // Extract parameters from signature like
  // "Transfer(address indexed from, address indexed to, uint256 amount)"
  const match = signature.match(/\((.*)\)/)
  if (!match || !match[1]) return []

  const paramsString = match[1]
  const params = paramsString.split(',').map((p) => p.trim())

  return params
    .map((param) => {
      // Remove 'indexed' keyword and type, keep only the name
      const parts = param.split(/\s+/)
      const name = parts[parts.length - 1]
      return name || ''
    })
    .filter((name): name is string => name.length > 0)
}
