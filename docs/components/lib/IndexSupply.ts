import { Address, Hex } from 'ox'
import * as z from 'zod/mini'

export const rowValueSchema = z.union([z.string(), z.number(), z.null()])

export const responseSchema = z.array(
  z.object({
    cursor: z.optional(z.string()),
    columns: z.array(
      z.object({
        name: z.string(),
        pgtype: z.string(),
      }),
    ),
    rows: z.array(z.array(rowValueSchema)),
  }),
)

export type RowValue = z.infer<typeof rowValueSchema>

export function toBigInt(value: RowValue | null | undefined): bigint {
  if (value === null || value === undefined) return 0n
  if (typeof value === 'number') return BigInt(value)
  const normalized = value.trim()
  if (normalized === '') return 0n
  return BigInt(normalized)
}

export function toQuantityHex(
  value: RowValue | null | undefined,
  fallback: bigint = 0n,
) {
  return Hex.fromNumber(
    value === null || value === undefined ? fallback : toBigInt(value),
  )
}

export function toHexData(value: RowValue | null | undefined): Hex.Hex {
  if (typeof value !== 'string' || value.length === 0) return '0x'
  Hex.assert(value)
  return value
}

export function toAddressValue(
  value: RowValue | null | undefined,
): Address.Address | null {
  if (typeof value !== 'string' || value.length === 0) return null
  Address.assert(value)
  return value
}

type RunQueryOptions = {
  chainId: number
  signatures?: string[]
}

export async function runIndexSupplyQuery(
  query: string,
  options: RunQueryOptions,
) {
  const url = import.meta.env.VITE_INDEXSUPPLY_API_URL || 'https://api.indexsupply.net/v2'
  const response = await fetch(`${url}/query`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify([{
      cursor: `${options.chainId}-0`,
      query: query.replace(/\s+/g, ' ').trim(),
      signatures: options.signatures,
    }]),
  })

  let json: unknown
  try {
    json = await response.json()
  } catch {
    throw new Error('API returned invalid JSON')
  }

  if (!response.ok) {
    const message =
      typeof json === 'object' &&
      json !== null &&
      'error' in json &&
      typeof (json as { error?: string }).error === 'string'
        ? (json as { error: string }).error
        : response.statusText
    throw new Error(`API error (${response.status}): ${message}`)
  }

  const result = (json as unknown[])[0] as z.infer<typeof responseSchema>[0]
  if (!result) throw new Error('API returned an empty result set')
  return result
}
