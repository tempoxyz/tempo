import * as React from 'react'
import { isAddress, isHash } from 'viem'
import { tempoModerato } from 'viem/chains'
import type * as z from 'zod/mini'
import LucideExternalLink from '~icons/lucide/external-link'
import { Container } from './Container'
import { Button } from './guides/Demo'
import { type responseSchema, runIndexSupplyQuery } from './lib/IndexSupply'
import {
  extractParameterNames,
  getAllSignatures,
} from './lib/IndexSupplySignatures'
import { SignatureSelector } from './SignatureSelector'
import { SqlEditor } from './SqlEditor'

type QueryResult = z.infer<typeof responseSchema>[0]

// Default EVM tables and their columns from IndexSupply
const EVM_TABLE_COLUMNS = {
  blocks: [
    'chain',
    'num',
    'timestamp',
    'size',
    'gas_limit',
    'gas_used',
    'nonce',
    'hash',
    'receipts_root',
    'state_root',
    'extra_data',
    'miner',
  ],
  txs: [
    'chain',
    'block_num',
    'block_timestamp',
    'idx',
    'type',
    'gas',
    'gas_price',
    'nonce',
    'hash',
    'from',
    'to',
    'input',
    'value',
  ],
  logs: [
    'chain',
    'block_num',
    'block_timestamp',
    'log_idx',
    'tx_hash',
    'address',
    'topics',
    'data',
  ],
} as const

type IndexSupplyQueryProps = {
  signatures?: string[]
  query?: string
  title?: string
  signatureFilter?: 'all' | 'events' | 'functions'
}

function getExplorerHost() {
  const { VITE_ENVIRONMENT, VITE_EXPLORER_OVERRIDE } = import.meta.env
  if (VITE_ENVIRONMENT !== 'testnet' && VITE_EXPLORER_OVERRIDE !== undefined) {
    return VITE_EXPLORER_OVERRIDE
  }
  return tempoModerato.blockExplorers.default.url
}

function classifyHash(value: string | number | boolean | null): {
  type: 'address' | 'token' | 'tx'
  value: string
} | null {
  if (typeof value !== 'string') return null

  if (!value.startsWith('0x')) return null

  if (value.length < 42) return null

  const lowerValue = value.toLowerCase()

  if (lowerValue.startsWith('0x20c')) {
    return { type: 'token', value }
  }

  if (isAddress(value)) {
    return { type: 'address', value }
  }

  if (isHash(value)) {
    return { type: 'tx', value }
  }

  return null
}

function renderCellValue(
  cell: string | number | boolean | null,
): React.ReactNode {
  if (cell === null) {
    return <span className="text-gray9 italic">null</span>
  }

  const classification = classifyHash(cell)

  if (!classification) {
    return String(cell)
  }

  const explorerHost = getExplorerHost()
  const pathMap = {
    address: 'account',
    token: 'token',
    tx: 'tx',
  }
  const explorerUrl = `${explorerHost}/${pathMap[classification.type]}/${classification.value}`

  const displayValue = `${classification.value.slice(0, 5)}...${classification.value.slice(-4)}`

  return (
    <a
      href={explorerUrl}
      target="_blank"
      rel="noopener noreferrer"
      className="text-accent hover:underline"
      onClick={(e) => e.stopPropagation()}
    >
      {displayValue}
    </a>
  )
}

export function IndexSupplyQuery(props: IndexSupplyQueryProps = {}) {
  const isReadOnly = props.query !== undefined

  const allSignatures = React.useMemo(() => getAllSignatures(), [])

  const resolvedSignatures = React.useMemo(() => {
    if (!props.signatures) return []

    return props.signatures.map((sig) => {
      // If it looks like a full signature (contains parentheses), use it as-is
      if (sig.includes('(')) return sig

      // Otherwise, treat it as a name and look up the full signature
      const found = allSignatures.find((s) => s.name === sig)
      return found ? found.signature : sig
    })
  }, [props.signatures, allSignatures])

  const [signatures, setSignatures] =
    React.useState<string[]>(resolvedSignatures)
  const [result, setResult] = React.useState<QueryResult | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [isLoading, setIsLoading] = React.useState(false)

  const selectedSignatureInfos = React.useMemo(() => {
    return signatures
      .map((sig) => allSignatures.find((s) => s.signature === sig))
      .filter((s) => s !== undefined)
  }, [signatures, allSignatures])

  const completions = React.useMemo(() => {
    // Build table -> columns mapping
    const tableColumns = new Map<string, string[]>()

    Object.entries(EVM_TABLE_COLUMNS).forEach(([table, columns]) => {
      tableColumns.set(table, [...columns])
    })

    selectedSignatureInfos.forEach((info, idx) => {
      const tableName = info.name.toLowerCase()
      const columns = extractParameterNames(signatures[idx] || '')
      tableColumns.set(tableName, columns)
    })

    const tables = Array.from(tableColumns.keys())
    const columns = Array.from(
      new Set(Array.from(tableColumns.values()).flat()),
    )

    return { tables, columns, tableColumns }
  }, [selectedSignatureInfos, signatures])

  const [query, setQuery] = React.useState(props.query || '')
  const queryRef = React.useRef(query)

  const handleQueryChange = (newQuery: string) => {
    queryRef.current = newQuery
    setQuery(newQuery)
  }

  // Update signatures if props change
  React.useEffect(() => {
    setSignatures(resolvedSignatures)
  }, [resolvedSignatures])

  const handleRunQuery = async () => {
    const queryToRun = query.trim()

    if (!queryToRun) {
      setError('Please enter a SQL query')
      return
    }

    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      const options = signatures.length > 0 ? { signatures } : {}
      const queryResult = await runIndexSupplyQuery(queryToRun, options)
      setResult(queryResult)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault()
      const queryToRun = queryRef.current.trim()
      if (!queryToRun) {
        setError('Please enter a SQL query')
        return
      }

      setIsLoading(true)
      setError(null)
      setResult(null)

      runIndexSupplyQuery(
        queryToRun,
        signatures.length > 0 ? { signatures } : {},
      )
        .then((queryResult) => {
          setResult(queryResult)
        })
        .catch((err) => {
          setError(
            err instanceof Error ? err.message : 'Unknown error occurred',
          )
        })
        .finally(() => {
          setIsLoading(false)
        })
    }
  }

  return (
    <Container
      headerLeft={
        <h4 className="text-gray12 text-[14px] font-normal leading-none -tracking-[1%]">
          {props.title || 'IndexSupply SQL Query'}
        </h4>
      }
      headerRight={
        <Button variant="accent" onClick={handleRunQuery} disabled={isLoading}>
          {isLoading ? 'Running...' : 'Run Query'}
        </Button>
      }
    >
      <div className="space-y-4">
        {props.signatures ? (
          <div className="space-y-2">
            <div className="text-[13px] text-gray11 flex items-center gap-1.5">
              Signatures
              <a
                href="https://www.indexsupply.net/docs#signatures"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray9 hover:text-gray11 transition-colors"
              >
                <LucideExternalLink className="size-3" />
              </a>
            </div>
            <div className="flex flex-wrap gap-1">
              {selectedSignatureInfos.map((sigInfo) => {
                const isEvent = sigInfo.type === 'event'
                return (
                  <div
                    key={sigInfo.signature}
                    className="inline-flex items-center gap-1.5 px-2 py-1 bg-gray3 border border-gray4 rounded text-[11px] font-mono"
                  >
                    <span
                      className={`size-2 rounded-full shrink-0 ${
                        isEvent ? 'bg-blue9' : 'bg-purple9'
                      }`}
                    />
                    <span className="text-gray11 truncate max-w-[300px]">
                      {sigInfo.name}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        ) : (
          <SignatureSelector
            value={signatures}
            onChange={setSignatures}
            disabled={isReadOnly}
            filter={props.signatureFilter}
          />
        )}

        <div className="space-y-2">
          <label
            htmlFor="sql-query"
            className="text-[13px] text-gray11 flex items-center gap-1.5"
          >
            SQL Query
            <a
              href="https://www.indexsupply.net/docs#sql"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray9 hover:text-gray11 transition-colors"
            >
              <LucideExternalLink className="size-3" />
            </a>
          </label>
          <SqlEditor
            value={query}
            onChange={handleQueryChange}
            onKeyDown={handleKeyDown}
            readOnly={isReadOnly}
            disabled={isLoading || isReadOnly}
            completions={completions}
            className={`w-full bg-gray2 border border-gray4 rounded font-mono focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed ${
              isReadOnly
                ? 'text-[11px] leading-[1.4]'
                : 'text-[13px] leading-normal'
            }`}
            minHeight={isReadOnly ? '200px' : '120px'}
          />
        </div>

        {error && (
          <div className="bg-destructiveTint text-destructive rounded py-2 px-3 text-[14px] -tracking-[2%] leading-normal font-normal">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-2">
            <div className="border border-gray4 rounded overflow-auto">
              <table className="w-full text-[12px]">
                <thead className="bg-gray2 border-b border-gray4">
                  <tr>
                    {result.columns.map((col) => (
                      <th
                        key={col.name}
                        className="text-left px-3 py-2 font-medium text-gray12"
                      >
                        <div className="flex flex-col gap-0.5">
                          <span>{col.name}</span>
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.rows.length === 0 ? (
                    <tr>
                      <td
                        colSpan={result.columns.length}
                        className="text-center py-4 text-gray9"
                      >
                        No rows returned
                      </td>
                    </tr>
                  ) : (
                    result.rows.map((row, rowIndex) => (
                      <tr
                        key={`row-${rowIndex}-${row.map((c) => (c === null ? 'null' : String(c))).join('-')}`}
                        className="border-b border-gray4 last:border-b-0 hover:bg-gray2"
                      >
                        {row.map((cell, cellIndex) => (
                          <td
                            key={`${result.columns[cellIndex]?.name}-${rowIndex}`}
                            className="px-3 py-2 font-mono text-gray11"
                          >
                            {renderCellValue(cell)}
                          </td>
                        ))}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Container>
  )
}
