import * as React from 'react'
import {
  getAllSignatures,
  type SignatureInfo,
} from './lib/IndexSupplySignatures'

type SignatureSelectorProps = {
  value: string[]
  onChange: (signatures: string[]) => void
  disabled?: boolean
  filter?: 'all' | 'events' | 'functions' | undefined
}

export function SignatureSelector(props: SignatureSelectorProps) {
  const { value, onChange, disabled = false, filter = 'all' } = props
  const [isOpen, setIsOpen] = React.useState(false)
  const [searchQuery, setSearchQuery] = React.useState('')
  const dropdownRef = React.useRef<HTMLDivElement>(null)

  const allSignatures = React.useMemo(() => getAllSignatures(), [])

  const filteredSignatures = React.useMemo(() => {
    let signatures = allSignatures

    // Apply type filter
    if (filter === 'events') {
      signatures = signatures.filter((sig) => sig.type === 'event')
    } else if (filter === 'functions') {
      signatures = signatures.filter((sig) => sig.type === 'function')
    }

    // Apply search query
    if (!searchQuery.trim()) return signatures

    const query = searchQuery.toLowerCase()
    return signatures.filter(
      (sig) =>
        sig.name.toLowerCase().includes(query) ||
        sig.signature.toLowerCase().includes(query) ||
        sig.contract.toLowerCase().includes(query),
    )
  }, [allSignatures, searchQuery, filter])

  const groupedSignatures = React.useMemo(() => {
    const grouped: Record<string, SignatureInfo[]> = {}
    for (const sig of filteredSignatures) {
      if (!grouped[sig.contract]) {
        grouped[sig.contract] = []
      }
      const contractGroup = grouped[sig.contract]
      if (contractGroup) {
        contractGroup.push(sig)
      }
    }
    return grouped
  }, [filteredSignatures])

  React.useEffect(() => {
    if (!isOpen) return

    function handleClickOutside(event: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [isOpen])

  const selectedSignatureInfos = React.useMemo(() => {
    return value
      .map((sig) => allSignatures.find((s) => s.signature === sig))
      .filter((s): s is SignatureInfo => s !== undefined)
  }, [value, allSignatures])

  const selectedTypes = React.useMemo(() => {
    return new Set(selectedSignatureInfos.map((s) => s.type))
  }, [selectedSignatureInfos])

  const hasMixedTypes = selectedTypes.size > 1

  const toggleSignature = (signature: string) => {
    if (value.includes(signature)) {
      onChange(value.filter((s) => s !== signature))
    } else {
      onChange([...value, signature])
    }
  }

  const clearAll = () => {
    onChange([])
    setIsOpen(false)
  }

  const getTableName = (eventName: string) => {
    return eventName.toLowerCase()
  }

  const placeholderText = React.useMemo(() => {
    if (filter === 'events') return 'Search events...'
    if (filter === 'functions') return 'Search functions...'
    return 'Search events and functions...'
  }, [filter])

  return (
    <div className="relative" ref={dropdownRef}>
      <div className="space-y-2">
        <label
          htmlFor="signature-search"
          className="text-[13px] text-gray11 block"
        >
          Filter by Signatures (optional)
        </label>
        <div className="relative">
          <input
            id="signature-search"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onFocus={() => !disabled && setIsOpen(true)}
            placeholder={placeholderText}
            className="w-full h-[34px] px-3 border border-gray4 rounded-lg text-[13px] focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-50 disabled:cursor-not-allowed"
            disabled={disabled}
          />
          {value.length > 0 && !disabled && (
            <button
              type="button"
              onClick={clearAll}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[11px] text-gray9 hover:text-gray12"
            >
              Clear ({value.length})
            </button>
          )}
        </div>
      </div>

      {isOpen && (
        <div className="absolute z-10 w-full mt-1 bg-gray1 border border-gray4 rounded-lg shadow-lg max-h-[400px] overflow-y-auto">
          {Object.keys(groupedSignatures).length === 0 ? (
            <div className="px-3 py-4 text-[13px] text-gray9 text-center">
              No signatures found
            </div>
          ) : (
            Object.entries(groupedSignatures).map(([contract, signatures]) => (
              <div
                key={contract}
                className="border-b border-gray4 last:border-b-0"
              >
                <div className="sticky top-0 px-3 py-1 text-[11px] font-medium text-gray10 uppercase tracking-wide bg-gray2 z-10">
                  {contract}
                </div>
                <div className="py-0.5">
                  {signatures.map((sig) => (
                    <button
                      key={sig.signature}
                      type="button"
                      onClick={() => toggleSignature(sig.signature)}
                      className="w-full px-3 py-1.5 text-left hover:bg-gray3 flex items-center gap-1.5"
                    >
                      <input
                        type="checkbox"
                        checked={value.includes(sig.signature)}
                        onChange={() => {}}
                        className="shrink-0"
                      />
                      <span className="text-[11px] text-gray12 font-mono shrink-0">
                        {sig.name}
                      </span>
                      <span className="text-[11px] text-gray9 font-mono truncate min-w-0">
                        {sig.signature}
                      </span>
                      <span
                        className={`text-[9px] font-medium h-[16px] flex items-center text-center justify-center rounded px-1.5 tracking-[2%] uppercase leading-none shrink-0 ml-auto ${
                          sig.type === 'event'
                            ? 'bg-blue3 text-blue9'
                            : 'bg-purple3 text-purple9'
                        }`}
                      >
                        {sig.type}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {!isOpen && (
        <div className="mt-2 space-y-2">
          {value.length === 0 ? (
            <div className="bg-gray2 border border-gray4 rounded p-3 space-y-2">
              <div className="text-[12px] text-gray11 leading-relaxed">
                No signatures selected. You can query from these base tables:
              </div>
              <div className="flex flex-wrap gap-2">
                <code className="text-[11px] font-mono bg-gray3 text-gray11 px-2 py-1 rounded">
                  blocks
                </code>
                <code className="text-[11px] font-mono bg-gray3 text-gray11 px-2 py-1 rounded">
                  txs
                </code>
                <code className="text-[11px] font-mono bg-gray3 text-gray11 px-2 py-1 rounded">
                  logs
                </code>
              </div>
              <div className="text-[11px] text-gray10">
                <a
                  href="https://www.indexsupply.net/docs#evm-data"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-accent hover:underline"
                >
                  View documentation →
                </a>
              </div>
            </div>
          ) : (
            <>
              <div className="flex flex-wrap gap-1">
                {value.map((sig) => {
                  const sigInfo = allSignatures.find((s) => s.signature === sig)
                  const isEvent = sigInfo?.type === 'event'
                  return (
                    <div
                      key={sig}
                      className="inline-flex items-center gap-1.5 px-2 py-1 bg-gray3 border border-gray4 rounded text-[11px] font-mono"
                    >
                      <span
                        className={`size-2 rounded-full shrink-0 ${
                          isEvent ? 'bg-blue9' : 'bg-purple9'
                        }`}
                      />
                      <span className="text-gray11 truncate max-w-[300px]">
                        {sigInfo?.name || sig}
                      </span>
                      {!disabled && (
                        <button
                          type="button"
                          onClick={() => toggleSignature(sig)}
                          className="text-gray9 hover:text-gray12 leading-none"
                        >
                          ×
                        </button>
                      )}
                    </div>
                  )
                })}
              </div>

              {!disabled && (
                <>
                  {hasMixedTypes && (
                    <div className="bg-yellow3 border border-yellow6 text-yellow11 rounded py-2 px-3 text-[12px] leading-normal">
                      ⚠️ All signatures must be the same type (all events or all
                      functions)
                    </div>
                  )}

                  {!hasMixedTypes && (
                    <div className="bg-blue2 border border-blue4 rounded p-3 space-y-2">
                      <div className="text-[11px] font-medium text-blue11">
                        Table names for your query:
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {selectedSignatureInfos.map((sig) => (
                          <code
                            key={sig.signature}
                            className="text-[11px] font-mono bg-blue3 text-blue11 px-2 py-1 rounded"
                          >
                            {getTableName(sig.name)}
                          </code>
                        ))}
                      </div>
                      <div className="text-[11px] text-blue9 leading-relaxed">
                        Each signature creates a virtual table. Use these names
                        in your SQL query.
                        {value.length > 1 &&
                          ' You can JOIN these tables together.'}
                      </div>
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
