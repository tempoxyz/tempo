import { Editor } from '@monaco-editor/react'
import type * as Monaco from 'monaco-editor'
import * as React from 'react'
import { format } from 'sql-formatter'

// Global flag to ensure completion provider is only registered once
let completionProviderRegistered = false

// Global map to track completions per editor model
interface EditorCompletionData {
  completions:
    | {
        tables: string[]
        columns: string[]
        tableColumns?: Map<string, string[]>
      }
    | undefined
  readOnly: boolean
}

const editorCompletionsMap = new Map<string, EditorCompletionData>()

interface SqlEditorProps {
  value: string
  onChange: (value: string) => void
  onKeyDown?: (e: React.KeyboardEvent<HTMLTextAreaElement>) => void
  readOnly?: boolean
  disabled?: boolean
  className?: string
  minHeight?: string
  completions?: {
    tables: string[]
    columns: string[]
    tableColumns?: Map<string, string[]>
  }
}

export function SqlEditor(props: SqlEditorProps) {
  const {
    value,
    onChange,
    onKeyDown,
    readOnly = false,
    disabled = false,
    className = '',
    minHeight = '120px',
    completions,
  } = props

  const [isFocused, setIsFocused] = React.useState(false)
  const [isDark, setIsDark] = React.useState(() => {
    // Check dark mode on initial render
    if (typeof document !== 'undefined') {
      return document.documentElement.classList.contains('dark')
    }
    return false
  })
  const [editorHeight, setEditorHeight] = React.useState<string>(minHeight)
  const editorRef = React.useRef<Monaco.editor.IStandaloneCodeEditor | null>(
    null,
  )
  const monacoRef = React.useRef<typeof Monaco | null>(null)
  const modelUriRef = React.useRef<string | null>(null)

  // Detect dark mode
  React.useEffect(() => {
    const checkDarkMode = () => {
      setIsDark(document.documentElement.classList.contains('dark'))
    }

    checkDarkMode()

    const observer = new MutationObserver(checkDarkMode)
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    })

    return () => observer.disconnect()
  }, [])

  // Update theme when dark mode changes
  React.useEffect(() => {
    if (monacoRef.current && editorRef.current) {
      const theme = isDark ? 'sql-custom-dark' : 'sql-custom-light'
      monacoRef.current.editor.setTheme(theme)
    }
  }, [isDark])

  const handleEditorWillMount = (monaco: typeof Monaco) => {
    monacoRef.current = monaco

    monaco.editor.defineTheme('sql-custom-dark', {
      base: 'vs-dark',
      inherit: false,
      rules: [
        { token: '', foreground: 'd4d4d4' },
        { token: 'keyword.sql', foreground: '7ba3cc' },
        { token: 'predefined.sql', foreground: 'c5b896' },
        { token: 'type.sql', foreground: '7ba3cc' },
        { token: 'string.sql', foreground: 'b89176' },
        { token: 'number', foreground: 'a0baa0' },
        { token: 'operator.sql', foreground: 'b084a8' },
        { token: 'comment', foreground: '6a9955', fontStyle: 'italic' },
        { token: 'delimiter', foreground: 'a0a0a0' },
        { token: 'identifier', foreground: 'd4d4d4' },
      ],
      colors: {
        'editor.background': '#191919',
        'editor.foreground': '#d4d4d4',
        'editorLineNumber.foreground': '#858585',
        'editorLineNumber.activeForeground': '#c6c6c6',
        'editor.lineHighlightBackground': '#2a2a2a',
        'editor.selectionBackground': '#264f78',
        'editor.inactiveSelectionBackground': '#3a3d41',
      },
    })

    monaco.editor.defineTheme('sql-custom-light', {
      base: 'vs',
      inherit: false,
      rules: [
        { token: '', foreground: '333333' },
        { token: 'keyword.sql', foreground: '0066cc' },
        { token: 'predefined.sql', foreground: '996600' },
        { token: 'type.sql', foreground: '0066cc' },
        { token: 'string.sql', foreground: 'a85c00' },
        { token: 'number', foreground: '098658' },
        { token: 'operator.sql', foreground: 'a8268f' },
        { token: 'comment', foreground: '008000', fontStyle: 'italic' },
        { token: 'delimiter', foreground: '666666' },
        { token: 'identifier', foreground: '333333' },
      ],
      colors: {
        'editor.foreground': '#333333',
        'editor.background': '#ffffff',
      },
    })

    // Register completion provider (only once globally)
    if (!completionProviderRegistered) {
      completionProviderRegistered = true
      monaco.languages.registerCompletionItemProvider('sql', {
        triggerCharacters: ['.'],
        provideCompletionItems: (model, position) => {
          const textUntilPosition = model.getValueInRange({
            startLineNumber: position.lineNumber,
            startColumn: 1,
            endLineNumber: position.lineNumber,
            endColumn: position.column,
          })

          const word = model.getWordUntilPosition(position)
          const range = {
            startLineNumber: position.lineNumber,
            endLineNumber: position.lineNumber,
            startColumn: word.startColumn,
            endColumn: word.endColumn,
          }

          const suggestions: Monaco.languages.CompletionItem[] = []

          // Look up completions for this specific model
          const modelUri = model.uri.toString()
          const editorData = editorCompletionsMap.get(modelUri)

          // Return empty suggestions if no data or editor is read-only
          if (!editorData || !editorData.completions || editorData.readOnly) {
            return { suggestions }
          }

          const completionsData = editorData.completions

          // Check if we're after a dot (for table.column completion)
          const match = textUntilPosition.match(/(\w+)\.\w*$/)
          if (match?.[1]) {
            const tableName = match[1]
            if (completionsData.tableColumns) {
              const tableColumns = completionsData.tableColumns.get(tableName)
              if (tableColumns) {
                tableColumns.forEach((column) => {
                  suggestions.push({
                    label: column,
                    kind: monaco.languages.CompletionItemKind.Field,
                    insertText: column,
                    range,
                  })
                })
              }
            }
          } else {
            // Add table names
            completionsData.tables.forEach((table) => {
              suggestions.push({
                label: table,
                kind: monaco.languages.CompletionItemKind.Class,
                insertText: table,
                range,
              })
            })

            // Add column names
            completionsData.columns.forEach((column) => {
              suggestions.push({
                label: column,
                kind: monaco.languages.CompletionItemKind.Field,
                insertText: column,
                range,
              })
            })

            // Add qualified column names (table.column)
            if (completionsData.tableColumns) {
              completionsData.tableColumns.forEach((columns, table) => {
                columns.forEach((column) => {
                  suggestions.push({
                    label: `${table}.${column}`,
                    kind: monaco.languages.CompletionItemKind.Property,
                    insertText: `${table}.${column}`,
                    range,
                  })
                })
              })
            }
          }

          return { suggestions }
        },
      })
    }
  }

  const handleEditorDidMount = (
    editor: Monaco.editor.IStandaloneCodeEditor,
    monaco: typeof Monaco,
  ) => {
    editorRef.current = editor
    monacoRef.current = monaco

    // Get model URI and register completions in global map
    const model = editor.getModel()
    if (model) {
      const modelUri = model.uri.toString()
      modelUriRef.current = modelUri

      // Register this editor's completions in the global map
      editorCompletionsMap.set(modelUri, {
        completions,
        readOnly: readOnly || disabled,
      })
    }

    // Set initial theme
    const theme = isDark ? 'sql-custom-dark' : 'sql-custom-light'
    monaco.editor.setTheme(theme)

    // Handle focus changes
    editor.onDidFocusEditorText(() => setIsFocused(true))
    editor.onDidBlurEditorText(() => setIsFocused(false))

    // Auto-size read-only editors to fit content
    if (readOnly || disabled) {
      const contentHeight = editor.getContentHeight()
      setEditorHeight(`${contentHeight}px`)

      // Update height when content changes
      editor.onDidContentSizeChange(() => {
        const newHeight = editor.getContentHeight()
        setEditorHeight(`${newHeight}px`)
      })
    }

    // Add Cmd/Ctrl+Enter shortcut
    if (onKeyDown) {
      editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => {
        if (onKeyDown) {
          const mockEvent = {
            key: 'Enter',
            metaKey: true,
            ctrlKey: true,
            preventDefault: () => {},
          } as React.KeyboardEvent<HTMLTextAreaElement>
          onKeyDown(mockEvent)
        }
      })
    }

    // Add Cmd/Ctrl+; shortcut for formatting
    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Semicolon, () => {
      const currentValue = editor.getValue()
      if (currentValue) {
        try {
          const formatted = format(currentValue, {
            language: 'postgresql',
            keywordCase: 'lower',
            indentStyle: 'standard',
            dataTypeCase: 'lower',
            functionCase: 'lower',
          })
          editor.setValue(formatted)
          onChange(formatted)
        } catch (error) {
          console.error('Failed to format SQL:', error)
        }
      }
    })
  }

  // Update map when completions or readOnly props change
  React.useEffect(() => {
    if (modelUriRef.current) {
      editorCompletionsMap.set(modelUriRef.current, {
        completions,
        readOnly: readOnly || disabled,
      })
    }
  }, [completions, readOnly, disabled])

  // Clean up map entry on unmount
  React.useEffect(() => {
    return () => {
      if (modelUriRef.current) {
        editorCompletionsMap.delete(modelUriRef.current)
      }
    }
  }, [])

  return (
    <div className={`${className} ${isFocused ? 'ring-1 ring-accent' : ''}`}>
      <Editor
        height={editorHeight}
        defaultLanguage="sql"
        value={value}
        onChange={(newValue) => onChange(newValue || '')}
        theme={isDark ? 'sql-custom-dark' : 'sql-custom-light'}
        beforeMount={handleEditorWillMount}
        onMount={handleEditorDidMount}
        options={{
          readOnly: readOnly || disabled,
          minimap: { enabled: false },
          lineNumbers: 'on',
          fontSize: 12,
          fontFamily:
            'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
          wordWrap: 'on',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          tabSize: 2,
          insertSpaces: true,
          suggestOnTriggerCharacters: true,
          quickSuggestions: true,
          acceptSuggestionOnCommitCharacter: true,
          acceptSuggestionOnEnter: 'on',
          scrollbar:
            readOnly || disabled
              ? {
                  alwaysConsumeMouseWheel: false,
                  handleMouseWheel: false,
                  vertical: 'hidden',
                  horizontal: 'hidden',
                  verticalScrollbarSize: 0,
                  horizontalScrollbarSize: 0,
                }
              : {
                  vertical: 'auto',
                  horizontal: 'auto',
                },
        }}
      />
    </div>
  )
}
