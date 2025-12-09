/**
 * Extracts type information from tempo.ts SDK functions for documentation auditing.
 *
 * Usage:
 *   pnpm tsx scripts/extract-sdk-types.ts <module> <function>
 *
 * Examples:
 *   pnpm tsx scripts/extract-sdk-types.ts token transfer
 *   pnpm tsx scripts/extract-sdk-types.ts token getBalance
 *
 * Output:
 *   Writes JSON to .claude/sdk-types/<module>.<function>.json
 */

import * as fs from 'node:fs'
import * as path from 'node:path'
import ts from 'typescript'

const [, , moduleName, functionName] = process.argv

if (!moduleName || !functionName) {
  console.error(
    'Usage: pnpm tsx scripts/extract-sdk-types.ts <module> <function>',
  )
  console.error('Example: pnpm tsx scripts/extract-sdk-types.ts token transfer')
  process.exit(1)
}

interface FunctionSignature {
  parameters: ParamInfo[]
  returnType: string
}

interface ParamInfo {
  name: string
  type: string
  optional: boolean
  description?: string | undefined
  // For object types - expanded fields (1 level deep)
  fields?: Record<string, ParamInfo> | undefined
  // For function types - expanded signature
  functionSignature?: FunctionSignature | undefined
}

interface ReturnTypeInfo {
  type: string
  fields?:
    | Record<string, { type: string; description?: string | undefined }>
    | undefined
}

interface TypeInfo {
  module: string
  function: string
  actionType: 'read' | 'write' | 'watch'
  hasSyncVariant: boolean
  parameters: ParamInfo[]
  returnType: ReturnTypeInfo
  syncReturnType?: ReturnTypeInfo | undefined
  callbackArgs?: ReturnTypeInfo | undefined // For watchers: the args passed to the callback
  sourceFile: string
}

// Paths to source files
const viemActionsPath = path.join(
  process.cwd(),
  'node_modules/tempo.ts/src/viem/Actions',
  `${moduleName}.ts`,
)
const wagmiActionsPath = path.join(
  process.cwd(),
  'node_modules/tempo.ts/src/wagmi/Actions',
  `${moduleName}.ts`,
)
const internalTypesPath = path.join(
  process.cwd(),
  'node_modules/tempo.ts/src/viem/internal/types.ts',
)
const abisPath = path.join(
  process.cwd(),
  'node_modules/tempo.ts/src/viem/Abis.ts',
)
const typeHelpersPath = path.join(
  process.cwd(),
  'scripts/type-helpers.ts',
)

// Create TypeScript program
const configPath = ts.findConfigFile(
  process.cwd(),
  ts.sys.fileExists,
  'tsconfig.json',
)
const configFile = configPath
  ? ts.readConfigFile(configPath, ts.sys.readFile)
  : { config: {} }
const parsedConfig = ts.parseJsonConfigFileContent(
  configFile.config,
  ts.sys,
  process.cwd(),
)

const program = ts.createProgram({
  rootNames: [
    viemActionsPath,
    wagmiActionsPath,
    internalTypesPath,
    abisPath,
    typeHelpersPath,
  ].filter(fs.existsSync),
  options: {
    ...parsedConfig.options,
    noEmit: true,
  },
})

const checker = program.getTypeChecker()

function getTypeString(type: ts.Type): string {
  return checker.typeToString(type, undefined, ts.TypeFormatFlags.NoTruncation)
}

// Built-in type methods to filter out from return type expansion
const BUILTIN_METHODS = new Set([
  'toString',
  'valueOf',
  'toLocaleString',
  'charAt',
  'charCodeAt',
  'concat',
  'indexOf',
  'lastIndexOf',
  'localeCompare',
  'match',
  'replace',
  'search',
  'slice',
  'split',
  'substring',
  'toLowerCase',
  'toLocaleLowerCase',
  'toUpperCase',
  'toLocaleUpperCase',
  'trim',
  'length',
  'substr',
  'codePointAt',
  'includes',
  'endsWith',
  'normalize',
  'repeat',
  'startsWith',
  'anchor',
  'big',
  'blink',
  'bold',
  'fixed',
  'fontcolor',
  'fontsize',
  'italics',
  'link',
  'small',
  'strike',
  'sub',
  'sup',
  'padStart',
  'padEnd',
  'trimEnd',
  'trimStart',
  'trimLeft',
  'trimRight',
  'matchAll',
  'replaceAll',
  'at',
  'isWellFormed',
  'toWellFormed',
])

/**
 * Check if a type is a function type
 */
function isFunctionType(type: ts.Type): boolean {
  const callSignatures = type.getCallSignatures()
  return callSignatures.length > 0
}

/**
 * Get the non-nullable version of a type (strip undefined/null from unions)
 */
function getNonNullableType(type: ts.Type): ts.Type {
  return checker.getNonNullableType(type)
}

/**
 * Check if a type is an object type (but not a function, array, or primitive)
 */
function isObjectType(type: ts.Type): boolean {
  // Strip undefined/null from union types first
  const nonNullType = getNonNullableType(type)

  // Must be an object type
  if (!(nonNullType.flags & ts.TypeFlags.Object)) return false

  // Exclude functions
  if (isFunctionType(nonNullType)) return false

  // Exclude arrays
  if (checker.isArrayType(nonNullType)) return false

  // Exclude primitives that masquerade as objects (like string templates)
  const typeString = getTypeString(nonNullType)
  if (
    typeString.startsWith('`') ||
    typeString === 'string' ||
    typeString === 'number' ||
    typeString === 'boolean' ||
    typeString === 'bigint'
  ) {
    return false
  }

  // Must have meaningful properties
  const props = nonNullType.getProperties()
  const meaningfulProps = props.filter(
    (p) => !BUILTIN_METHODS.has(p.getName()) && !p.getName().startsWith('__@'),
  )

  return meaningfulProps.length > 0
}

/**
 * Sort object fields: required (alphabetical) then optional (alphabetical)
 */
function sortFields<T extends { optional?: boolean }>(
  fields: Record<string, T>,
): Record<string, T> {
  const entries = Object.entries(fields)
  const required = entries.filter(([, v]) => !v.optional).sort(([a], [b]) => a.localeCompare(b))
  const optional = entries.filter(([, v]) => v.optional).sort(([a], [b]) => a.localeCompare(b))
  return Object.fromEntries([...required, ...optional])
}

/**
 * Expand an object type into its fields (1 level deep)
 */
function expandObjectType(
  type: ts.Type,
  node: ts.Node,
): Record<string, ParamInfo> | undefined {
  if (!isObjectType(type)) return undefined

  // Use non-nullable type to get the actual object properties
  const nonNullType = getNonNullableType(type)

  const fields: Record<string, ParamInfo> = {}
  const props = nonNullType.getProperties()

  for (const prop of props) {
    if (
      BUILTIN_METHODS.has(prop.getName()) ||
      prop.getName().startsWith('__@')
    ) {
      continue
    }

    const propType = checker.getTypeOfSymbolAtLocation(prop, node)
    const declarations = prop.getDeclarations()
    const isOptional =
      declarations?.some(
        (d) => ts.isPropertySignature(d) && !!d.questionToken,
      ) || getTypeString(propType).includes('undefined')
    const jsDocComment = ts.displayPartsToString(
      prop.getDocumentationComment(checker),
    )

    fields[prop.getName()] = {
      name: prop.getName(),
      type: getTypeString(propType).replace(' | undefined', ''),
      optional: isOptional,
      description: jsDocComment || undefined,
      // Don't expand nested objects (1 level deep only)
    }
  }

  if (Object.keys(fields).length === 0) return undefined
  return sortFields(fields)
}

/**
 * Expand a function type into its signature (parameters and return type)
 */
function expandFunctionType(
  type: ts.Type,
  node: ts.Node,
): FunctionSignature | undefined {
  const callSignatures = type.getCallSignatures()
  if (callSignatures.length === 0) return undefined

  // Use the first call signature
  const signature = callSignatures[0]
  if (!signature) return undefined

  const parameters: ParamInfo[] = []

  for (const param of signature.getParameters()) {
    const paramType = checker.getTypeOfSymbolAtLocation(param, node)
    const declarations = param.getDeclarations()
    const isOptional =
      declarations?.some((d) => ts.isParameter(d) && !!d.questionToken) ||
      getTypeString(paramType).includes('undefined')
    const jsDocComment = ts.displayPartsToString(
      param.getDocumentationComment(checker),
    )

    const paramInfo: ParamInfo = {
      name: param.getName(),
      type: getTypeString(paramType).replace(' | undefined', ''),
      optional: isOptional,
      description: jsDocComment || undefined,
    }

    // Expand object parameters (1 level deep - these are the function's params, not nested)
    if (isObjectType(paramType)) {
      paramInfo.fields = expandObjectType(paramType, node)
    }

    parameters.push(paramInfo)
  }

  const returnType = signature.getReturnType()

  return {
    parameters,
    returnType: getTypeString(returnType),
  }
}

/**
 * Extract a parameter with expanded type info
 */
function extractParamWithExpansion(prop: ts.Symbol, node: ts.Node): ParamInfo {
  const propType = checker.getTypeOfSymbolAtLocation(prop, node)
  const declarations = prop.getDeclarations()
  const isOptional =
    declarations?.some((d) => ts.isPropertySignature(d) && !!d.questionToken) ||
    getTypeString(propType).includes('undefined')
  const jsDocComment = ts.displayPartsToString(
    prop.getDocumentationComment(checker),
  )

  const paramInfo: ParamInfo = {
    name: prop.getName(),
    type: getTypeString(propType).replace(' | undefined', ''),
    optional: isOptional,
    description: jsDocComment || undefined,
  }

  // Expand object types
  if (isObjectType(propType)) {
    paramInfo.fields = expandObjectType(propType, node)
  }

  // Expand function types
  if (isFunctionType(propType)) {
    paramInfo.functionSignature = expandFunctionType(propType, node)
  }

  return paramInfo
}

/**
 * Detect the action type by analyzing the namespace structure
 */
function detectActionType(
  sourceFile: ts.SourceFile,
  funcName: string,
): { actionType: 'read' | 'write' | 'watch'; hasSyncVariant: boolean } | null {
  let hasSyncVariant = false
  let hasParameters = false
  let hasArgs = false
  let hasReturnValue = false
  let foundNamespace = false

  function visit(node: ts.Node) {
    // Check for Sync variant
    if (
      (ts.isFunctionDeclaration(node) &&
        node.name?.getText() === `${funcName}Sync`) ||
      (ts.isModuleDeclaration(node) &&
        node.name.getText() === `${funcName}Sync`)
    ) {
      hasSyncVariant = true
    }

    // Analyze the main namespace
    if (ts.isModuleDeclaration(node) && node.name.getText() === funcName) {
      foundNamespace = true
      const body = node.body
      if (body && ts.isModuleBlock(body)) {
        for (const statement of body.statements) {
          if (ts.isTypeAliasDeclaration(statement)) {
            const name = statement.name.getText()
            if (name === 'Parameters') hasParameters = true
            if (name === 'Args') hasArgs = true
            if (name === 'ReturnValue') hasReturnValue = true
          }
        }
      }
    }

    ts.forEachChild(node, visit)
  }

  visit(sourceFile)

  if (!foundNamespace) return null

  // Determine action type based on namespace structure:
  // - Watchers: Parameters + Args, NO ReturnValue
  // - Write actions: has Sync variant
  // - Read actions: no Sync variant
  let actionType: 'read' | 'write' | 'watch'
  if (hasParameters && hasArgs && !hasReturnValue) {
    actionType = 'watch'
  } else if (hasSyncVariant) {
    actionType = 'write'
  } else {
    actionType = 'read'
  }

  return { actionType, hasSyncVariant }
}

function extractReturnType(type: ts.Type, statement: ts.Node): ReturnTypeInfo {
  const typeString = getTypeString(type)
  const fields: Record<
    string,
    { type: string; description?: string | undefined }
  > = {}

  // Check if this is a meaningful object type (not a primitive with methods)
  const props = type.getProperties()
  const meaningfulProps = props.filter(
    (p) => !BUILTIN_METHODS.has(p.getName()) && !p.getName().startsWith('__@'),
  )

  if (meaningfulProps.length > 0) {
    for (const prop of meaningfulProps) {
      const propType = checker.getTypeOfSymbolAtLocation(prop, statement)
      const jsDocComment = ts.displayPartsToString(
        prop.getDocumentationComment(checker),
      )
      fields[prop.getName()] = {
        type: getTypeString(propType),
        description: jsDocComment || undefined,
      }
    }
  }

  // Sort fields alphabetically
  const sortedFields = Object.keys(fields).length > 0
    ? Object.fromEntries(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b)))
    : undefined

  return {
    type: typeString,
    fields: sortedFields,
  }
}

interface ExtractedNamespace {
  args: ParamInfo[]
  returnType: ReturnTypeInfo
  isWatcher: boolean
  callbackArgs?: ReturnTypeInfo
}

function extractArgsFromNamespace(
  sourceFile: ts.SourceFile,
  funcName: string,
): ExtractedNamespace | null {
  let result: ExtractedNamespace | null = null

  function visit(node: ts.Node) {
    // Look for namespace declaration
    if (ts.isModuleDeclaration(node) && node.name.getText() === funcName) {
      const body = node.body
      if (body && ts.isModuleBlock(body)) {
        let hasParameters = false
        let hasArgs = false
        let hasReturnValue = false
        let argsType: ReturnTypeInfo | null = null

        // First pass: check what types exist
        for (const statement of body.statements) {
          if (ts.isTypeAliasDeclaration(statement)) {
            if (statement.name.getText() === 'Parameters') hasParameters = true
            if (statement.name.getText() === 'Args') hasArgs = true
            if (statement.name.getText() === 'ReturnValue')
              hasReturnValue = true
          }
        }

        // Watchers have Parameters (input) and Args (callback args) but NO ReturnValue
        // Write actions have Parameters, Args, AND ReturnValue
        // Read actions have just Args (input) and ReturnValue (output)
        const isWatcher = hasParameters && hasArgs && !hasReturnValue

        for (const statement of body.statements) {
          // For watchers: extract from Parameters type
          // For regular functions: extract from Args type
          const targetTypeName = isWatcher ? 'Parameters' : 'Args'

          if (
            ts.isTypeAliasDeclaration(statement) &&
            statement.name.getText() === targetTypeName
          ) {
            const type = checker.getTypeAtLocation(statement)
            const args: ParamInfo[] = []

            for (const prop of type.getProperties()) {
              // Use the new expansion helper for full type info
              args.push(extractParamWithExpansion(prop, statement))
            }

            result = result || {
              args: [],
              returnType: { type: 'unknown' },
              isWatcher,
            }
            result.args = args
            result.isWatcher = isWatcher
          }

          // For watchers: extract Args as the callback args type
          if (
            isWatcher &&
            ts.isTypeAliasDeclaration(statement) &&
            statement.name.getText() === 'Args'
          ) {
            const type = checker.getTypeAtLocation(statement)
            argsType = extractReturnType(type, statement)
          }

          // Find ReturnValue type (for non-watchers)
          if (
            ts.isTypeAliasDeclaration(statement) &&
            statement.name.getText() === 'ReturnValue'
          ) {
            const type = checker.getTypeAtLocation(statement)
            result = result || {
              args: [],
              returnType: { type: 'unknown' },
              isWatcher,
            }
            result.returnType = extractReturnType(type, statement)
          }
        }

        // For watchers, set the callback args
        if (result && isWatcher && argsType) {
          result.callbackArgs = argsType
          // Watchers return an unsubscribe function
          result.returnType = { type: '() => void' }
        }
      }
    }

    ts.forEachChild(node, visit)
  }

  visit(sourceFile)
  return result
}

function extractSyncReturnType(
  sourceFile: ts.SourceFile,
  funcName: string,
): ReturnTypeInfo | null {
  let result: ReturnTypeInfo | null = null

  function visit(node: ts.Node) {
    // Look for namespace declaration for the Sync variant
    if (
      ts.isModuleDeclaration(node) &&
      node.name.getText() === `${funcName}Sync`
    ) {
      const body = node.body
      if (body && ts.isModuleBlock(body)) {
        for (const statement of body.statements) {
          // Find ReturnValue type
          if (
            ts.isTypeAliasDeclaration(statement) &&
            statement.name.getText() === 'ReturnValue'
          ) {
            const type = checker.getTypeAtLocation(statement)
            result = extractReturnType(type, statement)
          }
        }
      }
    }

    ts.forEachChild(node, visit)
  }

  visit(sourceFile)
  return result
}

/**
 * Extract parameters from a type alias in the type helpers file.
 * This uses our concrete type instantiations to get fully resolved types.
 */
function extractParametersFromTypeHelper(typeName: string): ParamInfo[] {
  const sourceFile = program.getSourceFile(typeHelpersPath)
  if (!sourceFile) {
    console.warn(`Warning: Could not load type helpers file: ${typeHelpersPath}`)
    return []
  }

  const result: ParamInfo[] = []

  function visit(node: ts.Node) {
    // Look for type alias or interface declaration with the given name
    if (
      (ts.isTypeAliasDeclaration(node) || ts.isInterfaceDeclaration(node)) &&
      node.name.getText() === typeName
    ) {
      const type = checker.getTypeAtLocation(node)
      const props = type.getProperties()

      for (const prop of props) {
        if (
          BUILTIN_METHODS.has(prop.getName()) ||
          prop.getName().startsWith('__@')
        ) {
          continue
        }

        const propType = checker.getTypeOfSymbolAtLocation(prop, node)
        const declarations = prop.getDeclarations()
        const isOptional =
          declarations?.some(
            (d) => ts.isPropertySignature(d) && !!d.questionToken,
          ) || getTypeString(propType).includes('undefined')
        const jsDocComment = ts.displayPartsToString(
          prop.getDocumentationComment(checker),
        )

        result.push({
          name: prop.getName(),
          type: getTypeString(propType).replace(' | undefined', ''),
          optional: isOptional,
          description: jsDocComment || undefined,
        })
      }
    }

    ts.forEachChild(node, visit)
  }

  visit(sourceFile)
  return result
}

function extractWriteParameters(): ParamInfo[] {
  return extractParametersFromTypeHelper('WriteParametersExpanded')
}

function extractReadParameters(): ParamInfo[] {
  return extractParametersFromTypeHelper('ReadParametersExpanded')
}

// Main extraction
const viemSourceFile = program.getSourceFile(viemActionsPath)
if (!viemSourceFile) {
  console.error(`Source file not found: ${viemActionsPath}`)
  process.exit(1)
}

// Step 1: Detect action type first
const actionTypeInfo = detectActionType(viemSourceFile, functionName)
if (!actionTypeInfo) {
  console.error(`Function ${functionName} not found in ${moduleName} module`)
  process.exit(1)
}

const { actionType, hasSyncVariant } = actionTypeInfo

// Step 2: Extract parameters and return types
const extracted = extractArgsFromNamespace(viemSourceFile, functionName)
if (!extracted) {
  console.error(`Could not extract args from ${moduleName}.${functionName}`)
  process.exit(1)
}

// Step 3: Extract Sync return type if it exists (write actions only)
const syncReturnType = hasSyncVariant
  ? extractSyncReturnType(viemSourceFile, functionName)
  : null

// Step 4: Merge with base parameters based on action type
let filteredBaseParams: ParamInfo[] = []
if (actionType === 'write') {
  const baseParams = extractWriteParameters()
  const argsNames = new Set(extracted.args.map((a) => a.name))
  filteredBaseParams = baseParams.filter((p) => !argsNames.has(p.name))
} else if (actionType === 'read') {
  const baseParams = extractReadParameters()
  const argsNames = new Set(extracted.args.map((a) => a.name))
  filteredBaseParams = baseParams.filter((p) => !argsNames.has(p.name))
}
// Watchers don't get base params merged - they have their own structure

// Sort parameters: required (alphabetical) then optional (alphabetical)
const allParams = [...extracted.args, ...filteredBaseParams]
const requiredParams = allParams.filter((p) => !p.optional).sort((a, b) => a.name.localeCompare(b.name))
const optionalParams = allParams.filter((p) => p.optional).sort((a, b) => a.name.localeCompare(b.name))
const sortedParams = [...requiredParams, ...optionalParams]

const typeInfo: TypeInfo = {
  module: moduleName,
  function: functionName,
  actionType,
  hasSyncVariant,
  parameters: sortedParams,
  returnType: extracted.returnType,
  syncReturnType: syncReturnType || undefined,
  callbackArgs: extracted.callbackArgs,
  sourceFile: viemActionsPath,
}

// Output directory
const outputDir = path.join(process.cwd(), '.claude/sdk-types')
fs.mkdirSync(outputDir, { recursive: true })

const outputPath = path.join(outputDir, `${moduleName}.${functionName}.json`)
fs.writeFileSync(outputPath, JSON.stringify(typeInfo, null, 2))

console.log(`✓ Extracted type info for ${moduleName}.${functionName}`)
console.log(`  Action type: ${actionType}`)
console.log(`  Has *Sync variant: ${hasSyncVariant}`)
console.log(`  Parameters: ${typeInfo.parameters.length}`)
console.log(`  Output: ${outputPath}`)
console.log('')
console.log(JSON.stringify(typeInfo, null, 2))
