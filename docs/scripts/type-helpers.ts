/**
 * Type helper file that instantiates complex generic types concretely.
 * This allows the TypeScript compiler to fully resolve these types
 * so we can extract their properties programmatically.
 *
 * Usage: Import this file in extract-sdk-types.ts to get fully resolved types.
 */

// Use relative paths to node_modules for reliable resolution
import type { ReadParameters, WriteParameters } from '../node_modules/tempo.ts/src/viem/internal/types.js'
import type { Chain, Account, Address } from 'viem'

// Use mapped type to force TypeScript to expand the intersection types
type ExpandType<T> = T extends object ? { [K in keyof T]: T[K] } : T

// Instantiate WriteParameters with concrete chain/account to resolve conditionals
export type WriteParametersExpanded = ExpandType<WriteParameters<Chain | undefined, Account | undefined>>

// ReadParameters doesn't have generics, but expand for consistency
export type ReadParametersExpanded = ExpandType<ReadParameters>

// For debugging/inspection - concrete values that force full type resolution
export const _writeParamsSample: WriteParametersExpanded = {} as WriteParametersExpanded
export const _readParamsSample: ReadParametersExpanded = {} as ReadParametersExpanded
