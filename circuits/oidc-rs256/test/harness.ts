// Compiles circom circuits and computes witnesses for tests.

import * as childProcess from 'node:child_process'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { WitnessCalculatorBuilder } from 'circom_runtime'
import * as snarkjs from 'snarkjs'

/** The package root. */
export const root = path.resolve(import.meta.dirname, '..')

const circom = process.env.CIRCOM ?? 'circom'

export type Circuit = {
  /** Checks a witness against every R1CS constraint. */
  check(witness: readonly bigint[]): Promise<boolean>
  /** The main component's outputs, in declaration order. */
  outputs(witness: readonly bigint[]): bigint[]
  /** Computes a witness, failing on any constraint the witness generator asserts. */
  witness(input: object): Promise<bigint[]>
}

/**
 * Compiles a circuit with a main component, reusing the previous build when no circom source
 * or the compiler changed.
 */
export async function compile(file: string): Promise<Circuit> {
  const name = path.basename(file, '.circom')
  const out = path.join(root, 'build', 'test', name)
  const stamp = path.join(out, 'stamp')
  const hash = sourceHash()
  if (!fs.existsSync(stamp) || fs.readFileSync(stamp, 'utf8') !== hash) {
    fs.rmSync(out, { force: true, recursive: true })
    fs.mkdirSync(out, { recursive: true })
    childProcess.execFileSync(
      circom,
      [file, '--r1cs', '--wasm', '--O1', '-l', path.join(root, 'node_modules'), '-o', out],
      { stdio: 'pipe' },
    )
    fs.writeFileSync(stamp, hash)
  }

  const r1cs = path.join(out, `${name}.r1cs`)
  const wasm = fs.readFileSync(path.join(out, `${name}_js`, `${name}.wasm`))
  const calculator = await WitnessCalculatorBuilder(wasm, { sanityCheck: true })
  const nOutputs = r1csOutputs(r1cs)
  // The calculator appends each failure's template trace to all earlier ones.
  let traces = ''

  return {
    async check(witness) {
      const file = path.join(out, `${crypto.randomUUID()}.wtns`)
      fs.writeFileSync(file, await encodeWitness(witness))
      try {
        return await snarkjs.wtns.check(r1cs, file, { info() {}, warn() {} })
      } finally {
        fs.rmSync(file, { force: true })
      }
    },
    outputs(witness) {
      return witness.slice(1, 1 + nOutputs)
    },
    async witness(input) {
      // The calculator prints failed assertions before throwing them; keep only the throw.
      const { error } = console
      console.error = () => {}
      try {
        return await calculator.calculateWitness(input, true)
      } catch (cause) {
        const { message } = cause as Error
        const split = message.indexOf('. ') + 2
        const trace = message.slice(split)
        const fresh = trace.startsWith(traces) ? trace.slice(traces.length) : trace
        traces = trace
        throw new Error(`${message.slice(0, split)}${fresh}`)
      } finally {
        console.error = error
      }
    },
  }
}

/** Stops the worker threads snarkjs starts for curve arithmetic, so the test process exits. */
export async function terminate(): Promise<void> {
  const { curve_bn128 } = globalThis as { curve_bn128?: { terminate(): Promise<void> } | null }
  await curve_bn128?.terminate()
}

/** Hashes every circom source and the compiler version. */
function sourceHash(): string {
  const hash = crypto.createHash('sha256')
  hash.update(childProcess.execFileSync(circom, ['--version']))
  for (const directory of ['circuits', 'test/circuits']) {
    const files = fs.readdirSync(path.join(root, directory), { recursive: true }) as string[]
    for (const file of files.filter((file) => file.endsWith('.circom')).sort()) {
      hash.update(file)
      hash.update(fs.readFileSync(path.join(root, directory, file)))
    }
  }
  return hash.digest('hex')
}

/** Reads the output count from an R1CS file's header section. */
function r1csOutputs(file: string): number {
  const descriptor = fs.openSync(file, 'r')
  try {
    const read = (position: number, length: number) => {
      const buffer = Buffer.alloc(length)
      fs.readSync(descriptor, buffer, 0, length, position)
      return buffer
    }
    const sections = read(8, 4).readUInt32LE()
    let position = 12
    for (let i = 0; i < sections; i++) {
      const section = read(position, 12)
      const type = section.readUInt32LE(0)
      const size = Number(section.readBigUInt64LE(4))
      position += 12
      if (type === 1) {
        // Field size, prime, wire count, then the output count.
        const fieldSize = read(position, 4).readUInt32LE()
        return read(position + 4 + fieldSize + 4, 4).readUInt32LE()
      }
      position += size
    }
    throw new Error(`${file} has no header section`)
  } finally {
    fs.closeSync(descriptor)
  }
}

/** Encodes a witness in the iden3 .wtns format over BN254. */
async function encodeWitness(witness: readonly bigint[]): Promise<Uint8Array> {
  const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
  const header = 4 + 4 + 4 + 4 + 8 + 4 + 32 + 4
  const bytes = new Uint8Array(header + 4 + 8 + 32 * witness.length)
  const view = new DataView(bytes.buffer)
  let offset = 0
  bytes.set(new TextEncoder().encode('wtns'), offset)
  offset += 4
  view.setUint32(offset, 2, true)
  offset += 4
  view.setUint32(offset, 2, true)
  offset += 4
  // Section 1: field size, prime, and witness count.
  view.setUint32(offset, 1, true)
  offset += 4
  view.setBigUint64(offset, 4n + 32n + 4n, true)
  offset += 8
  view.setUint32(offset, 32, true)
  offset += 4
  writeLittleEndian(bytes, offset, field)
  offset += 32
  view.setUint32(offset, witness.length, true)
  offset += 4
  // Section 2: the values.
  view.setUint32(offset, 2, true)
  offset += 4
  view.setBigUint64(offset, BigInt(32 * witness.length), true)
  offset += 8
  for (const value of witness) {
    writeLittleEndian(bytes, offset, ((value % field) + field) % field)
    offset += 32
  }
  return bytes
}

function writeLittleEndian(bytes: Uint8Array, offset: number, value: bigint) {
  for (let i = 0; i < 32; i++) {
    bytes[offset + i] = Number(value & 0xffn)
    value >>= 8n
  }
}
