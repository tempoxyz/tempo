import * as assert from 'node:assert/strict'
import * as path from 'node:path'
import { after, before, describe, test } from 'node:test'
import * as Inputs from '../src/inputs.ts'
import * as Harness from './harness.ts'

let circuit: Harness.Circuit

before(async () => {
  circuit = await Harness.compile(path.join(Harness.root, 'test', 'circuits', 'json.circom'))
})
after(Harness.terminate)

describe('JsonObject, TopLevelMember, and StringValue', () => {
  test('read sub exactly as JSON.parse does, and only when TIP-1133 allows', async () => {
    const random = prng(0x1133)
    let accepted = 0
    let rejected = 0
    for (let i = 0; i < 2000; i++) {
      const generated = payload(random)
      const bytes = new TextEncoder().encode(generated.text)
      if (bytes.length > 96) continue

      const read = await readSub(bytes)
      const parsed = JSON.parse(generated.text) as { sub?: unknown }
      if (read === undefined) {
        rejected++
        assert.ok(!generated.allowed, `rejected ${generated.text}`)
      } else {
        accepted++
        assert.ok(generated.allowed, `accepted ${generated.text}`)
        assert.equal(read, parsed.sub, generated.text)
      }
    }
    assert.ok(accepted > 200 && rejected > 200, `${accepted} accepted, ${rejected} rejected`)
  })
})

/** Runs the circuit and returns the sub it reads, or undefined when it rejects. */
async function readSub(bytes: Uint8Array): Promise<string | undefined> {
  const padded = new Uint8Array(96)
  padded.set(bytes)
  const subLen = Inputs.topLevelMembers(bytes).sub?.length ?? 0
  try {
    const witness = await circuit.witness({ bytes: [...padded], len: bytes.length, subLen })
    const content = circuit.outputs(witness).slice(0, subLen).map(Number)
    return new TextDecoder().decode(Uint8Array.from(content))
  } catch {
    return undefined
  }
}

type Random = () => number

type Generated = {
  /** Whether TIP-1133 accepts the payload's sub. */
  allowed: boolean
  text: string
}

/** A random valid JSON object, written compactly unless whitespace is injected. */
function payload(random: Random): Generated {
  const members: { name: string; raw: string; value: unknown }[] = []
  for (let i = Math.floor(random() * 4); i > 0; i--) {
    const name = pick(random, ['a', 'su', 'subs', 'Sub', 'x', 'b"c', 'd\\e', 'sub '])
    members.push({ name, raw: JSON.stringify(name), value: jsonValue(random, 1) })
  }
  const subs = random() < 0.9 ? 1 + Number(random() < 0.15) : 0
  for (let i = 0; i < subs; i++) {
    const value = random() < 0.8 ? string(random, 18) : jsonValue(random, 1)
    members.splice(Math.floor(random() * (members.length + 1)), 0, {
      name: 'sub',
      raw: '"sub"',
      value,
    })
  }
  // An escaped name means the same to JSON.parse but must be rejected.
  const escaped = members[Math.floor(random() * members.length)]
  if (escaped && random() < 0.1) {
    const hex = escaped.name.charCodeAt(0).toString(16).padStart(4, '0')
    escaped.raw = `"\\u${hex}${JSON.stringify(escaped.name).slice(2)}`
  }
  const whitespace = random() < 0.1
  const separator = whitespace ? pick(random, [', ', ',']) : ','
  const colon = whitespace ? pick(random, [': ', ':']) : ':'
  const pairs = members.map(({ raw, value }) => `${raw}${colon}${JSON.stringify(value)}`)
  const text = `{${pairs.join(separator)}}`

  const sub = members.find(({ name }) => name === 'sub')?.value
  const allowed =
    !hasOutsideWhitespace(text) &&
    members.every(({ raw }) => !raw.includes('\\')) &&
    members.filter(({ raw }) => raw === '"sub"').length === 1 &&
    typeof sub === 'string' &&
    !JSON.stringify(sub).includes('\\') &&
    new TextEncoder().encode(sub).length <= 16
  return { allowed, text }
}

function jsonValue(random: Random, depth: number): unknown {
  const roll = random()
  if (roll < 0.4) return string(random, 8)
  if (roll < 0.55) return Math.floor(random() * 1e6) - (roll < 0.47 ? 5e5 : 0)
  if (roll < 0.62) return pick(random, [true, false, null, 1.5, 1e21])
  if (depth < 3 && roll < 0.82) {
    const object: Record<string, unknown> = {}
    for (let i = Math.floor(random() * 3); i >= 0; i--)
      object[pick(random, ['sub', 'a', 'b"c', 'd\\e', 'x'])] = jsonValue(random, depth + 1)
    return object
  }
  if (depth < 3) return [jsonValue(random, depth + 1), jsonValue(random, depth + 1)]
  return string(random, 4)
}

function string(random: Random, max: number): string {
  const chars = ['a', 'b', '1', '"', '\\', ',', ':', '{', '}', '[', ']', 'é', '\u0001', ' ', '/']
  let out = ''
  for (let i = Math.floor(random() * (max + 1)); i > 0; i--)
    out += random() < 0.6 ? pick(random, ['a', 'b', '1', '-']) : pick(random, chars)
  return out
}

/** Whether a space appears outside a string. */
function hasOutsideWhitespace(text: string): boolean {
  let inString = false
  let escaped = false
  for (const char of text) {
    if (inString) {
      if (escaped) escaped = false
      else if (char === '\\') escaped = true
      else if (char === '"') inString = false
    } else if (char === '"') inString = true
    else if (char === ' ') return true
  }
  return false
}

function pick<item>(random: Random, items: readonly item[]): item {
  return items[Math.floor(random() * items.length)]!
}

/** mulberry32, for reproducible cases. */
function prng(seed: number): Random {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
