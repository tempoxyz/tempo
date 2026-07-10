#!/usr/bin/env node

import { readFile } from "node:fs/promises";

const [artifactPath, address] = process.argv.slice(2);
if (!artifactPath || !address) {
  throw new Error("usage: verify-runtime.mjs <artifact.json> <deployed-address>");
}

const artifact = JSON.parse(await readFile(artifactPath, "utf8"));
const expected = Buffer.from(artifact.deployedBytecode.object.slice(2), "hex");
const response = await fetch("https://rpc.tempo.xyz", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getCode",
    params: [address, "latest"],
  }),
});
if (!response.ok) {
  throw new Error(`RPC returned HTTP ${response.status}`);
}
const payload = await response.json();
if (payload.error) {
  throw new Error(`RPC error: ${JSON.stringify(payload.error)}`);
}
const actual = Buffer.from(payload.result.slice(2), "hex");

if (actual.length !== expected.length) {
  throw new Error(`runtime length mismatch: compiled=${expected.length}, deployed=${actual.length}`);
}

// Immutable values depend on the deployment address and constructor arguments.
for (const references of Object.values(artifact.deployedBytecode.immutableReferences ?? {})) {
  for (const { start, length } of references) {
    expected.fill(0, start, start + length);
    actual.fill(0, start, start + length);
  }
}

// Verification metadata contains an IPFS hash of compiler input that the explorer
// does not reproduce byte-for-byte. The executable portion before CBOR must match.
function clearCborMetadata(bytecode) {
  const cborLength = bytecode.readUInt16BE(bytecode.length - 2);
  const start = bytecode.length - cborLength - 2;
  if (start < 0) throw new Error("invalid Solidity CBOR metadata length");
  bytecode.fill(0, start);
}
clearCborMetadata(expected);
clearCborMetadata(actual);

if (!expected.equals(actual)) {
  const offset = expected.findIndex((byte, index) => byte !== actual[index]);
  throw new Error(`runtime opcode mismatch at byte ${offset}`);
}

console.log(`Verified deployed runtime opcodes for ${address}`);
