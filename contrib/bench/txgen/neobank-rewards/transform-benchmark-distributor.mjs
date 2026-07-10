#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";

const [inputPath, outputPath] = process.argv.slice(2);
if (!inputPath || !outputPath) {
  throw new Error(
    "usage: transform-benchmark-distributor.mjs <production-input.json> <benchmark-input.json>",
  );
}

const input = JSON.parse(await readFile(inputPath, "utf8"));
const sourcePath = "contracts/Distributor.sol";
const source = input.sources?.[sourcePath]?.content;
if (typeof source !== "string") {
  throw new Error(`missing verified source ${sourcePath}`);
}

function replaceExactlyOnce(value, expected, replacement, description) {
  const first = value.indexOf(expected);
  if (first === -1) {
    throw new Error(`could not find expected ${description}`);
  }
  if (value.indexOf(expected, first + expected.length) !== -1) {
    throw new Error(`found more than one expected ${description}`);
  }
  return value.slice(0, first) + replacement + value.slice(first + expected.length);
}

let benchmarkSource = replaceExactlyOnce(
  source,
  "/// @title Distributor\n",
  "/// @title BenchmarkDistributor\n" +
    "/// @dev BENCHMARK ONLY: identical proofs may be claimed repeatedly to exercise the full payout path.\n",
  "Distributor title",
);
benchmarkSource = replaceExactlyOnce(
  benchmarkSource,
  "contract Distributor is UUPSHelper {",
  "contract BenchmarkDistributor is UUPSHelper {",
  "Distributor contract declaration",
);
benchmarkSource = replaceExactlyOnce(
  benchmarkSource,
  "            uint256 toSend = amount - claimed[user][token].amount;\n" +
    "            claimed[user][token] = Claim(SafeCast.toUint208(amount), uint48(block.timestamp), getMerkleRoot());",
  "            uint256 toSend = amount;\n" +
    "            uint256 nextClaimed = uint256(claimed[user][token].amount) + amount;\n" +
    "            claimed[user][token] =\n" +
    "                Claim(SafeCast.toUint208(nextClaimed), uint48(block.timestamp), getMerkleRoot());",
  "cumulative payout accounting block",
);

input.sources[sourcePath].content = benchmarkSource;
await writeFile(outputPath, `${JSON.stringify(input)}\n`);
