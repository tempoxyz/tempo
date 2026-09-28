# Ethereum Bytecode Deduplication Measurement

Measured 2026-09-27 from the public [Zellic dataset](https://huggingface.co/datasets/Zellic/all-ethereum-contracts), revision `30510b58af8084b8a5b9ddfa148a46ae24132b16`.
Dataset cutoff: block 21,850,000, February 15, 2025.

## Result

These are raw runtime-code payload bytes for the known-code records in a historical address corpus, NOT current live-state or physical database sizes. GB below means 1,000,000,000 bytes.

| Storage model | Bytes | GB |
| --- | ---: | ---: |
| One copy per referenced code hash | 10,141,540,828 | 10.14 |
| One copy per contract record | 32,585,003,349 | 32.59 |
| Saved by exact-code deduplication | 22,443,462,521 | 22.44 |

Deduplication saves **68.8767%**; removing it expands the code payload **3.2130x**.

The synthetic benchmark's 4,266,667 unique 24-KiB contracts are different: their payload is **104,857,608,192 bytes with or without deduplication**. That statement concerns the generated code corpus, not the rest of the benchmark database.

## Method And Validation

For each code hash `h`, let `L[h]` be its raw runtime byte length and `n[h]` its number of contract-record references. The deduplicated total is `sum(L[h] for n[h] > 0)`; without deduplication it is `sum(n[h] * L[h])`. No metadata stripping, source-level equivalence, or compression is applied.

- Scanned all 69,788,231 contract rows and 1,539,859 code-hash rows.
- Accounted for 69,787,989 contract rows, including 4,837,939 with explicitly empty code.
- Excluded 242 rows with absent code hashes (0.000347% of records). Their code sizes are unknown, not assumed zero.
- Two records lack deployment-block metadata; that alone does not exclude their code from the calculation.
- 1,538,942 code hashes have references. The other 917 entries total 3,046,255 bytes and are excluded from both sides of the comparison.
- Input ZIP SHA256 values and sizes match the publisher's metadata. ZIP streams pass CRC validation.
- Tests cover byte lengths, CRLF, empty code, weighted references, unreferenced entries, absent/malformed block numbers, absent/dangling code hashes, invalid hex, and duplicate hashes.
- An independent sum of the length table and reconciliation of all size-bin totals agree with the result.

Detailed counts, size buckets, and the largest contributors to savings are in `summary.json`.

## Scope And Limitations

The dataset includes destroyed contracts and omits the destruction metadata needed to filter them out. Its collector keys records by address, not by every historical incarnation. These numbers describe the exported corpus, not a reconstructed canonical live state. See the [methodology](https://www.zellic.io/blog/all-ethereum-contracts/) and [collector](https://github.com/Zellic/EVM-trackooor/blob/main/actions/action_deployment_scan.go).

Keys, indexes, analyzed-code jump tables, compression, page packing, and database free space are not included. This is not a 3.21x whole-database or disk-I/O claim.

For an exact current live-state comparison, scan one canonical account snapshot at a fixed block, count nonempty code-hash references, and join those counts to runtime lengths in the code table. Report retained but unreferenced code separately. EIP-7702 delegation markers count as their own stored bytes, not another copy of the target implementation. Physical sizes require building and measuring the proposed database layouts under the same encoding and compression settings.

`mainnet-state-size-20260926.json` is a separately retrieved ethPandaOps code-size metric, retained as research context only. It is NOT an input to this calculation and cannot supply the no-deduplication size.

## Reproduce

From the repository root:

```bash
bash bench-results/bytecode-dedup-20260927/run.sh
```

Requires Bash, curl, g++, Node.js, Python 3, jq, and sha256sum. Downloads approximately 6.4 GB once and streams the ZIP contents without fully extracting the CSV files. No mainnet RPC, production database writes, or benchmark execution is needed.
