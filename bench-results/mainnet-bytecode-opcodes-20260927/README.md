# Ethereum mainnet bytecode-access opcode usage

Retrieved 2026-09-27. Window: 2026-08-01 through 2026-08-31 UTC.
September opcode aggregates were not available from this public endpoint.

## Sources and reproduction

Data comes from ethPandaOps' public mainnet Lab API:

- [Trace methodology](https://ethpandaops.io/posts/evm-gas-profiling/)
- [August opcode aggregates](https://lab.ethpandaops.io/api/v1/mainnet/fct_opcode_gas_by_opcode_daily?day_start_date_starts_with=2026-08&page_size=10000)
- [August transaction totals](https://lab.ethpandaops.io/api/v1/mainnet/fct_execution_transactions_daily?day_start_date_starts_with=2026-08&page_size=10000)
- [August block gas totals](https://lab.ethpandaops.io/api/v1/mainnet/fct_execution_gas_used_daily?day_start_date_starts_with=2026-08&page_size=10000)
- [Transaction opcode aggregation SQL](https://github.com/ethpandaops/xatu-cbt/blob/master/models/transformations/int_transaction_opcode_gas.sql)

Run `node analyze.cjs` in this directory. Existing JSON responses are reused;
missing responses are fetched through the read-only public API. `manifest.json`
records every successful analysis request. `summary.json` contains unrounded
metrics, denominators, and limitations.

## Results

The daily tables cover 222,412 blocks, 70,070,530 transactions,
6,753,596,205,710 charged block gas, and 309,146,881,414 opcode executions.
Counts below are opcode executions, not distinct transactions or physical reads.

| Opcode | August executions | Executions/day | Opcode-attributed gas / block gas |
| --- | ---: | ---: | ---: |
| EXTCODECOPY | 418,123 | 13,488 | 0.001834% |
| EXTCODESIZE | 68,421,290 | 2,207,138 | 0.6797% |
| EXTCODEHASH | 714,794 | 23,058 | 0.008448% |
| CALL | 212,382,513 | 6,851,049 | 7.2569% |
| STATICCALL | 131,842,351 | 4,252,979 | 0.8764% |
| DELEGATECALL | 88,273,373 | 2,847,528 | 1.0393% |
| CALLCODE | 930 | 30 | 0.000035% |
| CODESIZE | 16,797,481 | 541,854 | 0.000497% |
| CODECOPY | 84,745,035 | 2,733,711 | 0.014224% |
| CREATE | 75,616 | 2,439 | 0.4009% |
| CREATE2 | 1,836,972 | 59,257 | 1.7192% |
| SLOAD | 1,234,346,552 | 39,817,631 | 17.0681% |

EXTCODECOPY is rare by execution volume: 0.0001353% of all opcodes, about
1.88 executions per block. However, it occurs in 63.47% of blocks, so it is not
an unused feature. At most 0.5967% of the month's transactions could contain it
in the observed aggregates; this is an upper bound, not measured incidence.

Exact transaction incidence was checked separately for August 30:

- Blocks 25,864,359 through 25,871,535 inclusive: 7,177 blocks.
- 7,301 of 1,794,571 transactions contain EXTCODECOPY: **0.406838%**.
- Those transactions execute it 11,306 times; maximum 25 executions in one tx.
- Transaction-row counts and gas sums exactly match the daily opcode aggregate.
- Date-to-block query returns all 7,177 contiguous block numbers and matches the
  independently published daily transaction table's block count.

Adding 10,000 gas to every EXTCODECOPY execution would add 4,181,230,000 gas,
or **0.061911%** of August's charged block gas. Adding 1,000 gas to every call
family execution instead would add **6.403983%**. These are fixed-workload
arithmetic comparisons, not transaction replays: changed gas limits, refunds,
EIP-150 forwarding, calldata floors, failures and behavioral responses are not
modeled. The small aggregate EXTCODECOPY impact does not prove compatibility
for individual applications. SSTORE2 is one legitimate code-as-data pattern.

## Code loading and gas

Costs below use the Berlin-and-later schedule used in our benchmark, without
draft future repricings. Cold/warm here is EVM transaction-scoped accounting,
not physical residency in a node's cache.

| Operation | Gas components | Existing code blob loaded in the benchmark client? |
| --- | --- | --- |
| EXTCODECOPY | 2,600 cold / 100 warm + 3 per copied 32-byte word + memory expansion | Yes, full code before slicing |
| EXTCODESIZE | 2,600 cold / 100 warm | Yes currently; semantically only size is necessary |
| EXTCODEHASH | 2,600 cold / 100 warm | No; account already contains the code hash |
| CALL / STATICCALL / DELEGATECALL / CALLCODE | 2,600 cold / 100 warm + memory expansion + callee execution | Yes, for nonempty code not already cached |
| CODESIZE | 2 | No new external fetch; current executing code is loaded |
| CODECOPY | 3 + 3 per copied word + memory expansion | No new external fetch; current executing code is loaded |
| CREATE / CREATE2 | 32,000 + 2 per initcode word + memory + initcode execution + 200 per deposited runtime byte; CREATE2 adds 6 per initcode word for hashing | Initcode is already in memory; runtime code is created/written, not fetched as existing code |

CALL and CALLCODE with nonzero value add 9,000 gas. CALL creating an account
adds 25,000 gas. A zero-value call to an existing contract avoids both. Forwarded
gas is not automatically consumed: unused callee gas is returned. There is no
additional historical 700-gas call base on top of the 2,600/100 access charge.

Top-level contract transactions also load destination bytecode, even though
there is no CALL opcode for that dispatch. Their base intrinsic charge is
21,000 gas before calldata, access-list, authorization and other applicable
transaction costs. EIP-7702 delegation adds another resolution path; call
instructions charge 2,600/100 for the delegate account when cold/warm. EXTCODE*
operations on a delegated EOA inspect its 23-byte delegation indicator, not the
delegate's full code. These are distinct from ordinary call-opcode frequency.

Implementation references inspected:

- REVM interpreter 43.0.1 `src/instructions/host.rs:62`: EXTCODESIZE loads code.
- Same file, line 72: EXTCODEHASH does not load code.
- Same file, line 90: EXTCODECOPY loads full code then copies the requested range.
- `src/instructions/contract/call_helpers.rs:162`: the shared call helper loads code.
- Same file, line 190: EIP-7702 delegate code load.
- `revm-context-interface-43.0.1/src/cfg/gas_params.rs`: gas parameters.

Protocol references:
[EIP-2929](https://eips.ethereum.org/EIPS/eip-2929),
[EIP-7702](https://eips.ethereum.org/EIPS/eip-7702),
[EIP-3860](https://eips.ethereum.org/EIPS/eip-3860),
[opcode reference](https://ethereum.org/developers/docs/evm/opcodes/), and
[SSTORE2](https://github.com/Vectorized/solady/blob/main/src/utils/SSTORE2.sol).

## Implications

Repricing EXTCODECOPY alone has little aggregate mainnet exposure, but cannot
fix the general worst-case code-loading problem. A zero-input/output STATICCALL
to a unique 24 KiB contract beginning with STOP still loads the full code in
this client. STOP costs zero gas, so the access charge is 2,600 rather than
2,603 for our 32-byte EXTCODECOPY. The caller pays some additional stack/frame
bookkeeping. This equivalent I/O path follows from the implementation; we have
not measured a new full-node STATICCALL throughput result in this analysis.

EXTCODESIZE is about 164 times more frequent than EXTCODECOPY and is another
substitute for the full-code-read workload. It is a good candidate for a size-
metadata optimization, rather than treating it as an obscure opcode.

Priority: benchmark the same history-selected unique-code corpus with minimal
STATICCALL/CALL targets, consider size-only metadata for EXTCODESIZE, and if
repricing is needed, price first code loading consistently across all code-
loading paths. Account warmth alone does not imply code was loaded: BALANCE,
EXTCODEHASH and access lists can warm an account without reading the blob.
Raising only per-copy-word charges would also miss the tiny-copy/large-code case.

[Draft EIP-7907](https://eips.ethereum.org/EIPS/eip-7907) is relevant prior work:
it separates code warmth from account warmth and meters code loading. It is
not an activated mainnet rule or a benchmarked fix here.

## Limitations

- Public aggregate coverage was used; we did not independently retrace all
  transactions. The sampled transaction-level totals were cross-checked.
- Counts include reverted execution and do not identify unique contracts/users.
- Calls include EOAs, precompiles and repeated targets; not every call loads a
  nonempty code blob, and opcode counts cannot establish physical disk misses.
- Mainnet usage is evidence about compatibility, not a prediction of Tempo use.
- The `fct_opcode_ops_daily` table omits the first block of each day's rate
  calculation. Our opcode denominator instead sums the per-opcode daily table.
- Attributed gas excludes child-frame gas from CALL/CREATE to avoid double
  counting. Block gas and opcode gas differ due to intrinsic gas, refunds and
  other accounting. The gas-share column is not an additive partition of block gas.
