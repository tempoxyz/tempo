# Initial warmup attempt is invalid

Native suite `state-access-bloat-20260924-181407-282`, run
`20260924-181407-432`, was stopped during excluded warmup. Its transactions
reverted at the 500000 gas limit. No throughput from this attempt is valid.

An early receipt/call-trace check detected the problem. A direct replay with
the original 10000000 gas cap succeeded and performed exactly 128 data SLOADs
plus one cursor SLOAD, all cold. The first cursor write cost 252200 gas in the
opcode trace and total replay gas was 804704. Because the first write reverted,
the cursor remained uninitialized, so later transactions hit the same problem.

The corrected preset retains the original nonbinding 10000000 gas cap. Fresh
snapshots are required for the replacement run. The raw diagnostic is archived
as `initial-gas-limit-diagnostic.json` and the initial input source is retained
under `source/`.
