# Excluded startup attempt

No timed workload ran. Both fresh restores and persistence priming completed,
but the first near-cap direct call reverted out of gas. The router cursor was
still zero: Tempo charges 250000 gas for creating that slot, versus a much
cheaper nonzero update during steady-state load. The preflight correctly
stopped before measurement. Nodes were stopped by the native harness.

The corrected run initializes the cursor with one small, excluded transaction
before gas calibration and timed load. The receipt is archived; audits continue
to reconcile workload transactions against their actual pre-load cursor value.
This attempt is not pooled into the throughput comparison.
