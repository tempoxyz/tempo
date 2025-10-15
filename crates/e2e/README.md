# Tests for networks of validators

This crate contains full e2e tests. It spins up networks of validators with
full consensus and execution layers and asserts that a minimum height is
reached.

## Implementation details

The tests are rust tests (no container images or production binaries).
The consensus layer is run inside
[`commonware_runtime::deterministic`](https://docs.rs/commonware-runtime/0.0.62/commonware_runtime/deterministic/index.html),
while the execution layer is run inside a non-deterministic tokio runtime.


## Drawbacks

### Non-determinancy

Because the consensus and execution layers need to interact, arbitrarily
complex scenarios cannot yet be deterministically reproduced. For simple cases,
the interaction points between the two runtimes are paced: instead of running
in simulated time, the deterministic runtime waits in real time for the
future running inside tokio to return.

## Sequential or isolated by process

When trying to run too many tests concurrently (or when trying to launch too
large networks), the execution layers fail with errors like these:

> `failed to open the database: unknown error code: 12 (12)`

The source of this issue is not yet clear. It is therefore recommended to run
the tests sequentially. Alternatively, running tests in different processes also
seems to help, as is done by [`nextest`](https://nexte.st).
