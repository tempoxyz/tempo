# Executor runtime

`tempo-executor` supplies blocking workers for Tempo, the blockchain node built on
Reth. The default backend uses Rayon, OS threads, and Crossbeam channels. Its `fuzz`
feature selects Shuttle, a concurrency-testing runtime: each logical thread has a
resumable call stack, with a fixed round-robin scheduler and a virtual clock. There is no
runtime trait or backend parameter at call sites.

## Calling it

With `fuzz`, create all executor primitives and run the synchronous workload inside
one explicit entry point, `Runtime::run`. Finish or join spawned work before the entry point returns. Handles and
primitives cannot be carried between `Runtime::run` invocations. The default backend
runs the closure directly; the same caller compiles with either backend.

```rust
use tempo_executor::{Runtime, channel, thread, time::Duration};

let value = Runtime::new().run(|| {
    let (send, receive) = channel::bounded(1);
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(2));
        send.send(42).expect("receiver remains connected");
    });
    let value = receive.recv().expect("producer sends a value");
    worker.join().expect("producer completes");
    value
});
assert_eq!(value, 42);
```

The supported surface includes compute pools, detached jobs, `install`, `join`, borrowed
pool/thread scopes, broadcasts, and the parallel-iterator operations used by the patched
Reth crates. Pure compute iterators run serially under `fuzz`. Channels support cloned
senders and receivers, bounded/unbounded queues, zero-capacity rendezvous, blocking and
nonblocking operations, receive timeouts, disconnection, and receive selection.
Under `fuzz`, selection prioritizes receive branches in their written order; the current selection macros support receive branches and an immediate default,
not send branches or timed defaults.

Use this crate's `thread`, `sync`, and `time` modules for blocking coordination. Sleeps
and receive deadlines suspend logical tasks, not the host thread. The virtual clock
advances to the next pending deadline when no application task is runnable. A
simulated execution with no runnable work or pending timer panics as a deadlock. Blocking
on a standard-library/Crossbeam channel or mutex inside a simulated task can instead block the host and
must not be used.

## Reth integration

Tempo's Cargo patches select local copies of Reth's task, engine, trie, provider,
storage, pipeline, EVM, network, and CLI crates. Their source baseline is
[`paradigmxyz/reth@5efe80f`](https://github.com/paradigmxyz/reth/tree/5efe80f515c96fa34b569a22fb810b54f914cfb0).
The reduced workspace in `vendor/reth` retains upstream manifests and licensing; it
lets this branch carry the implementation without changing Tempo's upstream revision.

`reth_tasks::executor` reexports `tempo-executor`. Reth's named workers, work/result
queues, stateful compute pools, proof/trie workers, and the engine's synchronous
channels use it. Tempo payload prewarming and receipt channels use the same types.
The database workloads in `contrib/antithesis/reth-state-root` and
`contrib/antithesis/reth-proofs` enter the runtime explicitly, including their
synchronous persistence/request workers. Their `fuzz` features forward to the patched
crates; Cargo feature unification selects one backend throughout this graph.

Tokio remains native, including explicitly Tokio-backed blocking APIs. Network input,
filesystem/database internals, resource metrics, external caches, and input from the Antithesis testing platform
are not controlled by this scheduler. This does not make a running Tempo node or these
two full database workloads deterministic. Repeatability requires the same workload inputs
and all participating waits to stay inside one `Runtime::run` invocation. Merely
building a node with `fuzz` does not supply a `Runtime::run` invocation; simulated primitives used from
an unmanaged Tokio/OS worker panic rather than silently falling back to native execution.

## Executable checks

From the Tempo root:

```sh
cargo run -p tempo-executor --example trace
cargo run -p tempo-executor --features fuzz --example trace
cargo run --manifest-path vendor/reth/Cargo.toml -p reth-tasks \
  --features rayon --example executor
cargo run --manifest-path vendor/reth/Cargo.toml -p reth-tasks \
  --features rayon,fuzz --example executor
```

The `trace` example checks channel handshakes, backpressure, receive selection, timeouts,
and equality of the recorded send/receive event sequence across repeated `fuzz` runs.
The `executor` example uses Reth's `TaskExecutor` API for named-worker reuse, multiple
producers/consumers, borrowed scopes, and virtual time. It checks that non-`Send`
worker state is created, accessed, and dropped on its original physical thread, and
that a native Tokio task still completes with either backend.
