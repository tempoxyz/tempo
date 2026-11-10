# Executor runtime: concrete, feature-selected backends

Status: interface proposal. This document adds no runtime implementation, Cargo feature,
or change to production execution. The proposed home is a `tempo-executor` crate, which
Reth could depend on without depending on Tempo's node or consensus crates.

Provide one concrete API for synchronous jobs, borrowed parallel work, channels, and
time. Compute pools execute parallel jobs; named serial workers execute queued jobs one
at a time. Without the proposed Cargo feature `fuzz`, use Rayon for compute pools and OS
threads for named serial workers. With `fuzz`, repeat execution using a fixed task
scheduler and virtual time, so fuzz failures can be reproduced. Tokio remains outside
this runtime: its futures, timers, network I/O, and task scheduler are unchanged.

A logical task is one synchronous closure with its own resumable call stack. A logical
worker is an explicitly identified execution context that can own state which is not
`Send`. An execution domain is the set of tasks, workers, channels, and clock owned by
one runtime. Its pools are handles into that same domain, not separate schedulers.

## Synchronous blocking contract

Jobs remain synchronous closures. Runtime waits must suspend their call stacks, using
stackful execution or scheduler-controlled OS threads. Recursively running another
closure inside `recv` is insufficient. For example, job A waits for B's message, then
replies; B sends that message, then waits for A's reply. If B runs recursively inside
A's receive, A cannot resume to reply until B returns: an artificial deadlock. The
backend must preserve worker affinity for non-`Send` locals. Picking the suspension
mechanism remains an implementation decision; this draft supplies neither it nor a
working deterministic scheduler.

## Compile-time selection

Callers import concrete types; there is no public runtime trait, backend type parameter,
or trait object. The following module layout is proposed, not added by this change:

```rust
#[cfg(not(feature = "fuzz"))]
#[path = "native.rs"]
mod backend;

#[cfg(feature = "fuzz")]
#[path = "deterministic.rs"]
mod backend;

pub use backend::{
    Cancellation, Instant, Job, Mutex, Pool, Receiver, Runtime, Scope,
    ScopedJob, Sender, SerialWorker, Worker,
};
```

Both modules expose the same signatures and documented behavior. The configuration and
error types described below are shared between modules; the export list above shows only
the backend-dependent handles. The intended backend selection is a compile-time choice
for the entire crate, not per runtime instance. Cargo features are additive: any
dependency enabling this crate's `fuzz` feature selects it for all users of that crate
instance. Node-level feature propagation must therefore be explicit; a Cargo profile
alone does not select the backend.

## Execution API

The declarations below show the public surface; method bodies, private fields, imports,
and routine trait implementations are omitted. They are not a compilable crate.
`Runtime`, `Pool`, and `SerialWorker` are cloneable handles. `PoolConfig` contains a
diagnostic name and a nonzero logical parallelism, meaning the number of worker contexts
provisioned for that pool. Worker counts are configuration, not a query of the test
machine's physical CPUs.

`Runtime::run` admits the caller-provided root closure as the first managed task and
drives the execution domain until that root and its submitted work finish. A nested or
concurrent root would mix two executions, so it is rejected.

`TaskError` reports a panic during execution or cancellation before a job starts.
`RunError` reports a root-task failure, an overlapping/nested `run`, or deterministic
deadlock (the detection rule is defined under time below). `Capacity`, `Wait`, and wait
errors are defined in the channels section. `Job` and `ScopedJob` are result handles;
`Scope` bounds the lifetime of borrowed children. `Cancellation` wakes cancelled waits;
`Instant` belongs to the runtime clock. `Worker` represents an explicit pool worker,
while `SerialWorker` is a separate FIFO job queue. Scope callbacks propagate panic only
after all borrowed children have finished or unwound.

```rust,ignore
impl Runtime {
    pub fn new() -> Self;

    pub fn run<T: Send>(
        &self,
        root: impl FnOnce(&Runtime) -> T + Send,
    ) -> Result<T, RunError>;

    pub fn pool(&self, config: PoolConfig) -> Pool;
    pub fn serial_worker(&self, name: &'static str) -> SerialWorker;

    pub fn channel<T: Send>(&self, capacity: Capacity)
        -> (Sender<T>, Receiver<T>);
    pub fn cancellation(&self) -> Cancellation;
    pub fn mutex<T: Send>(&self, value: T) -> Mutex<T>;

    pub fn now(&self) -> Instant;
    pub fn sleep_until(&self, deadline: Instant, wait: Wait<'_>)
        -> Result<(), WaitError>;
    pub fn yield_now(&self);

    pub fn shutdown(&self);
}

impl Pool {
    pub fn parallelism(&self) -> NonZeroUsize;

    pub fn spawn<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<Job<T>, SpawnError>;

    pub fn scope<'env, T>(
        &self,
        body: impl for<'scope> FnOnce(
            &'scope Scope<'scope, 'env>,
        ) -> T,
    ) -> T;
}

impl<'scope, 'env: 'scope> Scope<'scope, 'env> {
    pub fn spawn<T: Send + 'scope>(
        &'scope self,
        job: impl FnOnce() -> T + Send + 'scope,
    ) -> Result<ScopedJob<'scope, T>, SpawnError>;
}

impl SerialWorker {
    pub fn spawn<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<Job<T>, SpawnError>;

    pub fn try_spawn<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<Job<T>, TrySpawnError>;
}
```

Submission is eager, even if nobody joins the result. Dropping a result handle does not
cancel its job. Named serial workers are interned within a runtime: repeated lookup of a
name returns the same FIFO execution lane. A lane runs only one job at a time, including
while that job is suspended. `try_spawn` rejects admission if a job is queued or active;
`TrySpawnError` distinguishes busy from runtime shutdown. `SpawnError` reports shutdown.
Serial workers are independent of compute-pool capacity, so long-lived channel loops do
not occupy every Rayon compute worker.

`Job<T>` and `ScopedJob<'_, T>` provide consuming `join(wait)` and `try_join(self) ->
Result<Result<T, TaskError>, Self>`; a not-ready try returns the original handle for
retry, while a ready try consumes it. `join` returns `Result<T, JoinError>`, with
variants for task failure, deadline expiry, and wait cancellation. `Wait` supplies those
wait conditions as described in the next section. An interrupted consuming join drops
the result handle, not the job. For scoped jobs, the enclosing scope still waits for its children.
`Job<T>` also provides a consuming `into_future()` adapter that registers a completion
waker and yields until the job finishes, rather than synchronously joining on a Tokio
worker. This adapter does not bring Tokio scheduling into the deterministic domain.
Reth's existing LazyHandle caches a shared result behind cloned handles. An adapter can
retain that behavior above these single-consumer jobs.

`run` rejects overlapping or nested root executions with `RunError`. Scope and
blocking-wait operations require a task admitted through `run`; out-of-domain use is
rejected with a diagnostic, not silently attached to another runtime. Scope bodies run
on the calling task, so their captures and return values need not be `Send`; only
transferred child closures and results must be. On root completion, `run` drains
submitted work before returning. Callers terminate long-lived receive loops by closing
their input channels or requesting cancellation and handling the receive error. Without
termination, native `run` continues waiting; the deterministic backend diagnoses
deadlock if no task or timer can progress. `shutdown` rejects new submissions and wakes
runtime-owned waits with cancellation; it does not forcibly interrupt CPU-bound code.
Borrowed tasks may never outlive a scope, even on root failure or deadlock. A backend
must unwind or finish those activations before returning an error, not detach them. On
deadlock, cancel and resume parked waits so tasks can exit. If a task refuses to exit,
the harness must fail the process rather than return while borrowed references remain
live. The runtime cannot promise recovery from arbitrary non-cooperative code.

## Channels, selection, and time

`Wait::forever()` has no deadline or operation-specific cancellation token.
`Wait::until(deadline)` sets a deadline; `.cancelled_by(&token)` adds a borrowed
token. Cancellation handles are cloneable and share state.

`Capacity` is `Bounded(NonZeroUsize)`, `Rendezvous`, or `Unbounded`. `Wait` contains an
optional runtime deadline and optional cancellation token; runtime shutdown always wakes
the wait with a cancellation error. Deadlines from another runtime are rejected rather
than compared. Cancellation tokens support `cancel()` and `is_cancelled()`; dropping a
token alone does not cancel work.

```rust,ignore
impl<T: Send> Sender<T> {
    pub fn send(&self, value: T, wait: Wait<'_>) -> Result<(), SendError<T>>;
    pub fn try_send(&self, value: T) -> Result<(), TrySendError<T>>;
}

impl<T: Send> Receiver<T> {
    pub fn recv(&self, wait: Wait<'_>) -> Result<T, RecvError>;
    pub fn try_recv(&self) -> Result<T, TryRecvError>;
}
```

Shutdown is reported as cancellation by send/receive operations. Both endpoints are
cloneable. Receivers compete for messages; this is not broadcast. Each message is
delivered once. Acceptance means buffer insertion or matching a rendezvous
receive; messages are FIFO in that order. Deterministic blocked senders are
admitted in registration order. Native competing senders have no stronger
ordering than actual acceptance order. Last sender drop wakes receivers, which
drain buffered messages before reporting closure. Last receiver drop wakes senders with
an error retaining the unsent value. Send/receive errors distinguish disconnection,
cancellation, and deadline expiry; nonblocking operations additionally distinguish
full/empty. Rendezvous sends complete only when paired with a receive. Failed or
cancelled receives consume no message.

Provide a typed `select_biased!` helper for heterogeneous receive operations and
cancellation. Each selected arm receives its operation's result and produces the macro
expression's value, like a match arm. Proposed syntax:

```rust,ignore
select_biased! {
    cancel(stop) => break,
    recv(jobs, wait) -> result => handle(result),
}
```

It registers all alternatives before parking and commits exactly one operation. Ready
alternatives are checked in source order, allowing abort to win over available work.
`stop` is a cancellation handle; its arm becomes ready when cancelled. `recv(jobs,
wait)` binds the receive Result to `result`. Selection errors and deadlines follow the
same rules as individual waits. Do not implement selection by receiving from every
channel and putting unwanted messages back. Arbitrary send-selection is not required by
the linked Reth receive loops in the source inventory below.

A relative `sleep(duration, wait)` helper uses the same clock as `now()` and
`sleep_until`. The native clock is monotonic; the deterministic clock starts at a fixed
origin. When no task can run, the deterministic backend advances to the next timer and
wakes expired waits. If neither a runnable task nor a timer remains, it diagnoses
deadlock. In the deterministic backend, reading time or executing CPU instructions alone
does not advance virtual time; polling loops must sleep or yield through the runtime.

`Mutex<T>::lock(wait) -> Result<MutexGuard<'_, T>, WaitError>` suspends the logical task
until the lock is available, cancelled, or its deadline expires. The guard unlocks on
drop; `WaitError` distinguishes cancellation from deadline expiry. Plain OS-blocking
mutexes, condvars, barriers, channels, and sleeps are not substitutes inside the
deterministic domain. Ordered result slots and barriers can be built from these channels
rather than exposing a second condition-variable API.

## Explicit workers and parallel algorithms

Provide `Pool::for_each_worker(body) -> Result<(), WorkerError>` as a structured
operation over exactly `parallelism()` worker contexts: invoke `body(Worker)` once on
each distinct logical worker and wait for all invocations. The callback is `Fn(Worker) +
Send + Sync`, may borrow the caller's environment, and may run a channel-driven service
loop. `Worker` exposes its stable index and runtime handle, not an implicit
current-thread context. Nested `for_each_worker` on the same pool returns
`WorkerError::Reentrant`; a service loop receives requests from its own explicit
channel.

State created inside that callback may be non-`Send`. Creation, use, and destruction
remain on the same physical thread throughout suspension and resumption. A multi-thread
deterministic backend must therefore pin those activations. Persistent state across
requests lives explicitly in a worker's service loop. There is no `current_worker()`,
global pool, TLS state slot, or `install` that implicitly changes where nested Rayon
calls run. Reth currently obtains worker state through static pool methods backed by
TLS. Replacing that pattern requires rewriting worker-state access, not merely renaming
imports.

Build these operations above scopes and worker groups, with native Rayon fast paths
where their contracts match:

- Borrowed `join(left, right)` and mutable-slice `for_each`.
- Indexed `map_collect` and `try_map_collect`, preserving input order. Multiple
  errors are chosen by input index, not completion time.
- `map_init` with explicit per-worker scratch state, initialized on its worker.
- `fold`/`reduce` using fixed-size indexed chunks and a left-to-right binary merge tree,
  independent of scheduling. Both backends use the same configured chunk size; arbitrary non-associative Rayon reductions are not promised equivalent.
- `map_ordered`, streaming parallel results in input order to a caller-local
  consumer. That consumer need not be `Send`. It must not wait for the whole
  collection before delivering the first result.

Scoped work is always drained before borrowed data or worker state is destroyed.
Detached job panics become result errors; callers may deliberately route them to the
caller's failure handler, which can shut down the node for a critical job. Scoped parallel algorithms forward panic
after cleanup. For example, named workers currently catch panic and close the result
channel, while trie-proof computation workers report a failed job and recreate the
database provider used to read state for proofs. Adapters must retain such
caller-specific recovery rather than swallow all panics or impose a global abort policy.

## Deterministic execution and Reth coverage

The deterministic implementation uses fixed runnable-task ordering, stable logical
worker identities, fixed waiter tie-breaking, and virtual time. No seed, scheduling
policy, or order-control API is exposed. Repeating the same controlled input stream and
configuration must repeat observable results. Arbitrary external I/O and uncontrolled
Tokio arrivals are outside that guarantee; the `Job::into_future` completion adapter
does not change this boundary.

The native implementation must also avoid starvation when runtime waits occur inside
compute jobs, by suspending a waiting activation and running other ready jobs, or moving
blocking services to dedicated workers. A wrapper that only calls ordinary `recv` on a
Rayon worker cannot promise this contract.

BAL means block access list. Reth uses it during parallel transaction execution; the
associated workers retain local database/EVM state. Provider affinity means creating,
using, and dropping a database provider on one physical worker. A release barrier waits
for all workers to drop that state before the caller proceeds. Build it by
receiving an acknowledgement from every worker after that worker drops its state.

The source inventory uses Reth revision
[`5efe80f`](https://github.com/paradigmxyz/reth/tree/5efe80f515c96fa34b569a22fb810b54f914cfb0)
and covers tasks, engine/tree, and trie, not every dependency in the workspace:

| Existing use | Replacement contract |
| --- | --- |
| [Named worker queues](https://github.com/paradigmxyz/reth/blob/5efe80f515c96fa34b569a22fb810b54f914cfb0/crates/tasks/src/worker_map.rs) | Interned serial workers, eager submission, `try_spawn` rejects a busy lane |
| [Worker pools and non-Send state](https://github.com/paradigmxyz/reth/blob/5efe80f515c96fa34b569a22fb810b54f914cfb0/crates/tasks/src/pool.rs) | Borrowed scopes, explicit worker callbacks and state |
| [Proof worker receive loops](https://github.com/paradigmxyz/reth/blob/5efe80f515c96fa34b569a22fb810b54f914cfb0/crates/trie/parallel/src/proof_task/mod.rs) | Concurrent services, runtime-owned receive, provider affinity |
| [BAL worker abort selection](https://github.com/paradigmxyz/reth/blob/5efe80f515c96fa34b569a22fb810b54f914cfb0/crates/engine/tree/src/tree/payload_processor/bal/worker.rs) | Biased selection and borrowed worker lifetimes |
| [Ordered streaming](https://github.com/paradigmxyz/reth/blob/5efe80f515c96fa34b569a22fb810b54f914cfb0/crates/tasks/src/for_each_ordered.rs) | Ordered caller-local consumer; producer panic wakes blocked consumers |
| [Direct BAL OS-thread pool](https://github.com/paradigmxyz/reth/blob/5efe80f515c96fa34b569a22fb810b54f914cfb0/crates/engine/tree/src/tree/payload_processor/bal_prewarm_pool.rs) | Services process BeginBlock/work/EndBlock in FIFO order; acknowledge state release |
| [Global Rayon storage jobs](https://github.com/paradigmxyz/reth/blob/5efe80f515c96fa34b569a22fb810b54f914cfb0/crates/engine/tree/src/tree/state_root_strategy/sparse_trie.rs) | Explicit pool submission and completion channels |

Replacing Reth's task-management crate (`reth-tasks`) alone does not intercept direct OS
threads, global Rayon calls, existing crossbeam channels, raw sleeps, or shared
synchronization in its callers. Those sites must use this surface before they belong to
the deterministic domain. Tokio task management remains separate. This proposal changes
no consensus or persisted-data semantics and makes no claim of whole-node deterministic
replay.
