// Verify the shutdown contract required by the engine against the pinned runtime.
use commonware_runtime::{Error, Handle, Metrics, Runner, Spawner, Supervisor, deterministic};
use futures::{FutureExt, future};

fn assert_stopped(context: &deterministic::Context, label: &str) {
    let metrics = context.encode();
    let label = format!("name=\"{label}\"");
    let running = metrics.lines().find_map(|line| {
        (line.starts_with("runtime_tasks_running{") && line.contains(&label))
            .then(|| line.rsplit_once(' ').unwrap().1)
    });
    assert_eq!(running, Some("0"), "actor still running: {metrics}");
}

#[test]
fn successful_exit_aborts_pending_siblings() {
    deterministic::Runner::default().start(|context| async move {
        let pending = context.child("pending").spawn(|_| future::pending::<()>());
        let completed = context.child("completed").spawn(|_| async {});

        Handle::select(vec![pending, completed]).await.unwrap();

        assert_stopped(&context, "pending");
    });
}

#[test]
fn failed_exit_aborts_pending_siblings() {
    deterministic::Runner::default().start(|context| async move {
        let pending = context.child("pending").spawn(|_| future::pending::<()>());
        let failed = Handle::ready(Err(Error::Exited));

        assert!(matches!(
            Handle::select(vec![pending, failed]).await,
            Err(Error::Exited)
        ));

        assert_stopped(&context, "pending");
    });
}

#[test]
fn cancellation_before_first_poll_aborts_actors() {
    deterministic::Runner::default().start(|context| async move {
        let first = context.child("first").spawn(|_| future::pending::<()>());
        let second = context.child("second").spawn(|_| future::pending::<()>());

        drop(Handle::select(vec![first, second]));

        assert_stopped(&context, "first");
        assert_stopped(&context, "second");
    });
}

#[test]
fn cancellation_while_waiting_aborts_actors() {
    deterministic::Runner::default().start(|context| async move {
        let first = context.child("first").spawn(|_| future::pending::<()>());
        let second = context.child("second").spawn(|_| future::pending::<()>());
        let mut supervisor = Box::pin(Handle::select(vec![first, second]));
        assert!(supervisor.as_mut().now_or_never().is_none());

        drop(supervisor);

        assert_stopped(&context, "first");
        assert_stopped(&context, "second");
    });
}

#[test]
fn empty_group_returns_closed() {
    assert!(matches!(
        Handle::<()>::select(vec![]).now_or_never(),
        Some(Err(Error::Closed))
    ));
}
