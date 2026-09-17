//! Race local body ingress against marshal's normal retrieval path.
use commonware_utils::channel::oneshot;

/// Keep marshal's ready result authoritative, including shutdown errors. A
/// closed or unusable broadcast response leaves its normal fallback untouched.
/// Both receivers are owned by this future, so cancellation drops both waiters.
pub(super) async fn receive<T>(
    mut marshal: oneshot::Receiver<T>,
    broadcast: oneshot::Receiver<T>,
    usable: impl FnOnce(&T) -> bool,
) -> (Result<T, oneshot::error::RecvError>, u64) {
    commonware_macros::select! {
        result = &mut marshal => (result, 2),
        result = broadcast => match result {
            Ok(value) if usable(&value) => (Ok(value), 3),
            _ => (marshal.await, 4),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt as _;

    #[test]
    fn broadcast_unblocks_body_while_marshal_actor_is_pending() {
        let (marshal, primary) = oneshot::channel();
        let (broadcast, secondary) = oneshot::channel();
        broadcast.send(42).unwrap();
        assert_eq!(
            receive(primary, secondary, |value| *value == 42)
                .now_or_never()
                .unwrap(),
            (Ok(42), 3)
        );
        assert!(
            marshal.is_closed(),
            "losing marshal subscription must be cancelled"
        );
    }

    #[test]
    fn both_ready_preserves_marshal_value_or_error() {
        let (marshal, primary) = oneshot::channel();
        let (broadcast, secondary) = oneshot::channel();
        marshal.send(41).unwrap();
        broadcast.send(42).unwrap();
        assert_eq!(
            receive(primary, secondary, |_| true)
                .now_or_never()
                .unwrap(),
            (Ok(41), 2)
        );
        let (marshal, primary) = oneshot::channel::<u64>();
        let (broadcast, secondary) = oneshot::channel();
        drop(marshal);
        broadcast.send(42).unwrap();
        assert!(
            receive(primary, secondary, |_| true)
                .now_or_never()
                .unwrap()
                .0
                .is_err()
        );
    }

    #[test]
    fn closed_or_mismatched_broadcast_keeps_marshal_fallback() {
        for value in [None, Some(99)] {
            let (marshal, primary) = oneshot::channel();
            let (broadcast, secondary) = oneshot::channel();
            if let Some(value) = value {
                broadcast.send(value).unwrap();
            } else {
                drop(broadcast);
            }
            let mut future = Box::pin(receive(primary, secondary, |value| *value == 42));
            assert!(future.as_mut().now_or_never().is_none());
            assert!(!marshal.is_closed());
            marshal.send(42).unwrap();
            assert_eq!(future.now_or_never().unwrap(), (Ok(42), 4));
        }
    }

    #[test]
    fn marshal_closure_drops_pending_broadcast() {
        let (marshal, primary) = oneshot::channel::<u64>();
        let (broadcast, secondary) = oneshot::channel();
        drop(marshal);
        assert!(
            receive(primary, secondary, |_| true)
                .now_or_never()
                .unwrap()
                .0
                .is_err()
        );
        assert!(broadcast.is_closed());
    }

    #[test]
    fn parent_cancellation_drops_both_subscriptions() {
        let (marshal, primary) = oneshot::channel::<u64>();
        let (broadcast, secondary) = oneshot::channel();
        let mut future = Box::pin(receive(primary, secondary, |_| true));
        assert!(future.as_mut().now_or_never().is_none());
        drop(future);
        assert!(marshal.is_closed());
        assert!(broadcast.is_closed());
    }

    #[test]
    fn marshal_success_drops_pending_broadcast() {
        let (marshal, primary) = oneshot::channel();
        let (broadcast, secondary) = oneshot::channel();
        marshal.send(42).unwrap();
        assert_eq!(
            receive(primary, secondary, |_| true)
                .now_or_never()
                .unwrap(),
            (Ok(42), 2)
        );
        assert!(broadcast.is_closed());
    }
}
