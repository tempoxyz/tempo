use reth_revm::cancelled::CancelOnDrop;
use std::{fmt, sync::mpsc, time::Duration};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompletionError {
    Cancelled,
    Disconnected,
}

impl fmt::Display for CompletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("payload build cancelled"),
            Self::Disconnected => f.write_str("payload completion producer dropped"),
        }
    }
}

impl std::error::Error for CompletionError {}

pub(crate) fn recv<T>(
    receiver: mpsc::Receiver<T>,
    cancel: &CancelOnDrop,
) -> Result<T, CompletionError> {
    loop {
        if cancel.is_cancelled() {
            return Err(CompletionError::Cancelled);
        }
        // Ready results wake immediately; the timeout bounds cancellation latency while idle.
        let result = receiver.recv_timeout(Duration::from_millis(10));
        if cancel.is_cancelled() {
            return Err(CompletionError::Cancelled);
        }
        match result {
            Ok(value) => return Ok(value),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(CompletionError::Disconnected);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receives_completed_work() {
        let (tx, rx) = mpsc::channel();
        tx.send(42).unwrap();
        assert_eq!(recv(rx, &CancelOnDrop::default()), Ok(42));
    }

    #[test]
    fn reports_disconnected_producer() {
        let (tx, rx) = mpsc::channel::<()>();
        drop(tx);
        assert_eq!(
            recv(rx, &CancelOnDrop::default()),
            Err(CompletionError::Disconnected)
        );
    }

    #[test]
    fn finalization_request_still_requires_completed_work() {
        let cancel = CancelOnDrop::default();
        cancel.request_finalization();
        let (tx, rx) = mpsc::channel();
        tx.send(42).unwrap();
        assert_eq!(recv(rx, &cancel), Ok(42));
    }

    #[test]
    fn cancelled_work_is_not_accepted() {
        let cancel = CancelOnDrop::default();
        drop(cancel.clone());
        let (tx, rx) = mpsc::channel();
        tx.send(42).unwrap();
        assert_eq!(recv(rx, &cancel), Err(CompletionError::Cancelled));
    }

    #[test]
    fn cancellation_releases_idle_receiver() {
        let cancel = CancelOnDrop::default();
        let worker_cancel = cancel.clone();
        let (_tx, rx) = mpsc::channel::<()>();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            result_tx.send(recv(rx, &worker_cancel)).unwrap();
        });
        drop(cancel);
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Err(CompletionError::Cancelled)
        );
        worker.join().unwrap();
    }
}
