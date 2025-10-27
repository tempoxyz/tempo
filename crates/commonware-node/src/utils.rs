use commonware_consensus::Reporter;
use tokio::sync::mpsc;

/// A reporter that forwards [`Reporter::Activity`] to an [`mpsc::UnboundedSender`].
#[derive(Debug)]
pub(crate) struct ChannelReporter<T> {
    tx: mpsc::UnboundedSender<T>,
}

impl<T> Clone for ChannelReporter<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<T> ChannelReporter<T> {
    /// Creates a new [`ChannelReporter`] and returns a receiver for the activities.
    pub(crate) fn new() -> (Self, mpsc::UnboundedReceiver<T>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

impl<T: Send + Sync + 'static> Reporter for ChannelReporter<T> {
    type Activity = T;

    async fn report(&mut self, activity: T) -> () {
        let _ = self.tx.send(activity);
    }
}
