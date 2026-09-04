use tracing::Span;

/// Lifecycle of a view's root tracing span.
///
/// A view is anchored by a single root span that opens when the view becomes
/// active and is released when the chain decides it. The voter and batcher each
/// hold a clone of this span, so the underlying trace ends only once both
/// owners release it. Once released this owner cannot reopen, so a round
/// retained for backfill or deduplication never anchors a new trace.
pub(crate) enum ViewSpan {
    /// Not yet opened.
    Pending,
    /// Active root span anchoring the view's work.
    Open(Span),
    /// View decided; this owner released the span and cannot reopen.
    Closed,
}

impl ViewSpan {
    /// Creates a span that has not yet opened.
    pub(crate) const fn new() -> Self {
        Self::Pending
    }

    /// Returns the active span, or a disabled span when pending or closed.
    pub(crate) fn get(&self) -> Span {
        match self {
            Self::Open(span) => span.clone(),
            Self::Pending | Self::Closed => Span::none(),
        }
    }

    /// Opens the span from `make` when pending. No-op once open. Opening a
    /// closed view span means a decided view was reactivated and panics.
    pub(crate) fn open(&mut self, make: impl FnOnce() -> Span) {
        assert!(!matches!(self, Self::Closed), "reopened a closed view span");
        if matches!(self, Self::Pending) {
            *self = Self::Open(make());
        }
    }

    /// Adopts an externally created span when pending. No-op once open. Adopting
    /// onto a closed view span means a decided view was reactivated and panics.
    pub(crate) fn adopt(&mut self, span: Span) {
        assert!(
            !matches!(self, Self::Closed),
            "adopted onto a closed view span"
        );
        if matches!(self, Self::Pending) {
            *self = Self::Open(span);
        }
    }

    /// Releases this owner's clone of the span. No-op if already released. The
    /// underlying span ends once the other owner releases its clone too, and it
    /// cannot reopen here.
    pub(crate) fn close(&mut self) {
        *self = Self::Closed;
    }
}
