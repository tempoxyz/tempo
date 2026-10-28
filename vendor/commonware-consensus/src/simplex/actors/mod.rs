mod span;

pub mod batcher;
pub mod resolver;
pub mod voter;

/// What a resolver request wants, and what retires it.
///
/// The wire key names only a view, so a responder cannot tell which certificate was
/// asked for and may answer with one that does not settle the request. Keeping the
/// ask local lets the requester recognize that case (see [resolver::Actor::settled]).
///
/// Only three of the four combinations occur: background repair always wants a
/// nullification, while proposal ancestry wants either kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Ask {
    /// The certificate that settles the request.
    pub kind: Kind,
    /// The boundary that retires the request.
    pub until: Until,
}

impl Ask {
    /// Returns an ask for background repair of a nullification gap.
    pub const fn backfill() -> Self {
        Self {
            kind: Kind::Nullification,
            until: Until::Floor,
        }
    }

    /// Returns an ask for ancestry a proposal named.
    pub const fn ancestry(kind: Kind) -> Self {
        Self {
            kind,
            until: Until::Finalization,
        }
    }
}

/// The certificate that settles a request.
///
/// A notarization and a nullification covering the same view can both exist, and
/// neither substitutes for the other, so this cannot be inferred from the view.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Kind {
    /// A nullification covering the view.
    ///
    /// Wanted to justify a proposal that skips the view, and to fill the
    /// nullification gaps below the current view.
    Nullification,
    /// A notarization for the view.
    ///
    /// Wanted to certify the parent a proposal names.
    Notarization,
}

impl Kind {
    /// Returns the stable trace field value for this kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nullification => "nullification",
            Self::Notarization => "notarization",
        }
    }
}

/// The boundary at which an ask retires.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Until {
    /// The resolver floor passes the view.
    ///
    /// Used for background repair of the nullification gaps below the current
    /// view, which resolver state stops tracking once its floor is above them.
    Floor,
    /// The view is finalized.
    ///
    /// Used for ancestry a proposal named. A proposal may name ancestry below
    /// the local floor, as when a peer holds a nullification for a view this
    /// node certified a notarization for. Only finalization retires the ask.
    Finalization,
}
