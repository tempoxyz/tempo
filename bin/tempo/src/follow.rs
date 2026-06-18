//! Follow mode configuration for syncing from an upstream node.

use std::{convert::Infallible, str::FromStr};
use tempo_chainspec::spec::TempoChainSpec;

/// The upstream a follower syncs from, as parsed from `--follow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FollowMode {
    /// Use the default follow URL for the selected chain.
    Auto,
    /// Follow an explicit upstream websocket URL.
    Url(String),
}

impl FollowMode {
    /// Resolves the mode to a concrete upstream URL.
    ///
    /// [`Auto`](Self::Auto) resolves to the chain's default follow URL, which may be absent for
    /// chains without one; an explicit [`Url`](Self::Url) is always returned as-is.
    pub(crate) fn resolve_url(&self, chain_spec: &TempoChainSpec) -> Option<String> {
        match self {
            Self::Auto => chain_spec.default_follow_url().map(str::to_string),
            Self::Url(url) => Some(url.clone()),
        }
    }
}

impl FromStr for FollowMode {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "auto" {
            Self::Auto
        } else {
            Self::Url(s.to_string())
        })
    }
}
