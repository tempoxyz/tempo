//! Shared registry of tokens enabled for a zone.

use alloy_primitives::Address;
use derive_more::Deref;
use parking_lot::RwLock;
use std::{collections::HashSet, sync::Arc};

/// Token addresses discovered at startup and from confirmed `TokenEnabled` events.
#[derive(Debug, Clone, Deref, Default)]
pub struct EnabledTokenRegistry {
    #[deref]
    inner: Arc<RwLock<HashSet<Address>>>,
}
