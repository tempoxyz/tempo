use std::{cell::RefCell, rc::Rc};

use alloy::primitives::{Address, B256, FixedBytes};
use scoped_tls::scoped_thread_local;

use super::AuthorizedKey;

scoped_thread_local!(static KEYCHAIN_TX_CACHE: Rc<RefCell<KeychainTxCache>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CachedTxKeyContext {
    pub tx_origin: Address,
    pub transaction_key: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedAccessKeyContext {
    pub account: Address,
    pub tx_origin: Address,
    pub transaction_key: Address,
    pub key_hash: B256,
    pub key: AuthorizedKey,
}

#[derive(Debug, Clone, Copy)]
struct CachedScopedKey {
    key_hash: B256,
    is_scoped: bool,
}

#[derive(Debug, Clone, Copy)]
struct CachedTargetScope {
    key_hash: B256,
    target: Address,
    allowed: bool,
    unconstrained: bool,
}

#[derive(Debug, Clone, Copy)]
struct CachedSelectorScope {
    key_hash: B256,
    target: Address,
    selector: FixedBytes<4>,
    allowed: bool,
    unconstrained: bool,
}

#[derive(Debug, Clone, Copy)]
struct CachedRecipientScope {
    key_hash: B256,
    target: Address,
    selector: FixedBytes<4>,
    recipient: Address,
    allowed: bool,
}

/// Transaction-scoped, typed cache for keychain facts that are repeatedly used by TIP-20 paths.
///
/// This intentionally caches decoded keychain facts, not raw storage slots. Mutable spending limit
/// rows are still read and written through storage so normal EVM checkpoint/revert semantics remain
/// authoritative during nested calls.
#[derive(Debug, Default)]
pub struct KeychainTxCache {
    tx_key: Option<CachedTxKeyContext>,
    access_key: Option<LoadedAccessKeyContext>,
    scoped_keys: Vec<CachedScopedKey>,
    target_scopes: Vec<CachedTargetScope>,
    selector_scopes: Vec<CachedSelectorScope>,
    recipient_scopes: Vec<CachedRecipientScope>,
}

impl KeychainTxCache {
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn tx_key(&self) -> Option<CachedTxKeyContext> {
        self.tx_key
    }

    pub(crate) fn set_tx_key(&mut self, tx_key: CachedTxKeyContext) {
        if self.tx_key == Some(tx_key) {
            return;
        }

        self.tx_key = Some(tx_key);
        self.access_key = self.access_key.take().filter(|access_key| {
            access_key.tx_origin == tx_key.tx_origin
                && access_key.transaction_key == tx_key.transaction_key
        });
    }

    pub(crate) fn set_tx_origin(&mut self, tx_origin: Address) {
        let tx_key = self.tx_key.get_or_insert(CachedTxKeyContext {
            tx_origin,
            transaction_key: Address::ZERO,
        });
        if tx_key.tx_origin != tx_origin {
            tx_key.tx_origin = tx_origin;
            self.access_key = None;
        }
    }

    pub(crate) fn set_transaction_key(&mut self, transaction_key: Address) {
        let tx_key = self.tx_key.get_or_insert(CachedTxKeyContext {
            tx_origin: Address::ZERO,
            transaction_key,
        });
        if tx_key.transaction_key != transaction_key {
            tx_key.transaction_key = transaction_key;
            self.access_key = self
                .access_key
                .take()
                .filter(|access_key| access_key.transaction_key == transaction_key);
        }
    }

    pub(crate) fn access_key(
        &self,
        account: Address,
        transaction_key: Address,
    ) -> Option<LoadedAccessKeyContext> {
        self.access_key
            .as_ref()
            .filter(|access_key| {
                access_key.account == account && access_key.transaction_key == transaction_key
            })
            .cloned()
    }

    pub(crate) fn set_access_key(&mut self, access_key: LoadedAccessKeyContext) {
        self.access_key = Some(access_key);
    }

    pub(crate) fn invalidate_account_key(
        &mut self,
        account: Address,
        key_id: Address,
        key_hash: B256,
    ) {
        if self.access_key.as_ref().is_some_and(|access_key| {
            access_key.account == account && access_key.transaction_key == key_id
        }) {
            self.access_key = None;
        }
        self.invalidate_scope(key_hash);
    }

    pub(crate) fn invalidate_scope(&mut self, key_hash: B256) {
        self.scoped_keys.retain(|entry| entry.key_hash != key_hash);
        self.target_scopes
            .retain(|entry| entry.key_hash != key_hash);
        self.selector_scopes
            .retain(|entry| entry.key_hash != key_hash);
        self.recipient_scopes
            .retain(|entry| entry.key_hash != key_hash);
    }

    pub(crate) fn scoped_key(&self, key_hash: B256) -> Option<bool> {
        self.scoped_keys
            .iter()
            .find(|entry| entry.key_hash == key_hash)
            .map(|entry| entry.is_scoped)
    }

    pub(crate) fn set_scoped_key(&mut self, key_hash: B256, is_scoped: bool) {
        if let Some(entry) = self
            .scoped_keys
            .iter_mut()
            .find(|entry| entry.key_hash == key_hash)
        {
            entry.is_scoped = is_scoped;
        } else {
            self.scoped_keys.push(CachedScopedKey {
                key_hash,
                is_scoped,
            });
        }
    }

    pub(crate) fn target_scope(&self, key_hash: B256, target: Address) -> Option<(bool, bool)> {
        self.target_scopes
            .iter()
            .find(|entry| entry.key_hash == key_hash && entry.target == target)
            .map(|entry| (entry.allowed, entry.unconstrained))
    }

    pub(crate) fn set_target_scope(
        &mut self,
        key_hash: B256,
        target: Address,
        allowed: bool,
        unconstrained: bool,
    ) {
        if let Some(entry) = self
            .target_scopes
            .iter_mut()
            .find(|entry| entry.key_hash == key_hash && entry.target == target)
        {
            entry.allowed = allowed;
            entry.unconstrained = unconstrained;
        } else {
            self.target_scopes.push(CachedTargetScope {
                key_hash,
                target,
                allowed,
                unconstrained,
            });
        }
    }

    pub(crate) fn selector_scope(
        &self,
        key_hash: B256,
        target: Address,
        selector: FixedBytes<4>,
    ) -> Option<(bool, bool)> {
        self.selector_scopes
            .iter()
            .find(|entry| {
                entry.key_hash == key_hash && entry.target == target && entry.selector == selector
            })
            .map(|entry| (entry.allowed, entry.unconstrained))
    }

    pub(crate) fn set_selector_scope(
        &mut self,
        key_hash: B256,
        target: Address,
        selector: FixedBytes<4>,
        allowed: bool,
        unconstrained: bool,
    ) {
        if let Some(entry) = self.selector_scopes.iter_mut().find(|entry| {
            entry.key_hash == key_hash && entry.target == target && entry.selector == selector
        }) {
            entry.allowed = allowed;
            entry.unconstrained = unconstrained;
        } else {
            self.selector_scopes.push(CachedSelectorScope {
                key_hash,
                target,
                selector,
                allowed,
                unconstrained,
            });
        }
    }

    pub(crate) fn recipient_scope(
        &self,
        key_hash: B256,
        target: Address,
        selector: FixedBytes<4>,
        recipient: Address,
    ) -> Option<bool> {
        self.recipient_scopes
            .iter()
            .find(|entry| {
                entry.key_hash == key_hash
                    && entry.target == target
                    && entry.selector == selector
                    && entry.recipient == recipient
            })
            .map(|entry| entry.allowed)
    }

    pub(crate) fn set_recipient_scope(
        &mut self,
        key_hash: B256,
        target: Address,
        selector: FixedBytes<4>,
        recipient: Address,
        allowed: bool,
    ) {
        if let Some(entry) = self.recipient_scopes.iter_mut().find(|entry| {
            entry.key_hash == key_hash
                && entry.target == target
                && entry.selector == selector
                && entry.recipient == recipient
        }) {
            entry.allowed = allowed;
        } else {
            self.recipient_scopes.push(CachedRecipientScope {
                key_hash,
                target,
                selector,
                recipient,
                allowed,
            });
        }
    }
}

pub struct KeychainTxCacheCtx;

impl KeychainTxCacheCtx {
    pub fn enter<R>(cache: &Rc<RefCell<KeychainTxCache>>, f: impl FnOnce() -> R) -> R {
        KEYCHAIN_TX_CACHE.set(cache, f)
    }

    pub(crate) fn with<R>(f: impl FnOnce(&mut KeychainTxCache) -> R) -> Option<R> {
        if !KEYCHAIN_TX_CACHE.is_set() {
            return None;
        }

        Some(KEYCHAIN_TX_CACHE.with(|cache| f(&mut cache.borrow_mut())))
    }
}
