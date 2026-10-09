//! Zone-native precompiles and shared execution for Tempo precompiles on a Zone.
//!
//! All implementations use ordinary EVM storage. The Zone EVM installs an anchored database below
//! the revm journal, so TIP-20, TIP-403, and Zone fee-manager code transparently observe
//! finalized Tempo policy state. Zone admission, delegate-call, fixed-gas, and privacy rules remain
//! outside the forwarded business logic.
//!
//! This crate is `no_std` compatible so these precompiles can run inside the
//! SP1 prover guest (RISC-V) as well as in the zone node.
//!
//! ## Cryptography
//!
//! - **Chaum-Pedersen verification** — verifies DLOG equality proofs for ECDH shared secret
//!   derivation inside the native inbox.
//! - **AES-256-GCM decryption** — decrypts ECIES ciphertext and verifies
//!   the GCM authentication tag inside the native inbox.
//! - **ECIES** ([`ecies`]) — sequencer-side ECIES decryption logic.
//!
//! ## Policy/token precompiles
//!
//! - **NonceManager** ([`nonce`]) — upstream 2D nonces with account-scoped read rules.
//! - **AccountKeychain** ([`account_keychain`]) — upstream key management with account-scoped
//!   read rules.
//! - **StorageCredits** ([`storage_credits`]) — upstream storage-credit accounting with
//!   account-scoped read rules.
//! - **Zone Inbox** ([`inbox`]) — advances Tempo state and processes the deposit queue.
//! - **TIP-403 Registry** ([`tip403_proxy`]) — upstream registry over finalized L1 state.
//! - **Zone TIP-20** ([`ztip20`]) — upstream TIP-20 with zone call rules.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

macro_rules! zone_precompile {
    ($env:expr, $precompile:path) => {
        zone_precompile!($env, $precompile, $crate::execution::NoCallRules)
    };
    ($env:expr, $precompile:path, $rules:expr) => {
        $crate::execution::create_precompile(
            stringify!($precompile),
            &$env,
            $rules,
            |data, caller| {
                tempo_precompiles::Precompile::call(&mut <$precompile>::new(), data, caller)
            },
        )
    };
}

pub mod error;
pub use error::{Result, ZonePrecompileError, ZoneResult};

mod aes_gcm;
mod chaum_pedersen;
pub mod ecies;
pub mod outbox;

/// Zone dispatch helpers for generic typed operations.
pub mod dispatch {
    pub use tempo_precompiles::dispatch::typed::{mutate, view};
}

mod execution;
mod privacy;
pub use execution::ZonePrecompileEnv;
mod account_keychain;
pub mod inbox;
mod nonce;
pub mod receive_policy_guard;
pub mod storage;
mod storage_credits;
pub mod tempo_state;
pub mod tip403_proxy;
#[cfg(feature = "std")]
pub mod tx_context;
pub mod zone_fee_manager;
pub mod zone_state;
pub mod ztip20;

pub use inbox::{ADVANCE_TEMPO_HEADERS_SELECTOR, ADVANCE_TEMPO_SELECTOR, ZoneInbox};
pub use outbox::ZoneOutbox;
pub use storage::{L1State, L1StateError, L1StorageReader};
pub use tempo_contracts::precompiles::TIP403_REGISTRY_ADDRESS;
pub use tempo_state::TempoState;
pub use zone_fee_manager::{ZONE_FEE_MANAGER_ADDRESS, ZoneFeeManager};

use alloc::rc::Rc;
use core::cell::RefCell;

use alloy_evm::precompiles::{DynPrecompile, PrecompilesMap};
use alloy_primitives::Address;
use alloy_sol_types::SolError;
use revm::{context::CfgEnv, handler::EthPrecompiles, primitives::hardfork::SpecId};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, NONCE_PRECOMPILE_ADDRESS, Precompile as _,
    RECEIVE_POLICY_GUARD_ADDRESS, STORAGE_CREDITS_ADDRESS,
    account_keychain::AccountKeychain,
    nonce::NonceManager,
    receive_policy_guard::ReceivePolicyGuard,
    storage::actions::StorageActions,
    storage_credits::{NonCreditableSlots, StorageCredits},
    tip20::{ITIP20::InsufficientBalance as TIP20InsufficientBalance, TIP20Token, is_tip20_prefix},
    tip403_registry::TIP403Registry,
};
#[cfg(feature = "std")]
use tempo_zone_contracts::ZONE_OUTBOX_ADDRESS;
use tempo_zone_contracts::{TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS};

/// Returns every precompile that is available to a Zone EVM.
///
/// The Zone wrappers all share one [`ZonePrecompileEnv`] and one execution-local [`L1State`].
/// Sharing those values is important: the database overlay and the L1-backed precompiles must use
/// the same Tempo anchor and the same storage-credit accounting state during a transaction.
pub fn zone_precompiles<P>(
    cfg: &CfgEnv<TempoHardfork>,
    l1: L1State<P>,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
) -> PrecompilesMap
where
    P: L1StorageReader,
{
    let env = ZonePrecompileEnv::new(cfg, actions, non_creditable_slots);
    let spec = if cfg.spec.is_t1c() {
        cfg.spec.into()
    } else {
        SpecId::PRAGUE
    };
    let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::new(spec).precompiles);

    precompiles.set_precompile_lookup(move |address: &Address| {
        #[cfg(feature = "std")]
        if *address == ZONE_OUTBOX_ADDRESS {
            return Some(create_outbox_precompile(l1.clone(), &env));
        }

        if is_tip20_prefix(*address) {
            Some(create_tip20_precompile(*address, &env))
        } else if *address == TEMPO_STATE_ADDRESS {
            Some(TempoState::create(l1.clone(), &env))
        } else if *address == ZONE_INBOX_ADDRESS {
            Some(ZoneInbox::create(l1.clone(), &env))
        } else if *address == ZONE_FEE_MANAGER_ADDRESS {
            Some(zone_precompile!(env, ZoneFeeManager))
        } else if *address == TIP403_REGISTRY_ADDRESS {
            Some(zone_precompile!(
                env,
                TIP403Registry,
                tip403_proxy::Tip403Rules
            ))
        } else if *address == NONCE_PRECOMPILE_ADDRESS {
            Some(zone_precompile!(env, NonceManager, nonce::NonceRules))
        } else if *address == ACCOUNT_KEYCHAIN_ADDRESS {
            Some(zone_precompile!(
                env,
                AccountKeychain,
                account_keychain::AccountKeychainRules
            ))
        } else if *address == RECEIVE_POLICY_GUARD_ADDRESS {
            Some(zone_precompile!(
                env,
                ReceivePolicyGuard,
                receive_policy_guard::ReceivePolicyGuardRules
            ))
        } else if *address == STORAGE_CREDITS_ADDRESS {
            Some(zone_precompile!(
                env,
                StorageCredits,
                storage_credits::StorageCreditsRules
            ))
        } else {
            // unsupported L1 precompiles:
            // TIP20Factory, TipFeeManager, TIP20ChannelReserve, StablecoinDEX
            None
        }
    });
    precompiles
}

/// Creates the native ZoneOutbox over ordinary Zone storage and the L1-mirrored portal account.
#[cfg(feature = "std")]
pub fn create_outbox_precompile<P>(l1: L1State<P>, env: &ZonePrecompileEnv) -> DynPrecompile
where
    P: L1StorageReader,
{
    execution::create_precompile(
        "ZoneOutbox",
        env,
        execution::NoCallRules,
        move |data, caller| {
            let (tx_hash, fee_payer) =
                tx_context::current_transaction().unwrap_or((Default::default(), caller));
            ZoneOutbox::new().call_with_transaction(&l1, data, caller, tx_hash, fee_payer)
        },
    )
}

/// Creates upstream TIP-20 execution with zone rules and adapter-backed L1 policy reads.
pub fn create_tip20_precompile(address: Address, env: &ZonePrecompileEnv) -> DynPrecompile {
    // Redacts TIP20 transfer from reverts that reveal user balances to the spender.
    let redact = |mut res: revm::precompile::PrecompileOutput| {
        if res.is_revert() && res.bytes.starts_with(&TIP20InsufficientBalance::SELECTOR) {
            res.bytes = crate::ztip20::InsufficientBalance {}.abi_encode().into();
        }
        res
    };

    execution::create_precompile(
        "TIP20Token",
        env,
        ztip20::TIP20Rules,
        move |data, caller| {
            TIP20Token::from_address_unchecked(address)
                .call(data, caller)
                .map(redact)
        },
    )
}

#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod test_utils;
