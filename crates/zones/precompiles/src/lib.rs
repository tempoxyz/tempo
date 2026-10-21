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
//! - **NonceManager** (`nonce`) — upstream 2D nonces with account-scoped read rules.
//! - **AccountKeychain** (`account_keychain`) — upstream key management with account-scoped
//!   read rules.
//! - **StorageCredits** (`storage_credits`) — upstream storage-credit accounting with
//!   account-scoped read rules.
//! - **Zone Inbox** ([`inbox`]) — advances Tempo state and processes the deposit queue.
//! - **TIP-403 Registry** ([`tip403_proxy`]) — upstream registry over finalized L1 state.
//! - **Zone TIP-20** ([`ztip20`]) — upstream TIP-20 with zone call rules.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

macro_rules! zone_precompile {
    ($evm:expr, $message:expr, $gas:expr, $env:expr, $precompile:path) => {
        zone_precompile!(
            $evm,
            $message,
            $gas,
            $env,
            $precompile,
            $crate::execution::NoCallRules
        )
    };
    ($evm:expr, $message:expr, $gas:expr, $env:expr, $precompile:path, $rules:expr) => {
        $crate::execution::execute_precompile($evm, $message, $gas, $env, $rules, |data, caller| {
            tempo_precompiles::Precompile::call(&mut <$precompile>::new(), data, caller)
        })
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

use alloy_primitives::Address;
use alloy_sol_types::SolError;
use evm2::{
    Evm, EvmTypes, Precompiles as BasePrecompiles, SpecId,
    evm::precompile::PrecompileProvider,
    interpreter::{GasTracker, Message},
    precompiles::{MovePrecompileError, PrecompileError, PrecompileId, PrecompileResult},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::zones::{TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS};
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
use tempo_primitives::TempoBlockExt;

/// Returns every precompile that is available to a Zone EVM.
///
/// The Zone wrappers all share one [`ZonePrecompileEnv`] and one execution-local [`L1State`].
/// Sharing those values is important: the database overlay and the L1-backed precompiles must use
/// the same Tempo anchor and the same storage-credit accounting state during a transaction.
#[derive(Debug)]
pub struct ZonePrecompiles<T: evm2::EvmTypesHost, P> {
    base: BasePrecompiles<T>,
    env: ZonePrecompileEnv,
    l1: L1State<P>,
}

impl<T, P> ZonePrecompiles<T, P>
where
    T: evm2::EvmTypesHost,
    P: L1StorageReader,
{
    /// Creates the Zone precompile set for `spec`.
    ///
    /// `actions` and `non_creditable_slots` are the transaction-local storage accounting state
    /// shared with the Zone EVM, and `l1` is the execution-local view of anchored Tempo state.
    pub fn new(
        spec: TempoHardfork,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
        l1: L1State<P>,
    ) -> Self {
        // Tempo used Prague's built-ins before T1C and follows its configured EVM fork after it.
        let base_spec = if spec.is_t1c() {
            spec.into()
        } else {
            SpecId::PRAGUE
        };
        Self {
            base: BasePrecompiles::base(base_spec),
            env: ZonePrecompileEnv::new(spec, actions, non_creditable_slots),
            l1,
        }
    }
}

impl<T, P> PrecompileProvider<T> for ZonePrecompiles<T, P>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    P: L1StorageReader,
{
    fn move_precompiles(
        &mut self,
        moves: &[(Address, Address)],
    ) -> core::result::Result<(), MovePrecompileError> {
        self.base.move_precompiles(moves)
    }

    fn addresses(&self) -> alloc::vec::Vec<Address> {
        self.base.addresses()
    }

    fn precompile_ids(&self) -> alloc::vec::Vec<(Address, PrecompileId)> {
        self.base.precompile_ids()
    }

    fn contains(&self, address: &Address) -> bool {
        self.base.contains(address)
            || is_tip20_prefix(*address)
            || matches!(
                *address,
                TEMPO_STATE_ADDRESS
                    | ZONE_INBOX_ADDRESS
                    | ZONE_FEE_MANAGER_ADDRESS
                    | TIP403_REGISTRY_ADDRESS
                    | NONCE_PRECOMPILE_ADDRESS
                    | ACCOUNT_KEYCHAIN_ADDRESS
                    | RECEIVE_POLICY_GUARD_ADDRESS
                    | STORAGE_CREDITS_ADDRESS
            )
            || cfg!(feature = "std") && *address == tempo_contracts::zones::ZONE_OUTBOX_ADDRESS
    }

    fn execute(
        &mut self,
        evm: &mut Evm<'_, T>,
        message: &Message<T>,
        gas: &mut GasTracker,
    ) -> Option<PrecompileResult> {
        let address = message.code_address;
        if let Some(result) = self.base.execute(evm, message, gas) {
            return Some(result);
        }

        let result = if is_tip20_prefix(address) {
            execution::execute_precompile(
                evm,
                message,
                gas,
                &self.env,
                ztip20::TIP20Rules,
                |data, caller| {
                    TIP20Token::from_address_unchecked(address)
                        .call(data, caller)
                        .map_err(|error| match error {
                            PrecompileError::Revert(bytes)
                                if bytes.starts_with(&TIP20InsufficientBalance::SELECTOR) =>
                            {
                                PrecompileError::Revert(
                                    crate::ztip20::InsufficientBalance {}.abi_encode().into(),
                                )
                            }
                            error => error,
                        })
                },
            )
        } else if address == TEMPO_STATE_ADDRESS {
            execution::execute_precompile(
                evm,
                message,
                gas,
                &self.env,
                execution::NoCallRules,
                |data, caller| TempoState::new().call_with_l1_state(&self.l1, data, caller),
            )
        } else if address == ZONE_INBOX_ADDRESS {
            execution::execute_precompile(
                evm,
                message,
                gas,
                &self.env,
                execution::NoCallRules,
                |data, caller| ZoneInbox::new().call(&self.l1, data, caller),
            )
        } else if address == ZONE_FEE_MANAGER_ADDRESS {
            zone_precompile!(evm, message, gas, &self.env, ZoneFeeManager)
        } else if address == TIP403_REGISTRY_ADDRESS {
            zone_precompile!(
                evm,
                message,
                gas,
                &self.env,
                TIP403Registry,
                tip403_proxy::Tip403Rules
            )
        } else if address == NONCE_PRECOMPILE_ADDRESS {
            zone_precompile!(
                evm,
                message,
                gas,
                &self.env,
                NonceManager,
                nonce::NonceRules
            )
        } else if address == ACCOUNT_KEYCHAIN_ADDRESS {
            zone_precompile!(
                evm,
                message,
                gas,
                &self.env,
                AccountKeychain,
                account_keychain::AccountKeychainRules
            )
        } else if address == RECEIVE_POLICY_GUARD_ADDRESS {
            zone_precompile!(
                evm,
                message,
                gas,
                &self.env,
                ReceivePolicyGuard,
                receive_policy_guard::ReceivePolicyGuardRules
            )
        } else if address == STORAGE_CREDITS_ADDRESS {
            zone_precompile!(
                evm,
                message,
                gas,
                &self.env,
                StorageCredits,
                storage_credits::StorageCreditsRules
            )
        } else {
            #[cfg(feature = "std")]
            if address == tempo_contracts::zones::ZONE_OUTBOX_ADDRESS {
                return Some(execution::execute_precompile(
                    evm,
                    message,
                    gas,
                    &self.env,
                    execution::NoCallRules,
                    |data, caller| {
                        let (tx_hash, fee_payer) = tx_context::current_transaction()
                            .unwrap_or((Default::default(), caller));
                        ZoneOutbox::new()
                            .call_with_transaction(&self.l1, data, caller, tx_hash, fee_payer)
                    },
                ));
            }
            // unsupported L1 precompiles:
            // TIP20Factory, TipFeeManager, TIP20ChannelReserve, StablecoinDEX
            return None;
        };

        Some(result)
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod test_utils;
