//! Zone fixture: the Zone system contracts on a test EVM, anchored to a mocked L1 portal.

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolValue};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::zones::{
    DecryptionData, DepositType, EnabledToken, IZoneInbox, IZoneOutbox, QueuedDeposit,
    ZonePortal::Role,
};
use tempo_precompiles::{
    receive_policy_guard::ReceivePolicyGuard,
    storage::{ContractStorage, Handler, StorageCtx},
    test_util::TIP20Setup,
    tip20::{ITIP20, TIP20Token},
    zone_factory::ZonePortalStorage,
};
use tempo_primitives::TempoHeader;
use zone_primitives::constants::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS};

use super::{
    MockL1Reader, PrecompileOutput, PrecompileResult, TestContext, TestPrecompiles,
    call_precompile, test_context_with_hardfork, test_precompiles, test_storage_provider,
};
use crate::{L1State, TempoState, ZoneInbox, ZoneOutbox, tx_context};

/// Transaction hash [`ZoneEnv::request_withdrawal`] publishes for the requesting transaction.
pub(crate) const WITHDRAWAL_TX_HASH: B256 = B256::repeat_byte(0x42);

/// A Zone for precompile tests, built into a [`ZoneEnv`] by [`ZoneSpec::apply`].
pub(crate) struct ZoneSpec {
    /// L1 the Zone reads its portal state from.
    pub(crate) l1: MockL1Reader,
    /// The Zone's portal on L1.
    pub(crate) portal: Address,
    /// Account holding the portal's sequencer role.
    pub(crate) sequencer: Address,
    /// Hardfork the Zone executes at.
    pub(crate) hardfork: TempoHardfork,
    /// Tempo block the Zone starts anchored to; the portal is seeded at this block.
    pub(crate) tempo_block: u64,
    /// Portal cap on the Tempo gas rate the sequencer may set.
    pub(crate) max_tempo_gas_rate: u128,
    /// Whether plain withdrawal recipients need the portal's `Account` role.
    pub(crate) access_enforced: bool,
    /// Whether callback withdrawals must target a portal `CallbackGateway`.
    pub(crate) gateway_enforced: bool,
    /// TIP-20 tokens set up after the Zone system contracts, each enabled on the portal.
    pub(crate) tokens: Vec<TIP20Setup>,
}

impl ZoneSpec {
    /// Initializes `TempoState` at `tempo_block`, the Zone system contracts and `tokens`, and
    /// seeds the portal with the sequencer, enforcement modes, gas rate cap and enabled tokens.
    pub(crate) fn apply(self) -> tempo_precompiles::Result<ZoneEnv> {
        let genesis_rlp = alloy_rlp::encode(TempoHeader {
            inner: Header {
                number: self.tempo_block,
                ..Default::default()
            },
            ..Default::default()
        });
        let l1_state = L1State::new(self.l1.clone(), self.portal);
        let ctx = test_context_with_hardfork(self.hardfork);
        let mut env = ZoneEnv {
            precompiles: test_precompiles(&ctx, l1_state.clone()),
            ctx,
            l1: self.l1,
            l1_state,
            child_header: TempoHeader {
                inner: Header {
                    parent_hash: keccak256(&genesis_rlp),
                    number: self.tempo_block + 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let tokens = env.with_storage(|| {
            TempoState::new().initialize(&genesis_rlp)?;
            ZoneInbox::new().initialize()?;
            ZoneOutbox::new().initialize()?;
            ReceivePolicyGuard::new().initialize()?;
            self.tokens
                .into_iter()
                .map(|token| Ok(token.apply()?.address()))
                .collect::<tempo_precompiles::Result<Vec<_>>>()
        })?;
        env.write_portal(self.tempo_block, |portal| {
            portal.role[self.sequencer].write(u8::from(Role::Sequencer))?;
            portal.is_access_enforced.write(self.access_enforced)?;
            portal.is_gateway_enforced.write(self.gateway_enforced)?;
            portal.max_tempo_gas_rate.write(self.max_tempo_gas_rate)?;
            for token in tokens {
                portal.token_configs[token].enabled.write(true)?;
            }
            Ok(())
        });
        Ok(env)
    }
}

impl Default for ZoneSpec {
    fn default() -> Self {
        Self {
            l1: MockL1Reader::default(),
            portal: Address::ZERO,
            sequencer: Address::ZERO,
            hardfork: TempoHardfork::T13,
            tempo_block: 0,
            max_tempo_gas_rate: 0,
            access_enforced: false,
            gateway_enforced: false,
            tokens: Vec::new(),
        }
    }
}

/// A Zone built by [`ZoneSpec::apply`]: the Zone precompiles on a test EVM over a mocked L1.
pub(crate) struct ZoneEnv {
    /// Zone EVM and block environment the precompiles execute against.
    pub(crate) ctx: TestContext,
    /// Zone precompiles, reading L1 through `l1_state`.
    pub(crate) precompiles: TestPrecompiles,
    /// Mocked L1 holding the portal's storage and recording the Zone's reads of it.
    pub(crate) l1: MockL1Reader,
    /// L1 state the precompiles share, holding the Tempo anchor the Zone selected.
    pub(crate) l1_state: L1State<MockL1Reader>,
    /// Header `advance_tempo` submits: the child of the Tempo block the Zone starts at.
    pub(crate) child_header: TempoHeader,
}

impl ZoneEnv {
    /// Runs `f` against the Zone's state, to seed or inspect storage directly.
    pub(crate) fn with_storage<R>(&mut self, f: impl FnOnce() -> R) -> R {
        let mut storage = test_storage_provider(&mut self.ctx, u64::MAX, false);
        StorageCtx::enter(&mut storage, f)
    }

    /// Writes the portal's L1 storage at `block_number`. Panics if a write fails.
    pub(crate) fn write_portal(
        &self,
        block_number: u64,
        f: impl FnOnce(&mut ZonePortalStorage) -> tempo_precompiles::Result<()>,
    ) {
        self.l1
            .with_storage(block_number, || {
                f(&mut ZonePortalStorage::new(self.l1_state.portal()))
            })
            .expect("mock L1 storage accepts writes");
    }

    /// Calls the precompile at `target` from `caller`. State changes persist even on revert.
    pub(crate) fn call(
        &mut self,
        caller: Address,
        target: Address,
        calldata: impl AsRef<[u8]>,
    ) -> PrecompileResult {
        call_precompile(
            &mut self.ctx,
            &mut self.precompiles,
            caller,
            calldata.as_ref(),
            u64::MAX,
            false,
            target,
            target,
        )
    }

    /// Calls the precompile at `target` from `caller` in a static context.
    pub(crate) fn static_call(
        &mut self,
        caller: Address,
        target: Address,
        calldata: impl AsRef<[u8]>,
    ) -> PrecompileResult {
        call_precompile(
            &mut self.ctx,
            &mut self.precompiles,
            caller,
            calldata.as_ref(),
            u64::MAX,
            true,
            target,
            target,
        )
    }

    /// Appends `deposit` to the portal's deposit queue at `child_header`'s block and returns the
    /// entry `advance_tempo` consumes it with.
    pub(crate) fn queue_deposit<T: SolValue>(
        &self,
        deposit_type: DepositType,
        deposit: T,
    ) -> QueuedDeposit {
        let deposit_data = deposit.abi_encode().into();
        self.write_portal(self.child_header.inner.number, |portal| {
            let head = portal.current_deposit_queue_hash.read()?;
            portal
                .current_deposit_queue_hash
                .write(keccak256((deposit_type, deposit, head).abi_encode_params()))
        });
        QueuedDeposit {
            depositType: deposit_type,
            rejected: false,
            depositData: deposit_data,
        }
    }

    /// Appends `enabled` to the portal's token enablement queue at `child_header`'s block, for
    /// `advance_tempo` to consume in `enabled_tokens`.
    pub(crate) fn queue_token_enablement(&self, enabled: &EnabledToken) {
        self.write_portal(self.child_header.inner.number, |portal| {
            let hash = enabled.hash_with_previous(portal.token_enablement_hash.read()?);
            portal.token_enablement_hash.write(hash)?;
            portal.enabled_tokens.push(enabled.token)
        });
    }

    /// Advances the Zone to `child_header` as the system, rolling Zone state back unless the
    /// call succeeds.
    pub(crate) fn advance_tempo(
        &mut self,
        deposits: Vec<QueuedDeposit>,
        decryptions: Vec<DecryptionData>,
        enabled_tokens: Vec<EnabledToken>,
    ) -> PrecompileResult {
        let calldata = IZoneInbox::advanceTempoCall {
            header: alloy_rlp::encode(&self.child_header).into(),
            deposits,
            decryptions,
            enabledTokens: enabled_tokens,
        }
        .abi_encode();
        let checkpoint = self.ctx.checkpoint();
        let result = self.call(Address::ZERO, ZONE_INBOX_ADDRESS, calldata);
        if !result.as_ref().is_ok_and(PrecompileOutput::is_success) {
            self.ctx.checkpoint_revert(checkpoint);
        }
        result
    }

    /// Requests `call` from `sender` in a transaction hashed [`WITHDRAWAL_TX_HASH`] that `sender`
    /// pays for.
    pub(crate) fn request_withdrawal(
        &mut self,
        sender: Address,
        call: IZoneOutbox::requestWithdrawalCall,
    ) -> PrecompileResult {
        let _tx = tx_context::set_current_transaction(WITHDRAWAL_TX_HASH, sender);
        self.call(sender, ZONE_OUTBOX_ADDRESS, call.abi_encode())
    }

    /// Finalizes the oldest `count` pending withdrawals as the system, with empty encrypted senders.
    pub(crate) fn finalize_batch(&mut self, count: usize) -> PrecompileResult {
        self.call(
            Address::ZERO,
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::finalizeWithdrawalBatchCall {
                count: U256::from(count),
                blockNumber: 0,
                encryptedSenders: vec![Bytes::new(); count],
            }
            .abi_encode(),
        )
    }

    /// Returns `account`'s balance of `token`. Panics if `token` is not an initialized TIP-20.
    pub(crate) fn balance(&mut self, token: Address, account: Address) -> U256 {
        self.with_storage(|| {
            TIP20Token::from_address(token)?.balance_of(ITIP20::balanceOfCall { account })
        })
        .expect("initialized TIP-20 token")
    }

    /// Returns the outbox's pending withdrawals. Panics if the outbox call fails.
    pub(crate) fn pending_withdrawals(&mut self) -> Vec<IZoneOutbox::PendingWithdrawal> {
        let output = self
            .static_call(
                Address::ZERO,
                ZONE_OUTBOX_ADDRESS,
                IZoneOutbox::getPendingWithdrawalsCall {}.abi_encode(),
            )
            .expect("pending withdrawals call");
        IZoneOutbox::getPendingWithdrawalsCall::abi_decode_returns(&output.bytes)
            .expect("pending withdrawals return data")
    }
}
