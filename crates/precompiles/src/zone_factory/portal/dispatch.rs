//! ABI dispatch for native ZonePortal accounts (T15+).

use super::{ZonePortalConstants, ZonePortalStorage};
use crate::{Precompile, charge_input_cost, dispatch, mutate, unknown_selector_result, view};
use alloy::primitives::Address;
use evm2::{evm::precompile::PrecompileOutput, precompiles::PrecompileResult};
use tempo_contracts::zones::ZonePortal;

impl Precompile for ZonePortalStorage {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        // A portal address the factory has not created yet behaves like an empty account.
        match self.is_initialized() {
            Ok(true) => {}
            Ok(false) => return Ok(PrecompileOutput::new(Default::default())),
            Err(error) => return error.into_precompile_result(),
        }
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                ZonePortal::ZonePortalCalls {
                    FIXED_DEPOSIT_GAS(call) => view(call, |call| self.fixed_deposit_gas(call)),
                    MAX_GAS_FEE_RATE(call) => view(call, |call| self.max_gas_fee_rate(call)),
                    MAX_TOKEN_METADATA_BYTES(call) => view(call, |call| self.max_token_metadata_bytes(call)),
                    MAX_UNPROCESSED_DEPOSITS(call) => view(call, |call| self.max_unprocessed_deposits(call)),
                    MAX_UNPROCESSED_TOKEN_ENABLEMENTS(call) => view(call, |call| self.max_unprocessed_token_enablements(call)),
                    MAX_WITHDRAWAL_GAS_LIMIT(call) => view(call, |call| self.max_withdrawal_gas_limit(call)),
                    abdicate(call) => mutate(call, msg_sender, |sender, call| self.abdicate(sender, call)),
                    abdicationEffectiveAt(call) => view(call, |call| self.abdication_effective_at(call)),
                    acceptAdmin(call) => mutate(call, msg_sender, |sender, call| self.accept_admin(sender, call)),
                    admin(call) => view(call, |call| self.admin(call)),
                    areDepositsActive(call) => view(call, |call| self.are_deposits_active(call)),
                    blockHash(call) => view(call, |call| self.block_hash(call)),
                    bouncebackGas(call) => view(call, |call| self.bounceback_gas(call)),
                    calculateBouncebackFee(call) => view(call, |call| self.calculate_bounceback_fee(call)),
                    calculateDepositFee(call) => view(call, |call| self.calculate_deposit_fee(call)),
                    claimRefund(call) => mutate(call, msg_sender, |sender, call| self.claim_refund(sender, call)),
                    currentDepositQueueHash(call) => view(call, |call| self.current_deposit_queue_hash(call)),
                    deliverWithdrawal(call) => mutate(call, msg_sender, |sender, call| self.deliver_withdrawal(sender, call)),
                    deposit(call) => mutate(call, msg_sender, |sender, call| self.deposit(sender, call)),
                    depositCount(call) => view(call, |call| self.deposit_count(call)),
                    depositEncrypted(call) => mutate(call, msg_sender, |sender, call| self.deposit_encrypted(sender, call)),
                    enableToken(call) => mutate(call, msg_sender, |sender, call| self.enable_token(sender, call)),
                    enabledTokenAt(call) => view(call, |call| self.enabled_token_at(call)),
                    enabledTokenCount(call) => view(call, |call| self.enabled_token_count(call)),
                    encryptionKeyAt(call) => view(call, |call| self.encryption_key_at(call)),
                    encryptionKeyAtBlock(call) => view(call, |call| self.encryption_key_at_block(call)),
                    encryptionKeyCount(call) => view(call, |call| self.encryption_key_count(call)),
                    hasRole(call) => view(call, |call| self.has_role(call)),
                    initialize(call) => mutate(call, msg_sender, |sender, call| self.initialize(sender, call)),
                    isAccessEnforced(call) => view(call, |call| self.is_access_enforced(call)),
                    isEncryptionKeyValid(call) => view(call, |call| self.is_encryption_key_valid(call)),
                    isGatewayOpen(call) => view(call, |call| self.is_gateway_open(call)),
                    isSequencer(call) => view(call, |call| self.is_sequencer(call)),
                    isTokenEnabled(call) => view(call, |call| self.is_token_enabled(call)),
                    lastProcessedDepositNumber(call) => view(call, |call| self.last_processed_deposit_number(call)),
                    lastProcessedEnabledTokenCount(call) => view(call, |call| self.last_processed_enabled_token_count(call)),
                    lastSyncedTempoBlockNumber(call) => view(call, |call| self.last_synced_tempo_block_number(call)),
                    leader(call) => view(call, |call| self.leader(call)),
                    leaderActivationTempoBlock(call) => view(call, |call| self.leader_activation_tempo_block(call)),
                    leaderEpoch(call) => view(call, |call| self.leader_epoch(call)),
                    maxTempoGasRate(call) => view(call, |call| self.max_tempo_gas_rate(call)),
                    messenger(call) => view(call, |call| self.messenger(call)),
                    pause(call) => mutate(call, msg_sender, |sender, call| self.pause(sender, call)),
                    pauseDeposits(call) => mutate(call, msg_sender, |sender, call| self.pause_deposits(sender, call)),
                    pauseExpiry(call) => view(call, |call| self.pause_expiry(call)),
                    paused(call) => view(call, |call| self.paused(call)),
                    pendingAdmin(call) => view(call, |call| self.pending_admin(call)),
                    processWithdrawals(call) => mutate(call, msg_sender, |sender, call| self.process_withdrawals(sender, call)),
                    refunds(call) => view(call, |call| self.refunds(call)),
                    resume(call) => mutate(call, msg_sender, |sender, call| self.resume(sender, call)),
                    resumeDeposits(call) => mutate(call, msg_sender, |sender, call| self.resume_deposits(sender, call)),
                    rpcUrl(call) => view(call, |call| self.rpc_url(call)),
                    sequencerAt(call) => view(call, |call| self.sequencer_at(call)),
                    sequencerCount(call) => view(call, |call| self.sequencer_count(call)),
                    sequencerEncryptionKey(call) => view(call, |call| self.sequencer_encryption_key(call)),
                    sequencerSetVersion(call) => view(call, |call| self.sequencer_set_version(call)),
                    sequencerThreshold(call) => view(call, |call| self.sequencer_threshold(call)),
                    setAccessMode(call) => mutate(call, msg_sender, |sender, call| self.set_access_mode(sender, call)),
                    setAllowedAccount(call) => mutate(call, msg_sender, |sender, call| self.set_allowed_account(sender, call)),
                    setBouncebackGas(call) => mutate(call, msg_sender, |sender, call| self.set_bounceback_gas(sender, call)),
                    setGateway(call) => mutate(call, msg_sender, |sender, call| self.set_gateway(sender, call)),
                    setGatewayMode(call) => mutate(call, msg_sender, |sender, call| self.set_gateway_mode(sender, call)),
                    setLeader(call) => mutate(call, msg_sender, |sender, call| self.set_leader(sender, call)),
                    setMaxTempoGasRate(call) => mutate(call, msg_sender, |sender, call| self.set_max_tempo_gas_rate(sender, call)),
                    setPauseGuardian(call) => mutate(call, msg_sender, |sender, call| self.set_pause_guardian(sender, call)),
                    setRpcUrl(call) => mutate(call, msg_sender, |sender, call| self.set_rpc_url(sender, call)),
                    setSequencerEncryptionKey(call) => mutate(call, msg_sender, |sender, call| self.set_sequencer_encryption_key(sender, call)),
                    setSequencerSet(call) => mutate(call, msg_sender, |sender, call| self.set_sequencer_set(sender, call)),
                    setZoneGasRate(call) => mutate(call, msg_sender, |sender, call| self.set_zone_gas_rate(sender, call)),
                    submitBatch_1(call) => mutate(call, msg_sender, |sender, call| self.submit_batch(sender, call)),
                    tokenConfig(call) => view(call, |call| self.token_config(call)),
                    tokenEnablementCursorInitialized(call) => view(call, |call| self.token_enablement_cursor_initialized(call)),
                    tokenEnablementHash(call) => view(call, |call| self.token_enablement_hash(call)),
                    transferAdmin(call) => mutate(call, msg_sender, |sender, call| self.transfer_admin(sender, call)),
                    verifier(call) => view(call, |call| self.verifier(call)),
                    withdrawalBatchIndex(call) => view(call, |call| self.withdrawal_batch_index(call)),
                    withdrawalQueueHead(call) => view(call, |call| self.withdrawal_queue_head(call)),
                    withdrawalQueueSlot(call) => view(call, |call| self.withdrawal_queue_slot(call)),
                    withdrawalQueueTail(call) => view(call, |call| self.withdrawal_queue_tail(call)),
                    zoneGasRate(call) => view(call, |call| self.zone_gas_rate(call)),
                    zoneHeight(call) => view(call, |call| self.zone_height(call)),
                    zoneId(call) => view(call, |call| self.zone_id(call)),
                    MAX_DEPOSITS_PER_TEMPO_BLOCK(_) => unknown_selector_result(calldata),
                    MAX_TOKENS_ENABLED_PER_TEMPO_BLOCK(_) => unknown_selector_result(calldata),
                    submitBatch_0(_) => unknown_selector_result(calldata),
                }
                ZonePortalConstants::ZonePortalConstantsCalls {
                    ABDICATION_DELAY(call) => view(call, |call| self.abdication_delay(call)),
                    MAX_SEQUENCERS(call) => view(call, |call| self.max_sequencers(call)),
                    PAUSE_DURATION(call) => view(call, |call| self.pause_duration(call)),
                }
            }
        )
    }
}
