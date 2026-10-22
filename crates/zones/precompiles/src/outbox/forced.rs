//! Atomic debit and withdrawal construction for authenticated inbox requests.
use super::*;
use crate::error::ZonePrecompileError;
use exithatch::ForcedExitReason;
use tempo_precompiles::{tip20::Recipient, tip403_registry::TIP403Registry};

/// Upper bound on the gas of one forced-exit debit attempt (debit, token hooks, fallback mapping,
/// and enqueue) that the weight-14 admission budget assumes.
///
/// The attempt runs only native code with no user-supplied logic, so its cost is bounded by the
/// implementation, and tests enforce this bound at production gas. It is metered on the advance's
/// gas, not a separate gas limit: an attempt that uses more is rolled back as `DebitFailed`.
pub(crate) const FORCED_EXIT_DEBIT_GAS: u64 = 5_000_000;

/// Private authenticated input; never emitted as a public L1 attribution.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ForcedWithdrawalRequest {
    /// Hash of the canonical decrypted payload including its verified root signature.
    pub private_request_hash: B256,
    pub token: Address,
    pub account: Address,
    pub recipient: Address,
    pub amount: u128,
}

impl ZoneOutbox {
    /// Check policy for an already root-authorized full balance, then debit it and enqueue a plain
    /// withdrawal atomically. No ABI selector exposes this operation. The inbox checks
    /// authorization and replay first.
    ///
    /// Returns `Ok(Err(PolicyRejected | DebitFailed))` for a terminal rejection. `Err` aborts the
    /// advance and is returned only for missing or conflicting L1 state, invariant violations,
    /// and exhaustion of the advance's own gas.
    pub(crate) fn request_forced_withdrawal<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        caller: Address,
        request: ForcedWithdrawalRequest,
    ) -> ZoneResult<Result<(), ForcedExitReason>> {
        if caller != ZONE_INBOX_ADDRESS {
            return Err(ZoneOutboxError::only_zone_inbox().into());
        }
        let ForcedWithdrawalRequest {
            token,
            account,
            recipient,
            amount,
            ..
        } = request;
        if account.is_zero() || recipient.is_zero() || amount == 0 {
            return Err(ZonePrecompileError::MalformedCalldata);
        }
        // An error raised while evaluating a policy check is that check's result. Running out of
        // gas here exhausts the advance itself, so it aborts.
        match self.check_forced_withdrawal_policy(l1, token, account, recipient) {
            Ok(true) => {}
            Err(error)
                if aborts_advance(&error) || error == TempoPrecompileError::OutOfGas.into() =>
            {
                return Err(error);
            }
            Ok(false) | Err(_) => return Ok(Err(ForcedExitReason::PolicyRejected)),
        }
        // Balance was checked by the inbox immediately before this call. Drift is fatal.
        if TIP20Token::from_address(token)?.balance_of(ITIP20::balanceOfCall { account })?
            != U256::from(amount)
        {
            return Err(TempoPrecompileError::under_overflow().into());
        }
        self.try_debit(request, FORCED_EXIT_DEBIT_GAS)
    }

    /// Returns whether every TIP-1012 policy check permits debiting `account` to `recipient`.
    fn check_forced_withdrawal_policy<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        token: Address,
        account: Address,
        recipient: Address,
    ) -> ZoneResult<bool> {
        if !l1.read_portal(|portal| &portal.token_configs[token].enabled)? {
            return Ok(false);
        }
        // Admission already checked portal pause. Only recipient policy is checked again here.
        self.validate_recipient_policy(l1, recipient, 0)?;
        // L1 admission bounds this mandatory inbox workload. Do not apply or consume the
        // ordinary user-withdrawal cap: it could prevent an admitted anchor from executing.
        // Enabled at the anchor implies initialized: the portal sets `enabled` with the
        // token-enablement hash, which `advance_tempo` matched before applying `enable_tokens`.
        let token_contract = TIP20Token::from_address(token)?;
        // Token pause policy is authenticated at the imported Tempo anchor.
        if l1.read_l1(&token_contract.paused)? {
            return Ok(false);
        }
        token_contract.check_not_paused()?;
        token_contract.ensure_transfer_authorized(account, self.address)?;
        // Reject instead of allowing a successful transfer to divert principal to a receipt.
        Ok(TIP403Registry::new()
            .validate_receive_policy(token, account, self.address)?
            .is_none())
    }

    /// Run the debit attempt under a checkpoint. A revert, or using more than `gas`, rolls the
    /// attempt back and produces `DebitFailed`. `gas` is checked against the advance's own gas
    /// after the attempt; it is not a separate gas limit.
    ///
    /// Returns `Err` only when the advance does not have `gas` left, or for an error that
    /// [`aborts_advance`].
    pub(super) fn try_debit(
        &mut self,
        request: ForcedWithdrawalRequest,
        gas: u64,
    ) -> ZoneResult<Result<(), ForcedExitReason>> {
        let start = self.storage.gas_used();
        let remaining = self
            .storage
            .gas_limit()
            .checked_sub(start)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        if remaining < gas {
            return Err(TempoPrecompileError::OutOfGas.into());
        }
        let checkpoint = self.storage.checkpoint();
        // The attempt is a bounded sequence of native operations metered on the advance's gas, so
        // it is classified after it ends. Since the advance has `gas` left, running out of gas
        // inside the attempt means it used more than `gas`.
        let result = self.debit(request);
        let used = self
            .storage
            .gas_used()
            .checked_sub(start)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        match result {
            Ok(()) if used <= gas => {
                checkpoint.commit();
                Ok(Ok(()))
            }
            Err(error) if aborts_advance(&error) => Err(error),
            Ok(()) | Err(_) => Ok(Err(ForcedExitReason::DebitFailed)),
        }
    }

    /// Transfer and burn the full balance, map a fallback nonce, and enqueue the withdrawal.
    fn debit(&mut self, request: ForcedWithdrawalRequest) -> ZoneResult<()> {
        let ForcedWithdrawalRequest {
            private_request_hash,
            token,
            account,
            recipient,
            amount,
        } = request;
        let amount256 = U256::from(amount);
        let mut token_contract = TIP20Token::from_address(token)?;
        // The destination is our fixed precompile address, not a caller-selected virtual alias.
        // Root authorization replaces allowance/transaction-key spending authorization only.
        // Native transfer and burn still run balance, supply, reward and event hooks.
        token_contract._transfer(account, &Recipient::direct(self.address), amount256)?;
        token_contract.burn(self.address, ITIP20::burnCall { amount: amount256 })?;

        let fallback_nonce = self.allocate_fallback_nonce(account)?;
        let pending = PendingWithdrawal {
            token,
            sender: account,
            tx_hash: private_request_hash,
            to: recipient,
            amount,
            fallback_nonce,
            ..Default::default()
        };
        self.enqueue(pending, PendingWithdrawal::forced_requested_event)
    }
}

/// Returns whether `error` aborts the advance instead of producing a terminal result: missing
/// or conflicting L1 or Zone witnesses (surfaced as `Fatal`), and invariant violations.
fn aborts_advance(error: &ZonePrecompileError) -> bool {
    matches!(
        error,
        ZonePrecompileError::L1State(_)
            | ZonePrecompileError::Tempo(TempoPrecompileError::Fatal(_))
    )
}
