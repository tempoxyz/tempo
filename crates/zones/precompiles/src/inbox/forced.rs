//! Shared STF execution for encrypted forced exits. No decrypted fields are logged.
use super::*;
use crate::outbox::{ForcedWithdrawalError, ForcedWithdrawalRequest};
use exithatch::ForcedExitReason as Reason;
use zone_primitives::constants::decode_l1_chain_id;

/// Internal classification only; never persisted or included in settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ForcedExitResult {
    Exited,
    Empty,
    Rejected(Reason),
}

/// Test builds record every classification so tests can assert it directly instead of
/// inferring it from side effects. Production builds discard it.
#[cfg(not(test))]
pub(super) fn observe(_result: ForcedExitResult) {}

#[cfg(test)]
std::thread_local! {
    pub(super) static OBSERVED: core::cell::RefCell<Vec<ForcedExitResult>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(super) fn observe(result: ForcedExitResult) {
    OBSERVED.with(|observed| observed.borrow_mut().push(result));
}

impl ZoneInbox {
    pub(super) fn process_forced_exit<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        outbox: &mut ZoneOutbox,
        entry: ForcedExit,
        decryption: DecryptionData,
    ) -> ZoneResult<ForcedExitResult> {
        // 1. The hash chain authenticates the entry; only reject requests from a future anchor.
        // Checkpoint-only imports can defer this entry to a later execution anchor.
        if entry.requestedAtBlock > TempoState::new().tempo_block_number()? {
            return Err(ZonePrecompileError::MalformedCalldata);
        }
        let key = read_encryption_key(l1, entry.keyIndex)?;
        chaum_pedersen::charge_gas()?;
        if !chaum_pedersen::verify(
            &entry.encrypted.ephemeralPubkeyX.0,
            entry.encrypted.ephemeralPubkeyYParity,
            &decryption.sharedSecret.0,
            decryption.sharedSecretYParity,
            &key.0.0,
            key.1,
            &decryption.cpProof,
        ) {
            return Err(ZoneInboxError::invalid_shared_secret_proof().into());
        }

        // 2. Only proven decryption may produce InvalidPayload. No host rejection flag is used.
        let info = hkdf_info(
            &l1.portal(),
            &entry.keyIndex,
            &entry.encrypted.ephemeralPubkeyX,
            &entry.feePayer,
            Some("forced-exit-v1"),
        );
        let key = hkdf_sha256(&decryption.sharedSecret.0, b"ecies-aes-key", &info);
        aes_gcm::charge_gas(entry.encrypted.ciphertext.len(), 0)?;
        let (plaintext, valid) = aes_gcm::decrypt(
            &key,
            &entry.encrypted.nonce.0,
            &entry.encrypted.ciphertext,
            &[],
            &entry.encrypted.tag.0,
        );
        let decoded = if valid {
            exithatch::decode_payload(&plaintext)
        } else {
            Err(Reason::InvalidPayload)
        };
        match decoded {
            Err(reason) => Ok(ForcedExitResult::Rejected(reason)),
            Ok((auth, signature)) => {
                // 3. Authenticate before touching the private, token-independent replay map.
                // Cover the most expensive supported primitive (P256/WebAuthn), plus input work.
                self.storage
                    .deduct_gas(8_000 + signature.len() as u64 * 16)?;
                let chain_id = self.storage.chain_id();
                let parent_chain_id = decode_l1_chain_id(chain_id)
                    .map_err(|_| ZonePrecompileError::MalformedCalldata)?;
                if let Err(reason) = exithatch::authorize(
                    &auth,
                    &signature,
                    U256::from(parent_chain_id),
                    l1.portal(),
                    U256::from(chain_id),
                    entry.token,
                    entry.requestedAtTime,
                ) {
                    Ok(ForcedExitResult::Rejected(reason))
                } else if self.forced_exit_nonces[auth.account][auth.nonce].read()? {
                    Ok(ForcedExitResult::Rejected(Reason::NonceAlreadyConsumed))
                } else {
                    self.forced_exit_nonces[auth.account][auth.nonce].write(true)?;
                    let balance = TIP20Token::from_address(entry.token)?.balance_of(
                        ITIP20::balanceOfCall {
                            account: auth.account,
                        },
                    )?;
                    // 4. Overflow and Empty precede all execution policy checks.
                    if balance > U256::from(u128::MAX) {
                        Ok(ForcedExitResult::Rejected(Reason::BalanceOverflow))
                    } else if balance.is_zero() {
                        Ok(ForcedExitResult::Empty)
                    } else {
                        match outbox.request_forced_withdrawal(
                            l1,
                            self.address,
                            ForcedWithdrawalRequest {
                                private_request_hash: exithatch::private_request_hash(
                                    &auth, &signature,
                                ),
                                token: entry.token,
                                account: auth.account,
                                recipient: auth.recipient,
                                amount: balance.to::<u128>(),
                            },
                        ) {
                            Ok(_) => Ok(ForcedExitResult::Exited),
                            Err(ForcedWithdrawalError::PolicyRejected) => {
                                Ok(ForcedExitResult::Rejected(Reason::PolicyRejected))
                            }
                            Err(ForcedWithdrawalError::Fatal(error)) => Err(error),
                        }
                    }
                }
            }
        }
    }
}
