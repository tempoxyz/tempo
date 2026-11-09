//! Deposit allowlist enforcement for the block builder, backed by the on-chain `ZoneAllowlist`.
//!
//! When a Zone portal runs with access mode disabled, anyone can deposit on L1. The leader bounces
//! deposits whose L1 `sender` or zone recipient the allowlist does not allow by supplying zeroed
//! decryption data, which the inbox treats as a failed decryption and refunds through the ordinary
//! deposit bounce-back path. Only the block builder checks the list: followers and the prover
//! accept the decryption data the leader supplied. Before T15 the allowlist address holds no
//! state, which reads as disabled, so every deposit is credited.

use alloy_primitives::Address;
use eyre::{WrapErr as _, ensure};
use zone_l1::{FAILED_DECRYPTION, abi::DecryptionData};
use zone_payload::Allowlist;

/// Replace the decryption data of every deposit whose L1 sender or zone recipient `allowlist`
/// does not allow.
///
/// `senders` holds the L1 sender of each user deposit in queue order; `prepare_many` emits exactly
/// one entry in `recipients` and `decryptions` per user deposit in the same order. A deposit the
/// leader could not decrypt has no recipient and is left alone, since its decryption data already
/// bounces it. Returns the number of rejected deposits.
pub(crate) fn reject_unlisted(
    allowlist: &Allowlist<'_>,
    senders: &[Address],
    recipients: &[Option<Address>],
    decryptions: &mut [DecryptionData],
) -> eyre::Result<usize> {
    ensure!(
        senders.len() == decryptions.len() && recipients.len() == decryptions.len(),
        "{} deposit senders and {} recipients but {} decryptions",
        senders.len(),
        recipients.len(),
        decryptions.len()
    );
    let mut rejected = 0;
    for ((sender, recipient), decryption) in senders.iter().zip(recipients).zip(decryptions) {
        let Some(recipient) = recipient else {
            continue;
        };
        let allowed = allowlist
            .allows(*sender)
            .wrap_err_with(|| format!("read deposit allowlist membership of {sender}"))?
            && (recipient == sender
                || allowlist.allows(*recipient).wrap_err_with(|| {
                    format!("read deposit allowlist membership of {recipient}")
                })?);
        if !allowed {
            *decryption = FAILED_DECRYPTION;
            rejected += 1;
        }
    }
    Ok(rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256, address};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::StateProviderFactory as _;
    use tempo_primitives::TempoPrimitives;
    use zone_l1::abi::ChaumPedersenProof;
    use zone_precompiles::{ZONE_ALLOWLIST_ADDRESS, allowlist::storage_entries};

    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");

    fn valid_decryption() -> DecryptionData {
        DecryptionData {
            sharedSecret: B256::repeat_byte(1),
            sharedSecretYParity: 0x03,
            cpProof: ChaumPedersenProof {
                s: B256::repeat_byte(2),
                c: B256::repeat_byte(3),
            },
        }
    }

    /// Zone state whose allowlist has enforcement `enabled` and lists `members`.
    fn state(enabled: bool, members: &[Address]) -> MockEthProvider<TempoPrimitives> {
        let provider = MockEthProvider::<TempoPrimitives>::new();
        provider.add_account(
            ZONE_ALLOWLIST_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(
                storage_entries(enabled, members)
                    .into_iter()
                    .map(|(slot, value)| (B256::from(slot), value)),
            ),
        );
        provider
    }

    /// Rejects deposits from `senders` to themselves against `state`.
    fn reject(
        state: MockEthProvider<TempoPrimitives>,
        senders: &[Address],
        decryptions: &mut [DecryptionData],
    ) -> eyre::Result<usize> {
        let recipients = senders
            .iter()
            .map(|sender| Some(*sender))
            .collect::<Vec<_>>();
        reject_to(state, senders, &recipients, decryptions)
    }

    fn reject_to(
        state: MockEthProvider<TempoPrimitives>,
        senders: &[Address],
        recipients: &[Option<Address>],
        decryptions: &mut [DecryptionData],
    ) -> eyre::Result<usize> {
        let state = state.latest()?;
        let allowlist = Allowlist::read(state.as_ref())?;
        reject_unlisted(&allowlist, senders, recipients, decryptions)
    }

    #[test]
    fn enabled_allowlist_zeroes_only_unlisted_senders() {
        let valid = valid_decryption();
        let mut decryptions = vec![valid.clone(), valid.clone(), valid.clone()];

        let rejected = reject(
            state(true, &[ALICE]),
            &[ALICE, BOB, ALICE],
            &mut decryptions,
        )
        .unwrap();

        assert_eq!(rejected, 1);
        assert_eq!(decryptions, [valid.clone(), FAILED_DECRYPTION, valid]);
    }

    #[test]
    fn enabled_allowlist_zeroes_deposits_to_unlisted_recipients() {
        let valid = valid_decryption();
        let mut decryptions = vec![valid.clone(), valid.clone(), valid.clone()];

        // Alice to Bob is rejected; Alice to herself and a deposit that already failed to decrypt
        // are left alone.
        let rejected = reject_to(
            state(true, &[ALICE]),
            &[ALICE, ALICE, ALICE],
            &[Some(BOB), Some(ALICE), None],
            &mut decryptions,
        )
        .unwrap();

        assert_eq!(rejected, 1);
        assert_eq!(decryptions, [FAILED_DECRYPTION, valid.clone(), valid]);
    }

    #[test]
    fn enabled_empty_allowlist_rejects_every_sender() {
        let mut decryptions = vec![valid_decryption(), valid_decryption()];

        let rejected = reject(state(true, &[]), &[ALICE, BOB], &mut decryptions).unwrap();

        assert_eq!(rejected, 2);
        assert_eq!(decryptions, [FAILED_DECRYPTION, FAILED_DECRYPTION]);
    }

    #[test]
    fn disabled_allowlist_credits_every_sender() {
        let valid = valid_decryption();
        let mut decryptions = vec![valid.clone()];

        // Membership is kept while disabled but not enforced.
        let rejected = reject_to(
            state(false, &[ALICE]),
            &[BOB],
            &[Some(ALICE)],
            &mut decryptions,
        )
        .unwrap();

        assert_eq!(rejected, 0);
        assert_eq!(decryptions, [valid]);
    }

    #[test]
    fn empty_state_reads_as_disabled() {
        let valid = valid_decryption();
        let mut decryptions = vec![valid.clone()];

        let rejected = reject(MockEthProvider::new(), &[BOB], &mut decryptions).unwrap();

        assert_eq!(rejected, 0);
        assert_eq!(decryptions, [valid]);
    }

    #[test]
    fn requires_one_recipient_and_decryption_per_sender() {
        let err = reject(state(true, &[]), &[ALICE], &mut []).unwrap_err();
        assert_eq!(
            err.to_string(),
            "1 deposit senders and 1 recipients but 0 decryptions"
        );
        let err =
            reject_to(state(true, &[]), &[ALICE], &[], &mut [valid_decryption()]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "1 deposit senders and 0 recipients but 1 decryptions"
        );
    }
}
