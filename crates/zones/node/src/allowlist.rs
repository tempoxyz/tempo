//! Deposit allowlist enforcement for the block builder, backed by the on-chain [`ZoneAllowlist`].
//!
//! When a Zone portal runs with access mode disabled, anyone can deposit on L1. The leader bounces
//! deposits whose L1 `sender` the allowlist does not allow by supplying zeroed decryption data,
//! which the inbox treats as a failed decryption and refunds through the ordinary deposit
//! bounce-back path. Only the block builder checks the list: followers and the prover accept the
//! decryption data the leader supplied. Before T15 the allowlist address holds no state, which
//! reads as disabled, so every deposit is credited.

use alloy_primitives::Address;
use eyre::{WrapErr as _, ensure};
use zone_l1::{FAILED_DECRYPTION, abi::DecryptionData};
use zone_precompiles::ZoneAllowlist;

/// Replace the decryption data of every deposit whose sender the zone allowlist does not allow.
///
/// Must run inside a read-only `StorageCtx` over the state the next block builds on. `senders`
/// holds the L1 sender of each user deposit in queue order; `prepare_many` emits exactly one entry
/// in `decryptions` per user deposit in the same order. Reads only the enforcement flag and the
/// senders' membership slots. Returns the number of rejected deposits.
pub(crate) fn reject_unlisted(
    senders: &[Address],
    decryptions: &mut [DecryptionData],
) -> eyre::Result<usize> {
    ensure!(
        senders.len() == decryptions.len(),
        "{} deposit senders but {} decryptions",
        senders.len(),
        decryptions.len()
    );
    let allowlist = ZoneAllowlist::new();
    if !allowlist
        .is_enabled()
        .wrap_err("read deposit allowlist enforcement")?
    {
        return Ok(0);
    }
    let mut rejected = 0;
    for (sender, decryption) in senders.iter().zip(decryptions) {
        if !allowlist
            .allows(*sender)
            .wrap_err_with(|| format!("read deposit allowlist membership of {sender}"))?
        {
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
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_evm::TempoStateAccess as _;
    use tempo_precompiles::storage::{StorageActions, StorageKey as _};
    use tempo_primitives::TempoPrimitives;
    use zone_l1::abi::ChaumPedersenProof;
    use zone_precompiles::{ZONE_ALLOWLIST_ADDRESS, allowlist::slots};

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
        let mut storage = vec![(B256::from(slots::ENABLED), U256::from(enabled))];
        storage.extend(members.iter().enumerate().map(|(index, member)| {
            (
                B256::from(member.mapping_slot(slots::MEMBER_INDEX)),
                U256::from(index + 1),
            )
        }));
        provider.add_account(
            ZONE_ALLOWLIST_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
        );
        provider
    }

    fn reject(
        mut state: MockEthProvider<TempoPrimitives>,
        senders: &[Address],
        decryptions: &mut [DecryptionData],
    ) -> eyre::Result<usize> {
        state.with_read_only_storage_ctx(TempoHardfork::T15, StorageActions::disabled(), || {
            reject_unlisted(senders, decryptions)
        })
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
        let rejected = reject(state(false, &[ALICE]), &[BOB], &mut decryptions).unwrap();

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
    fn requires_one_decryption_per_sender() {
        let err = reject(state(true, &[]), &[ALICE], &mut []).unwrap_err();
        assert_eq!(err.to_string(), "1 deposit senders but 0 decryptions");
    }
}
