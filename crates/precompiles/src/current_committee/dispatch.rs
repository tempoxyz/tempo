//! ABI dispatch for the [`CurrentCommittee`] precompile.

use crate::{
    Precompile, charge_input_cost, current_committee::CurrentCommittee, dispatch, mutate_void, view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ICurrentCommittee;
#[cfg(test)]
use tempo_contracts::precompiles::ICurrentCommittee::ICurrentCommitteeCalls;

impl Precompile for CurrentCommittee {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                ICurrentCommittee::ICurrentCommitteeCalls {
                    getCommitteeMembers(call) => view(call, |_| self.get_committee_members()),
                    setCommitteeMembers(call) => {
                        mutate_void(call, msg_sender, |s, c| self.set_committee_members(s, c))
                    }
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        storage_credits::StorageCredits,
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{primitives::B256, sol_types::SolCall};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        CURRENT_COMMITTEE_ADDRESS, CurrentCommitteeError, ICurrentCommittee,
    };

    #[test]
    fn test_current_committee_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut committee = CurrentCommittee::new();

            let unsupported = check_selector_coverage(
                &mut committee,
                ICurrentCommitteeCalls::SELECTORS,
                "ICurrentCommittee",
                ICurrentCommitteeCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }

    #[test]
    fn test_set_committee_members_is_system_only() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_block_number(2);
        StorageCtx::enter(&mut storage, || {
            let mut committee = CurrentCommittee::new();
            let call = ICurrentCommittee::setCommitteeMembersCall {
                epoch: 42,
                publicKeys: vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
            };

            let unauthorized = committee.call(&call.abi_encode(), Address::repeat_byte(0x01));
            expect_precompile_revert(&unauthorized, CurrentCommitteeError::unauthorized());

            let system = committee.call(&call.abi_encode(), Address::ZERO);
            assert!(system.is_ok_and(|output| output.is_success()));

            let ret = committee.get_committee_members()?;
            assert_eq!(ret.epoch, call.epoch);
            assert_eq!(ret.publicKeys, call.publicKeys);
            Ok(())
        })
    }

    #[test]
    fn test_get_committee_members_defaults_and_replaces() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut committee = CurrentCommittee::new();

            let empty = committee.get_committee_members()?;
            assert_eq!(empty.epoch, 0);
            assert!(empty.publicKeys.is_empty());

            committee.set_committee_members(
                Address::ZERO,
                ICurrentCommittee::setCommitteeMembersCall {
                    epoch: 1,
                    publicKeys: vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
                },
            )?;
            committee.set_committee_members(
                Address::ZERO,
                ICurrentCommittee::setCommitteeMembersCall {
                    epoch: 2,
                    publicKeys: vec![B256::repeat_byte(0x33)],
                },
            )?;

            let ret = committee.get_committee_members()?;
            assert_eq!(ret.epoch, 2);
            assert_eq!(ret.publicKeys, vec![B256::repeat_byte(0x33)]);
            Ok(())
        })
    }

    #[test]
    fn test_set_committee_members_does_not_mint_storage_credits() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        StorageCtx::enter(&mut storage, || {
            let mut committee = CurrentCommittee::new();
            committee.set_committee_members(
                Address::ZERO,
                ICurrentCommittee::setCommitteeMembersCall {
                    epoch: 1,
                    publicKeys: vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
                },
            )?;
            committee.set_committee_members(
                Address::ZERO,
                ICurrentCommittee::setCommitteeMembersCall {
                    epoch: 2,
                    publicKeys: vec![B256::repeat_byte(0x33)],
                },
            )?;

            assert_eq!(
                StorageCredits::new().balance_of(CURRENT_COMMITTEE_ADDRESS)?,
                0
            );
            Ok(())
        })
    }
}
