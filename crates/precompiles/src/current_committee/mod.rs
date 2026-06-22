//! Current committee precompile for TIP-1070.

pub mod dispatch;

use tempo_contracts::precompiles::CurrentCommitteeError;
pub use tempo_contracts::precompiles::{CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee};
use tempo_precompiles_macros::contract;

use crate::{error::Result, storage::Handler};
use alloy::primitives::{Address, B256};
use tempo_chainspec::spec::chainspec_from_chain_id;

#[contract(addr = CURRENT_COMMITTEE_ADDRESS)]
pub struct CurrentCommittee {
    public_keys: Vec<B256>,
}

impl CurrentCommittee {
    pub fn get_committee_members(&self) -> Result<ICurrentCommittee::getCommitteeMembersReturn> {
        Ok(ICurrentCommittee::getCommitteeMembersReturn {
            epoch: self.current_epoch(),
            publicKeys: self.public_keys.read()?,
        })
    }

    fn current_epoch(&self) -> u64 {
        let block_number = self.storage.block_number();
        chainspec_from_chain_id(self.storage.chain_id())
            .and_then(|chain_spec| chain_spec.info.epoch_length())
            .map_or(0, |epoch_length| block_number / epoch_length)
    }

    pub fn set_committee_members(
        &mut self,
        msg_sender: Address,
        call: ICurrentCommittee::setCommitteeMembersCall,
    ) -> Result<()> {
        if msg_sender != Address::ZERO {
            return Err(CurrentCommitteeError::unauthorized().into());
        }

        self.public_keys.write(call.publicKeys)?;
        Ok(())
    }
}
