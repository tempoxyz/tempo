//! Current committee precompile for TIP-1070.

pub mod dispatch;

use tempo_contracts::precompiles::CurrentCommitteeError;
pub use tempo_contracts::precompiles::{CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee};
use tempo_precompiles_macros::contract;

use crate::{error::Result, storage::Handler};
use alloy::primitives::{Address, B256};

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
        self.storage.epoch(block_number)
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
