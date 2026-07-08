//! Current committee precompile for TIP-1070.

pub mod dispatch;

use tempo_contracts::precompiles::CurrentCommitteeError;
pub use tempo_contracts::precompiles::{CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee};
use tempo_precompiles_macros::contract;

use crate::{
    error::Result,
    storage::{ContractStorage, Handler},
};
use alloy::primitives::{Address, B256};

#[contract(addr = CURRENT_COMMITTEE_ADDRESS)]
pub struct CurrentCommittee {
    ids: Vec<B256>,
}

impl CurrentCommittee {
    pub fn get_committee_members(&self) -> Result<ICurrentCommittee::getCommitteeMembersReturn> {
        let current_epoch = self.storage().epoch(self.storage().block_number());
        Ok(ICurrentCommittee::getCommitteeMembersReturn {
            epoch: current_epoch,
            publicKeys: self.ids.read()?,
        })
    }

    pub fn set_committee_members(
        &mut self,
        msg_sender: Address,
        call: ICurrentCommittee::setCommitteeMembersCall,
    ) -> Result<()> {
        if msg_sender != Address::ZERO {
            return Err(CurrentCommitteeError::unauthorized().into());
        }

        self.ids.write(call.publicKeys)?;
        Ok(())
    }
}
