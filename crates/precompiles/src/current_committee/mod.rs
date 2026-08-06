//! Current committee precompile for TIP-1070.

pub mod dispatch;

use tempo_contracts::precompiles::CurrentCommitteeError;
pub use tempo_contracts::precompiles::{CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee};
use tempo_precompiles_macros::contract;

use crate::{error::Result, storage::Handler};
use alloy::primitives::{Address, B256};

#[contract(addr = CURRENT_COMMITTEE_ADDRESS)]
pub struct CurrentCommittee {
    epoch: u64,
    ids: Vec<B256>,
}

impl CurrentCommittee {
    pub fn get_committee_members(&self) -> Result<ICurrentCommittee::getCommitteeMembersReturn> {
        Ok(ICurrentCommittee::getCommitteeMembersReturn {
            epoch: self.epoch.read()?,
            publicKeys: self.ids.read()?,
        })
    }

    /// Stores the next epoch's committee.
    ///
    /// Correctness assumes this system-only entrypoint is invoked only while
    /// processing the last block of an epoch.
    pub fn set_committee_members(
        &mut self,
        msg_sender: Address,
        call: ICurrentCommittee::setCommitteeMembersCall,
    ) -> Result<()> {
        if msg_sender != Address::ZERO {
            return Err(CurrentCommitteeError::unauthorized().into());
        }

        // System writes are free and must not mint or consume TIP-1060 storage credits.
        self.storage.set_tip1060_storage_credits(false);
        self.epoch.write(call.epoch)?;
        self.ids.write(call.publicKeys)?;
        Ok(())
    }
}
