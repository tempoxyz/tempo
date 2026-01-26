pub mod dispatch;

use tempo_contracts::precompiles::{
    ERC1271_MAGIC_VALUE, IRecoveryGuardian, RecoveryGuardianError, RecoveryGuardianEvent,
};
pub use tempo_contracts::precompiles::{
    IRecoveryGuardian::{
        RecoveryConfig, RecoveryRequest, approveRecoveryCall, cancelRecoveryCall,
        executeRecoveryCall, getConfigCall, getRecoveryRequestCall, hasApprovedCall,
        initConfigCall, initiateRecoveryCall, isValidSignatureWithKeyHashCall,
    },
    RECOVERY_GUARDIAN_ADDRESS,
};

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, FixedBytes};
use tempo_precompiles_macros::{Storable, contract};

/// Maximum number of guardians
pub const MAX_GUARDIANS: usize = 10;

/// Minimum recovery delay (1 hour)
pub const MIN_RECOVERY_DELAY: u64 = 3600;

/// Maximum recovery delay (30 days)
pub const MAX_RECOVERY_DELAY: u64 = 30 * 24 * 3600;

/// Stored recovery configuration
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct StoredRecoveryConfig {
    /// Required number of guardian approvals
    pub threshold: u8,
    /// Delay in seconds before recovery can execute
    pub recovery_delay: u64,
    /// Number of guardians
    pub guardian_count: u8,
}

/// Stored recovery request
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct StoredRecoveryRequest {
    /// Proposed new owner
    pub new_owner: Address,
    /// Timestamp when recovery can execute
    pub execute_after: u64,
    /// Number of approvals received
    pub approval_count: u8,
}

/// RecoveryGuardian precompile for social recovery
#[contract(addr = RECOVERY_GUARDIAN_ADDRESS)]
pub struct RecoveryGuardian {
    /// configs[account][keyHash] -> StoredRecoveryConfig
    configs: Mapping<Address, Mapping<B256, StoredRecoveryConfig>>,
    /// guardians[account][keyHash][index] -> guardian address
    guardians: Mapping<Address, Mapping<B256, Mapping<u8, Address>>>,
    /// requests[account][keyHash] -> StoredRecoveryRequest
    requests: Mapping<Address, Mapping<B256, StoredRecoveryRequest>>,
    /// approvals[account][keyHash][guardian] -> has approved current request
    approvals: Mapping<Address, Mapping<B256, Mapping<Address, bool>>>,
}

impl RecoveryGuardian {
    /// Initialize the recovery guardian precompile
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Initialize recovery configuration for an account
    /// Called by the account itself (via root key transaction)
    pub fn init_config(&mut self, msg_sender: Address, call: initConfigCall) -> Result<()> {
        let key_hash = call.keyHash;
        let threshold = call.threshold;
        let recovery_delay = call.recoveryDelay;
        let guardians = &call.guardians;

        // Validate threshold
        if threshold == 0 || threshold as usize > guardians.len() {
            return Err(RecoveryGuardianError::invalid_threshold().into());
        }

        // Validate guardian count
        if guardians.is_empty() || guardians.len() > MAX_GUARDIANS {
            return Err(RecoveryGuardianError::invalid_threshold().into());
        }

        // Validate delay
        if !(MIN_RECOVERY_DELAY..=MAX_RECOVERY_DELAY).contains(&recovery_delay) {
            return Err(RecoveryGuardianError::invalid_delay().into());
        }

        // Check config doesn't already exist
        let existing = self.configs[msg_sender][key_hash].read()?;
        if existing.threshold > 0 {
            return Err(RecoveryGuardianError::config_already_exists().into());
        }

        // Store config
        let config = StoredRecoveryConfig {
            threshold,
            recovery_delay,
            guardian_count: guardians.len() as u8,
        };
        self.configs[msg_sender][key_hash].write(config)?;

        // Store guardians
        for (i, guardian) in guardians.iter().enumerate() {
            self.guardians[msg_sender][key_hash][i as u8].write(*guardian)?;
        }

        // Emit event
        self.emit_event(RecoveryGuardianEvent::RecoveryConfigured(
            IRecoveryGuardian::RecoveryConfigured {
                account: msg_sender,
                keyHash: key_hash,
                threshold,
                delay: recovery_delay,
            },
        ))
    }

    /// Initiate a recovery request
    pub fn initiate_recovery(
        &mut self,
        msg_sender: Address,
        call: initiateRecoveryCall,
    ) -> Result<()> {
        let account = call.account;
        let key_hash = call.keyHash;
        let new_owner = call.newOwner;

        // Validate new owner
        if new_owner == Address::ZERO {
            return Err(RecoveryGuardianError::invalid_new_owner().into());
        }

        // Load config
        let config = self.configs[account][key_hash].read()?;
        if config.threshold == 0 {
            return Err(RecoveryGuardianError::config_not_found().into());
        }

        // Check caller is a guardian
        if !self.is_guardian(account, key_hash, msg_sender, config.guardian_count)? {
            return Err(RecoveryGuardianError::not_guardian().into());
        }

        // Check no pending recovery
        let existing = self.requests[account][key_hash].read()?;
        if existing.new_owner != Address::ZERO {
            return Err(RecoveryGuardianError::recovery_already_pending().into());
        }

        // Calculate execute_after
        let current_time = self.storage.timestamp().saturating_to::<u64>();
        let execute_after = current_time.saturating_add(config.recovery_delay);

        // Store request
        let request = StoredRecoveryRequest {
            new_owner,
            execute_after,
            approval_count: 1, // Initiator counts as first approval
        };
        self.requests[account][key_hash].write(request)?;

        // Mark initiator as approved
        self.approvals[account][key_hash][msg_sender].write(true)?;

        // Emit event
        self.emit_event(RecoveryGuardianEvent::RecoveryInitiated(
            IRecoveryGuardian::RecoveryInitiated {
                account,
                keyHash: key_hash,
                newOwner: new_owner,
                executeAfter: execute_after,
            },
        ))
    }

    /// Approve a pending recovery request
    pub fn approve_recovery(
        &mut self,
        msg_sender: Address,
        call: approveRecoveryCall,
    ) -> Result<()> {
        let account = call.account;
        let key_hash = call.keyHash;

        // Load config
        let config = self.configs[account][key_hash].read()?;
        if config.threshold == 0 {
            return Err(RecoveryGuardianError::config_not_found().into());
        }

        // Check caller is a guardian
        if !self.is_guardian(account, key_hash, msg_sender, config.guardian_count)? {
            return Err(RecoveryGuardianError::not_guardian().into());
        }

        // Check pending recovery exists
        let mut request = self.requests[account][key_hash].read()?;
        if request.new_owner == Address::ZERO {
            return Err(RecoveryGuardianError::no_recovery_pending().into());
        }

        // Check not already approved
        let already_approved = self.approvals[account][key_hash][msg_sender].read()?;
        if already_approved {
            return Err(RecoveryGuardianError::already_approved().into());
        }

        // Add approval
        request.approval_count = request.approval_count.saturating_add(1);
        self.requests[account][key_hash].write(request)?;
        self.approvals[account][key_hash][msg_sender].write(true)?;

        // Emit event
        self.emit_event(RecoveryGuardianEvent::RecoveryApproved(
            IRecoveryGuardian::RecoveryApproved {
                account,
                keyHash: key_hash,
                guardian: msg_sender,
            },
        ))
    }

    /// Cancel a pending recovery request
    /// Can only be called by the account owner
    pub fn cancel_recovery(&mut self, msg_sender: Address, call: cancelRecoveryCall) -> Result<()> {
        let key_hash = call.keyHash;

        // Check pending recovery exists
        let request = self.requests[msg_sender][key_hash].read()?;
        if request.new_owner == Address::ZERO {
            return Err(RecoveryGuardianError::no_recovery_pending().into());
        }

        // Load config to clear approvals
        let config = self.configs[msg_sender][key_hash].read()?;

        // Clear the request
        self.requests[msg_sender][key_hash].write(StoredRecoveryRequest::default())?;

        // Clear all approvals
        for i in 0..config.guardian_count {
            let guardian = self.guardians[msg_sender][key_hash][i].read()?;
            self.approvals[msg_sender][key_hash][guardian].write(false)?;
        }

        // Emit event
        self.emit_event(RecoveryGuardianEvent::RecoveryCancelled(
            IRecoveryGuardian::RecoveryCancelled {
                account: msg_sender,
                keyHash: key_hash,
            },
        ))
    }

    /// Execute a recovery after the timelock has passed
    pub fn execute_recovery(
        &mut self,
        _msg_sender: Address,
        call: executeRecoveryCall,
    ) -> Result<Address> {
        let account = call.account;
        let key_hash = call.keyHash;

        // Load config
        let config = self.configs[account][key_hash].read()?;
        if config.threshold == 0 {
            return Err(RecoveryGuardianError::config_not_found().into());
        }

        // Check pending recovery exists
        let request = self.requests[account][key_hash].read()?;
        if request.new_owner == Address::ZERO {
            return Err(RecoveryGuardianError::no_recovery_pending().into());
        }

        // Check threshold met
        if request.approval_count < config.threshold {
            return Err(RecoveryGuardianError::threshold_not_met().into());
        }

        // Check delay passed
        let current_time = self.storage.timestamp().saturating_to::<u64>();
        if current_time < request.execute_after {
            return Err(RecoveryGuardianError::recovery_delay_not_passed().into());
        }

        let new_owner = request.new_owner;

        // Clear the request
        self.requests[account][key_hash].write(StoredRecoveryRequest::default())?;

        // Clear all approvals
        for i in 0..config.guardian_count {
            let guardian = self.guardians[account][key_hash][i].read()?;
            self.approvals[account][key_hash][guardian].write(false)?;
        }

        // Emit event
        self.emit_event(RecoveryGuardianEvent::RecoveryExecuted(
            IRecoveryGuardian::RecoveryExecuted {
                account,
                keyHash: key_hash,
                newOwner: new_owner,
            },
        ))?;

        Ok(new_owner)
    }

    /// Get recovery configuration
    pub fn get_config(&self, call: getConfigCall) -> Result<RecoveryConfig> {
        let config = self.configs[call.account][call.keyHash].read()?;

        if config.threshold == 0 {
            return Ok(RecoveryConfig {
                threshold: 0,
                recoveryDelay: 0,
                guardians: vec![],
            });
        }

        // Load guardians
        let mut guardians = Vec::with_capacity(config.guardian_count as usize);
        for i in 0..config.guardian_count {
            let guardian = self.guardians[call.account][call.keyHash][i].read()?;
            guardians.push(guardian);
        }

        Ok(RecoveryConfig {
            threshold: config.threshold,
            recoveryDelay: config.recovery_delay,
            guardians,
        })
    }

    /// Get pending recovery request
    pub fn get_recovery_request(&self, call: getRecoveryRequestCall) -> Result<RecoveryRequest> {
        let request = self.requests[call.account][call.keyHash].read()?;

        Ok(RecoveryRequest {
            newOwner: request.new_owner,
            executeAfter: request.execute_after,
            approvalCount: request.approval_count,
        })
    }

    /// Check if a guardian has approved the current request
    pub fn has_approved(&self, call: hasApprovedCall) -> Result<bool> {
        self.approvals[call.account][call.keyHash][call.guardian].read()
    }

    /// Validate recovery authorization (implements ITempoSigner)
    /// This is called by AccountKeychain to validate recovery execution
    pub fn is_valid_signature_with_key_hash(
        &self,
        call: isValidSignatureWithKeyHashCall,
    ) -> Result<FixedBytes<4>> {
        let account = call.account;
        let key_hash = call.keyHash;

        // Load config
        let config = self.configs[account][key_hash].read()?;
        if config.threshold == 0 {
            return Ok(FixedBytes::ZERO);
        }

        // Check pending recovery exists and is ready
        let request = self.requests[account][key_hash].read()?;
        if request.new_owner == Address::ZERO {
            return Ok(FixedBytes::ZERO);
        }

        // Check threshold met
        if request.approval_count < config.threshold {
            return Ok(FixedBytes::ZERO);
        }

        // Check delay passed
        let current_time = self.storage.timestamp().saturating_to::<u64>();
        if current_time < request.execute_after {
            return Ok(FixedBytes::ZERO);
        }

        // Recovery is valid
        Ok(FixedBytes::from(ERC1271_MAGIC_VALUE))
    }

    /// Check if an address is a guardian for an account/keyHash
    fn is_guardian(
        &self,
        account: Address,
        key_hash: B256,
        addr: Address,
        guardian_count: u8,
    ) -> Result<bool> {
        for i in 0..guardian_count {
            let guardian = self.guardians[account][key_hash][i].read()?;
            if guardian == addr {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};

    #[test]
    fn test_init_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_hash = B256::random();
        let guardian1 = Address::random();
        let guardian2 = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut guardian = RecoveryGuardian::new();
            guardian.initialize()?;

            let call = initConfigCall {
                keyHash: key_hash,
                threshold: 2,
                recoveryDelay: 86400, // 1 day
                guardians: vec![guardian1, guardian2],
            };
            guardian.init_config(account, call)?;

            // Verify config
            let config = guardian.get_config(getConfigCall {
                account,
                keyHash: key_hash,
            })?;

            assert_eq!(config.threshold, 2);
            assert_eq!(config.recoveryDelay, 86400);
            assert_eq!(config.guardians.len(), 2);

            Ok(())
        })
    }

    #[test]
    fn test_recovery_flow() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let account = Address::random();
        let key_hash = B256::random();
        let guardian1 = Address::random();
        let guardian2 = Address::random();
        let new_owner = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut guardian = RecoveryGuardian::new();
            guardian.initialize()?;

            // Init config
            let call = initConfigCall {
                keyHash: key_hash,
                threshold: 2,
                recoveryDelay: 3600, // 1 hour (minimum)
                guardians: vec![guardian1, guardian2],
            };
            guardian.init_config(account, call)?;

            // Guardian1 initiates recovery
            guardian.initiate_recovery(
                guardian1,
                initiateRecoveryCall {
                    account,
                    keyHash: key_hash,
                    newOwner: new_owner,
                },
            )?;

            // Check request
            let request = guardian.get_recovery_request(getRecoveryRequestCall {
                account,
                keyHash: key_hash,
            })?;
            assert_eq!(request.newOwner, new_owner);
            assert_eq!(request.approvalCount, 1);

            // Guardian2 approves
            guardian.approve_recovery(
                guardian2,
                approveRecoveryCall {
                    account,
                    keyHash: key_hash,
                },
            )?;

            // Check approvals
            let request = guardian.get_recovery_request(getRecoveryRequestCall {
                account,
                keyHash: key_hash,
            })?;
            assert_eq!(request.approvalCount, 2);

            Ok(())
        })
    }
}
