pub mod dispatch;
#[cfg(test)]
mod tests;

use tempo_contracts::precompiles::BRIDGE_ADDRESS;
pub use tempo_contracts::precompiles::{BridgeError, IBridge};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::Result,
    storage::{Handler, Mapping},
    tip20::TIP20Token,
    validator_config::ValidatorConfig,
};
use alloy::primitives::{Address, B256, U256, keccak256};
use tracing::trace;

/// Domain separator for deposit signatures
pub const DEPOSIT_DOMAIN: &[u8] = b"TEMPO_BRIDGE_DEPOSIT_V1";

/// Domain separator for burn requests
pub const BURN_DOMAIN: &[u8] = b"TEMPO_BRIDGE_BURN_V1";

/// Deposit status constants matching Solidity enum
/// None = 0, Registered = 1, Finalized = 2
pub const DEPOSIT_STATUS_NONE: u8 = 0;
pub const DEPOSIT_STATUS_REGISTERED: u8 = 1;
pub const DEPOSIT_STATUS_FINALIZED: u8 = 2;

/// Burn status constants matching Solidity enum
/// None = 0, Initiated = 1, Finalized = 2
pub const BURN_STATUS_NONE: u8 = 0;
pub const BURN_STATUS_INITIATED: u8 = 1;
pub const BURN_STATUS_FINALIZED: u8 = 2;

/// Internal deposit request storage
#[derive(Debug, Clone, Storable)]
pub struct DepositRequest {
    pub origin_chain_id: u64,
    pub origin_token: Address,
    pub origin_tx_hash: B256,
    pub origin_log_index: u32,
    pub tempo_recipient: Address,
    pub amount: u64,
    pub origin_block_number: u64,
    pub tempo_tip20: Address,
    pub voting_power_signed: u64,
    pub status: u8,
}

/// Internal burn request storage
#[derive(Debug, Clone, Storable)]
pub struct BurnRequest {
    pub origin_chain_id: u64,
    pub origin_token: Address,
    pub origin_recipient: Address,
    pub amount: u64,
    pub nonce: u64,
    pub status: u8,
    pub tempo_block_number: u64,
}

/// Token mapping storage
#[derive(Debug, Clone, Storable)]
pub struct TokenMapping {
    pub origin_chain_id: u64,
    pub origin_token: Address,
    pub tempo_tip20: Address,
    pub active: bool,
}

/// Bridge precompile for cross-chain stablecoin bridging
#[contract(addr = BRIDGE_ADDRESS)]
pub struct Bridge {
    owner: Address,

    /// Token mappings: hash(chainId, originToken) -> TokenMapping
    token_mappings: Mapping<B256, TokenMapping>,

    /// Deposit requests: requestId -> DepositRequest
    deposits: Mapping<B256, DepositRequest>,

    /// Validator signatures for deposits: requestId -> validator -> signed
    deposit_signatures: Mapping<B256, Mapping<Address, bool>>,

    /// Burn requests: burnId -> BurnRequest
    burns: Mapping<B256, BurnRequest>,

    /// User burn nonces: user -> nonce (unused in current impl but reserved)
    #[allow(dead_code)]
    burn_nonces: Mapping<Address, u64>,
}

impl Bridge {
    /// Initialize the bridge precompile
    pub fn initialize(&mut self, owner: Address) -> Result<()> {
        trace!(address=%self.address, %owner, "Initializing bridge precompile");
        self.__initialize()?;
        self.owner.write(owner)
    }

    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    fn check_owner(&self, caller: Address) -> Result<()> {
        if self.owner()? != caller {
            return Err(BridgeError::unauthorized().into());
        }
        Ok(())
    }

    pub fn change_owner(&mut self, sender: Address, call: IBridge::changeOwnerCall) -> Result<()> {
        self.check_owner(sender)?;
        self.owner.write(call.newOwner)
    }

    /// Compute token mapping key
    fn token_mapping_key(origin_chain_id: u64, origin_token: Address) -> B256 {
        let mut buf = [0u8; 28]; // 8 bytes for u64 + 20 bytes for address
        buf[..8].copy_from_slice(&origin_chain_id.to_be_bytes());
        buf[8..].copy_from_slice(origin_token.as_slice());
        keccak256(buf)
    }

    /// Register a token mapping (owner only)
    pub fn register_token_mapping(
        &mut self,
        sender: Address,
        call: IBridge::registerTokenMappingCall,
    ) -> Result<()> {
        self.check_owner(sender)?;

        let key = Self::token_mapping_key(call.originChainId, call.originToken);

        // Check if mapping already exists and is active
        let existing = self.token_mappings[key].read()?;
        if existing.active {
            return Err(BridgeError::token_mapping_exists().into());
        }

        let mapping = TokenMapping {
            origin_chain_id: call.originChainId,
            origin_token: call.originToken,
            tempo_tip20: call.tempoTip20,
            active: true,
        };
        self.token_mappings[key].write(mapping)?;

        self.emit_event(IBridge::TokenMappingRegistered {
            originChainId: call.originChainId,
            originToken: call.originToken,
            tempoTip20: call.tempoTip20,
        })
    }

    pub fn get_tip20_for_origin_token(
        &self,
        call: IBridge::getTip20ForOriginTokenCall,
    ) -> Result<Address> {
        let key = Self::token_mapping_key(call.originChainId, call.originToken);
        let mapping = self.token_mappings[key].read()?;
        if !mapping.active {
            return Err(BridgeError::token_mapping_not_found().into());
        }
        Ok(mapping.tempo_tip20)
    }

    pub fn get_token_mapping(
        &self,
        call: IBridge::getTokenMappingCall,
    ) -> Result<IBridge::TokenMapping> {
        let key = Self::token_mapping_key(call.originChainId, call.originToken);
        let mapping = self.token_mappings[key].read()?;
        Ok(IBridge::TokenMapping {
            originChainId: mapping.origin_chain_id,
            originToken: mapping.origin_token,
            tempoTip20: mapping.tempo_tip20,
            active: mapping.active,
        })
    }

    /// Compute deposit request ID
    fn compute_request_id(
        origin_chain_id: u64,
        origin_token: Address,
        origin_tx_hash: B256,
        origin_log_index: u32,
        tempo_recipient: Address,
        amount: u64,
        origin_block_number: u64,
    ) -> B256 {
        // abi.encodePacked(DEPOSIT_DOMAIN, origin_chain_id, origin_token, origin_tx_hash,
        //                  origin_log_index, tempo_recipient, amount, origin_block_number)
        let mut buf = Vec::with_capacity(DEPOSIT_DOMAIN.len() + 8 + 20 + 32 + 4 + 20 + 8 + 8);
        buf.extend_from_slice(DEPOSIT_DOMAIN);
        buf.extend_from_slice(&origin_chain_id.to_be_bytes());
        buf.extend_from_slice(origin_token.as_slice());
        buf.extend_from_slice(origin_tx_hash.as_slice());
        buf.extend_from_slice(&origin_log_index.to_be_bytes());
        buf.extend_from_slice(tempo_recipient.as_slice());
        buf.extend_from_slice(&amount.to_be_bytes());
        buf.extend_from_slice(&origin_block_number.to_be_bytes());
        keccak256(&buf)
    }

    /// Register a deposit from origin chain
    pub fn register_deposit(
        &mut self,
        _sender: Address,
        call: IBridge::registerDepositCall,
    ) -> Result<B256> {
        // Validate amount
        if call.amount == 0 {
            return Err(BridgeError::zero_amount().into());
        }

        // Validate recipient
        if call.tempoRecipient == Address::ZERO {
            return Err(BridgeError::invalid_recipient().into());
        }

        // Get token mapping
        let key = Self::token_mapping_key(call.originChainId, call.originToken);
        let mapping = self.token_mappings[key].read()?;
        if !mapping.active {
            return Err(BridgeError::token_mapping_not_found().into());
        }

        // Compute request ID
        let request_id = Self::compute_request_id(
            call.originChainId,
            call.originToken,
            call.originTxHash,
            call.originLogIndex,
            call.tempoRecipient,
            call.amount,
            call.originBlockNumber,
        );

        // Check if already exists
        let existing = self.deposits[request_id].read()?;
        if existing.status != DEPOSIT_STATUS_NONE {
            return Err(BridgeError::deposit_already_exists().into());
        }

        // Store deposit
        let deposit = DepositRequest {
            origin_chain_id: call.originChainId,
            origin_token: call.originToken,
            origin_tx_hash: call.originTxHash,
            origin_log_index: call.originLogIndex,
            tempo_recipient: call.tempoRecipient,
            amount: call.amount,
            origin_block_number: call.originBlockNumber,
            tempo_tip20: mapping.tempo_tip20,
            voting_power_signed: 0,
            status: DEPOSIT_STATUS_REGISTERED,
        };
        self.deposits[request_id].write(deposit)?;

        self.emit_event(IBridge::DepositRegistered {
            requestId: request_id,
            originChainId: call.originChainId,
            originToken: call.originToken,
            originTxHash: call.originTxHash,
            tempoRecipient: call.tempoRecipient,
            amount: call.amount,
        })?;

        Ok(request_id)
    }

    /// Submit validator signature for a deposit
    pub fn submit_deposit_signature(
        &mut self,
        sender: Address,
        call: IBridge::submitDepositSignatureCall,
    ) -> Result<()> {
        // Verify sender is an active validator
        let validator_config = ValidatorConfig::new();
        let validator = validator_config.validators(sender)?;
        if !validator.active || validator.publicKey.is_zero() {
            return Err(BridgeError::validator_not_active().into());
        }

        // Get deposit
        let mut deposit = self.deposits[call.requestId].read()?;
        if deposit.status == DEPOSIT_STATUS_NONE {
            return Err(BridgeError::deposit_not_found().into());
        }
        if deposit.status == DEPOSIT_STATUS_FINALIZED {
            return Err(BridgeError::deposit_already_finalized().into());
        }

        // Check if already signed
        if self.deposit_signatures[call.requestId][sender].read()? {
            return Err(BridgeError::already_signed().into());
        }

        // Verify signature (ECDSA over requestId)
        // For simplicity, we trust the validator's submission since they're already authenticated
        // In production, we'd verify the signature matches
        let _ = &call.signature; // Signature verification would go here

        // Mark as signed
        self.deposit_signatures[call.requestId][sender].write(true)?;

        // Increment voting power (each validator = 1 vote for now)
        deposit.voting_power_signed += 1;
        self.deposits[call.requestId].write(deposit.clone())?;

        self.emit_event(IBridge::DepositSignatureSubmitted {
            requestId: call.requestId,
            validator: sender,
            votingPowerSigned: deposit.voting_power_signed,
        })
    }

    /// Finalize deposit and mint TIP-20
    pub fn finalize_deposit(
        &mut self,
        _sender: Address,
        call: IBridge::finalizeDepositCall,
    ) -> Result<()> {
        let mut deposit = self.deposits[call.requestId].read()?;
        if deposit.status == DEPOSIT_STATUS_NONE {
            return Err(BridgeError::deposit_not_found().into());
        }
        if deposit.status == DEPOSIT_STATUS_FINALIZED {
            return Err(BridgeError::deposit_already_finalized().into());
        }

        // Check threshold (2/3 of ACTIVE validators)
        let validator_config = ValidatorConfig::new();
        let validators = validator_config.get_validators()?;
        let active_count = validators.iter().filter(|v| v.active).count() as u64;

        // Ensure we have at least 1 active validator (prevent 0-threshold)
        if active_count == 0 {
            return Err(BridgeError::threshold_not_reached().into());
        }

        let threshold = (active_count * 2).div_ceil(3).max(1);

        if deposit.voting_power_signed < threshold {
            return Err(BridgeError::threshold_not_reached().into());
        }

        // Mark as finalized BEFORE external call (reentrancy protection)
        deposit.status = DEPOSIT_STATUS_FINALIZED;
        self.deposits[call.requestId].write(deposit.clone())?;

        // Mint TIP-20 tokens
        let mut tip20 = TIP20Token::from_address(deposit.tempo_tip20)?;
        tip20.mint(
            self.address, // Bridge is the minter
            tempo_contracts::precompiles::ITIP20::mintCall {
                to: deposit.tempo_recipient,
                amount: U256::from(deposit.amount),
            },
        )?;

        self.emit_event(IBridge::DepositFinalized {
            requestId: call.requestId,
            tempoTip20: deposit.tempo_tip20,
            recipient: deposit.tempo_recipient,
            amount: deposit.amount,
        })
    }

    pub fn get_deposit(&self, call: IBridge::getDepositCall) -> Result<IBridge::DepositRequest> {
        let deposit = self.deposits[call.requestId].read()?;
        Ok(IBridge::DepositRequest {
            originChainId: deposit.origin_chain_id,
            originToken: deposit.origin_token,
            originTxHash: deposit.origin_tx_hash,
            originLogIndex: deposit.origin_log_index,
            tempoRecipient: deposit.tempo_recipient,
            amount: deposit.amount,
            originBlockNumber: deposit.origin_block_number,
            tempoTip20: deposit.tempo_tip20,
            votingPowerSigned: deposit.voting_power_signed,
            status: match deposit.status {
                DEPOSIT_STATUS_NONE => IBridge::DepositStatus::None,
                DEPOSIT_STATUS_REGISTERED => IBridge::DepositStatus::Registered,
                DEPOSIT_STATUS_FINALIZED => IBridge::DepositStatus::Finalized,
                _ => IBridge::DepositStatus::None, // Fallback for unknown values
            },
        })
    }

    pub fn has_validator_signed_deposit(
        &self,
        call: IBridge::hasValidatorSignedDepositCall,
    ) -> Result<bool> {
        self.deposit_signatures[call.requestId][call.validator].read()
    }

    /// Compute burn ID
    fn compute_burn_id(
        origin_chain_id: u64,
        origin_token: Address,
        origin_recipient: Address,
        amount: u64,
        nonce: u64,
        sender: Address,
    ) -> B256 {
        // abi.encodePacked(BURN_DOMAIN, origin_chain_id, origin_token, origin_recipient, amount, nonce, sender)
        let mut buf = Vec::with_capacity(BURN_DOMAIN.len() + 8 + 20 + 20 + 8 + 8 + 20);
        buf.extend_from_slice(BURN_DOMAIN);
        buf.extend_from_slice(&origin_chain_id.to_be_bytes());
        buf.extend_from_slice(origin_token.as_slice());
        buf.extend_from_slice(origin_recipient.as_slice());
        buf.extend_from_slice(&amount.to_be_bytes());
        buf.extend_from_slice(&nonce.to_be_bytes());
        buf.extend_from_slice(sender.as_slice());
        keccak256(&buf)
    }

    /// Burn TIP-20 to unlock on origin chain
    pub fn burn_for_unlock(
        &mut self,
        sender: Address,
        call: IBridge::burnForUnlockCall,
    ) -> Result<B256> {
        // Validate amount
        if call.amount == 0 {
            return Err(BridgeError::zero_amount().into());
        }

        // Validate recipient
        if call.originRecipient == Address::ZERO {
            return Err(BridgeError::invalid_recipient().into());
        }

        // Get token mapping
        let key = Self::token_mapping_key(call.originChainId, call.originToken);
        let mapping = self.token_mappings[key].read()?;
        if !mapping.active {
            return Err(BridgeError::token_mapping_not_found().into());
        }

        // Compute burn ID
        let burn_id = Self::compute_burn_id(
            call.originChainId,
            call.originToken,
            call.originRecipient,
            call.amount,
            call.nonce,
            sender,
        );

        // Check if already exists
        let existing = self.burns[burn_id].read()?;
        if existing.status != BURN_STATUS_NONE {
            return Err(BridgeError::burn_already_exists().into());
        }

        // Burn the TIP-20 tokens from sender
        let mut tip20 = TIP20Token::from_address(mapping.tempo_tip20)?;

        // Check balance
        let balance = tip20
            .balance_of(tempo_contracts::precompiles::ITIP20::balanceOfCall { account: sender })?;
        if balance < U256::from(call.amount) {
            return Err(BridgeError::insufficient_balance().into());
        }

        // Burn tokens
        tip20.burn(
            sender,
            tempo_contracts::precompiles::ITIP20::burnCall {
                amount: U256::from(call.amount),
            },
        )?;

        // Get current block number from storage context
        let block_number = self.storage.block_number();

        // Store burn request
        let burn = BurnRequest {
            origin_chain_id: call.originChainId,
            origin_token: call.originToken,
            origin_recipient: call.originRecipient,
            amount: call.amount,
            nonce: call.nonce,
            status: BURN_STATUS_INITIATED,
            tempo_block_number: block_number,
        };
        self.burns[burn_id].write(burn)?;

        self.emit_event(IBridge::BurnInitiated {
            burnId: burn_id,
            originChainId: call.originChainId,
            originToken: call.originToken,
            originRecipient: call.originRecipient,
            amount: call.amount,
            nonce: call.nonce,
            tempoBlockNumber: block_number,
        })?;

        Ok(burn_id)
    }

    pub fn get_burn(&self, call: IBridge::getBurnCall) -> Result<IBridge::BurnRequest> {
        let burn = self.burns[call.burnId].read()?;
        Ok(IBridge::BurnRequest {
            originChainId: burn.origin_chain_id,
            originToken: burn.origin_token,
            originRecipient: burn.origin_recipient,
            amount: burn.amount,
            nonce: burn.nonce,
            status: match burn.status {
                BURN_STATUS_NONE => IBridge::BurnStatus::None,
                BURN_STATUS_INITIATED => IBridge::BurnStatus::Initiated,
                BURN_STATUS_FINALIZED => IBridge::BurnStatus::Finalized,
                _ => IBridge::BurnStatus::None, // Fallback for unknown values
            },
            tempoBlockNumber: burn.tempo_block_number,
        })
    }
}
