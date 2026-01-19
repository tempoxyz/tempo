//! # Bridge Precompile
//!
//! Cross-chain bridge for moving stablecoins between Ethereum L1 and Tempo.
//!
//! ## Security Model: Validator-Attested Deposits
//!
//! **This bridge uses a validator-attested model, NOT trustless on-chain proofs.**
//!
//! When a user deposits tokens on Ethereum L1:
//! 1. The deposit is locked in the L1 escrow contract
//! 2. Tempo validators observe the deposit event via the bridge-exex component
//! 3. Each validator independently verifies the deposit and submits an attestation
//! 4. Once 2/3+ of active validators have attested, anyone can finalize the deposit
//! 5. Finalization mints the corresponding TIP-20 tokens to the recipient
//!
//! ### Trust Assumptions
//!
//! **Users must trust that a supermajority (>2/3) of validators are honest.**
//!
//! - If 2/3+ of validators collude, they could attest to fake deposits and mint
//!   unbacked tokens
//! - If 2/3+ of validators go offline, deposits cannot be finalized
//! - Validators are economically incentivized to behave honestly (staking/slashing TBD)
//!
//! This is similar to the security model of many PoS bridges (e.g., early versions
//! of cross-chain bridges before ZK proofs became practical).
//!
//! ### Why Not Trustless?
//!
//! A fully trustless bridge would require verifying Ethereum state proofs on Tempo,
//! which needs either:
//! - An Ethereum light client running on Tempo (complex, requires tracking sync committees)
//! - ZK proofs of Ethereum consensus (computationally expensive)
//!
//! The validator-attested model was chosen for simplicity and speed at launch.
//! A future upgrade could add trustless verification as defense-in-depth.
//!
//! ### Defense-in-Depth (Separate Implementation)
//!
//! The following safeguards should be added to limit damage from validator compromise:
//! - Per-deposit caps (e.g., max $1M per deposit)
//! - Rate limits (e.g., max $10M per hour across all deposits)
//! - Time-delayed finalization for large deposits
//! - Circuit breaker that pauses the bridge if anomalies are detected
//!
//! ## Deposit Flow
//!
//! ```text
//! L1: User deposits to Escrow → DepositRegistered event
//!                                      ↓
//! Tempo: bridge-exex observes event → calls register_deposit()
//!                                      ↓
//! Tempo: Validators call submit_deposit_vote() with their attestation
//!                                      ↓
//! Tempo: Once threshold reached → anyone calls finalize_deposit()
//!                                      ↓
//! Tempo: TIP-20 tokens minted to recipient
//! ```
//!
//! ## Burn/Unlock Flow
//!
//! ```text
//! Tempo: User calls burn_for_unlock() → tokens burned, BurnInitiated event
//!                                      ↓
//! L1: Relayer observes event → submits unlock proof to Escrow
//!                                      ↓
//! L1: Escrow verifies & releases tokens to recipient
//! ```

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

/// Half of the secp256k1 curve order (n/2).
/// Signatures with s > SECP256K1_N_DIV_2 are considered "high-s" and rejected
/// to prevent signature malleability (BIP-62).
const SECP256K1_N_DIV_2: U256 = U256::from_be_slice(&[
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
]);

/// Domain separator for burn requests
pub const BURN_DOMAIN: &[u8] = b"TEMPO_BRIDGE_BURN_V1";

/// Domain separator for deposit attestations
pub const DEPOSIT_ATTESTATION_DOMAIN: &[u8] = b"TEMPO_BRIDGE_DEPOSIT_V2";

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
    pub origin_escrow: Address,
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

    /// Whether the contract is paused
    paused: bool,

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

    fn check_not_paused(&self) -> Result<()> {
        if self.paused.read()? {
            return Err(BridgeError::contract_paused().into());
        }
        Ok(())
    }

    pub fn paused(&self) -> Result<bool> {
        self.paused.read()
    }

    pub fn pause(&mut self, sender: Address) -> Result<()> {
        self.check_owner(sender)?;
        self.paused.write(true)?;
        self.emit_event(IBridge::Paused { account: sender })
    }

    pub fn unpause(&mut self, sender: Address) -> Result<()> {
        self.check_owner(sender)?;
        self.paused.write(false)?;
        self.emit_event(IBridge::Unpaused { account: sender })
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

    /// Compute canonical deposit request ID.
    ///
    /// Formula: keccak256(origin_chain_id || escrow_address || origin_tx_hash || origin_log_index)
    ///
    /// This uses tx_hash + log_index for global uniqueness, as these are immutable
    /// properties of the deposit event on the origin chain.
    ///
    /// IMPORTANT: This formula must match `compute_canonical_deposit_id` in bridge-exex.
    pub(crate) fn compute_request_id(
        origin_chain_id: u64,
        escrow_address: Address,
        origin_tx_hash: B256,
        origin_log_index: u32,
    ) -> B256 {
        let mut buf = Vec::with_capacity(8 + 20 + 32 + 4);
        buf.extend_from_slice(&origin_chain_id.to_be_bytes());
        buf.extend_from_slice(escrow_address.as_slice());
        buf.extend_from_slice(origin_tx_hash.as_slice());
        buf.extend_from_slice(&origin_log_index.to_be_bytes());
        keccak256(&buf)
    }

    /// Register a deposit from origin chain.
    ///
    /// # Security Note
    ///
    /// This function does NOT verify that the deposit actually occurred on L1.
    /// It merely records the deposit request for validators to attest to.
    /// The actual security comes from the validator attestation threshold in
    /// `finalize_deposit` - tokens are only minted after 2/3+ validators confirm.
    ///
    /// Anyone can call this function, but without validator attestations,
    /// the deposit cannot be finalized and no tokens will be minted.
    pub fn register_deposit(
        &mut self,
        _sender: Address,
        call: IBridge::registerDepositCall,
    ) -> Result<B256> {
        self.check_not_paused()?;

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

        // Compute canonical request ID (must match bridge-exex computation)
        let request_id = Self::compute_request_id(
            call.originChainId,
            call.originEscrow,
            call.originTxHash,
            call.originLogIndex,
        );

        // Check if already exists
        let existing = self.deposits[request_id].read()?;
        if existing.status != DEPOSIT_STATUS_NONE {
            return Err(BridgeError::deposit_already_exists().into());
        }

        // Store deposit
        let deposit = DepositRequest {
            origin_chain_id: call.originChainId,
            origin_escrow: call.originEscrow,
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

    /// Submit a validator's vote for a deposit.
    ///
    /// Security model: The validator's vote is authenticated by the transaction sender address.
    /// No separate signature is required because submitting this transaction from a registered
    /// validator address already proves the validator's intent to vote for this deposit.
    pub fn submit_deposit_vote(
        &mut self,
        sender: Address,
        call: IBridge::submitDepositVoteCall,
    ) -> Result<()> {
        // Verify sender is an active validator - this IS the authentication
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

        // Check if already voted
        if self.deposit_signatures[call.requestId][sender].read()? {
            return Err(BridgeError::already_signed().into());
        }

        // Record the vote - authenticated by tx sender being a registered validator
        self.deposit_signatures[call.requestId][sender].write(true)?;

        // Increment voting power (each validator = 1 vote for now)
        deposit.voting_power_signed += 1;
        self.deposits[call.requestId].write(deposit.clone())?;

        self.emit_event(IBridge::DepositVoteSubmitted {
            requestId: call.requestId,
            validator: sender,
            votingPowerSigned: deposit.voting_power_signed,
        })
    }

    /// Finalize a deposit and mint TIP-20 tokens to the recipient.
    ///
    /// # Security Model: Validator-Attested (NOT Trustless)
    ///
    /// **This function enforces the 2/3 validator threshold but does NOT verify
    /// on-chain proofs of the L1 deposit.** Security relies on the assumption that
    /// 2/3+ of validators have independently verified the deposit occurred on L1.
    ///
    /// See module-level documentation for full trust model explanation.
    ///
    /// # Caller Permissions
    ///
    /// **Anyone can call this function once the voting threshold is reached.**
    ///
    /// This is intentional:
    /// - **Permissionless finalization**: Any relayer can finalize on behalf of users
    /// - **No value extraction**: Recipient is immutably set at registration
    /// - **Idempotent**: Reverts if already finalized
    pub fn finalize_deposit(
        &mut self,
        _sender: Address,
        call: IBridge::finalizeDepositCall,
    ) -> Result<()> {
        self.check_not_paused()?;

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
            originEscrow: deposit.origin_escrow,
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

    /// Compute the digest that validators sign for deposit attestations.
    ///
    /// Domain separation includes:
    /// - Domain tag: "TEMPO_BRIDGE_DEPOSIT_V2"
    /// - Tempo chain ID: prevents replay across different Tempo networks
    /// - Bridge address: binds attestation to specific bridge contract
    /// - Request ID: the canonical deposit identifier
    /// - All deposit fields: ensures attestation is for this exact deposit
    /// - Validator set hash: binds signatures to a specific validator set,
    ///   preventing threshold manipulation during validator set transitions
    ///
    /// IMPORTANT: This formula must match the signer implementation in bridge-exex.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_deposit_attestation_digest(
        tempo_chain_id: u64,
        request_id: B256,
        origin_chain_id: u64,
        origin_escrow: Address,
        origin_token: Address,
        origin_tx_hash: B256,
        origin_log_index: u32,
        tempo_recipient: Address,
        amount: u64,
        origin_block_number: u64,
        validator_set_hash: B256,
    ) -> B256 {
        let mut buf = Vec::with_capacity(
            DEPOSIT_ATTESTATION_DOMAIN.len() + 8 + 20 + 32 + 8 + 20 + 20 + 32 + 4 + 20 + 8 + 8 + 32,
        );
        buf.extend_from_slice(DEPOSIT_ATTESTATION_DOMAIN);
        buf.extend_from_slice(&tempo_chain_id.to_be_bytes());
        buf.extend_from_slice(BRIDGE_ADDRESS.as_slice());
        buf.extend_from_slice(request_id.as_slice());
        buf.extend_from_slice(&origin_chain_id.to_be_bytes());
        buf.extend_from_slice(origin_escrow.as_slice());
        buf.extend_from_slice(origin_token.as_slice());
        buf.extend_from_slice(origin_tx_hash.as_slice());
        buf.extend_from_slice(&origin_log_index.to_be_bytes());
        buf.extend_from_slice(tempo_recipient.as_slice());
        buf.extend_from_slice(&amount.to_be_bytes());
        buf.extend_from_slice(&origin_block_number.to_be_bytes());
        buf.extend_from_slice(validator_set_hash.as_slice());
        keccak256(&buf)
    }

    /// Register and finalize a deposit in one call with bundled validator signatures.
    ///
    /// This is the preferred method for bridge operation. Instead of each validator
    /// submitting separate vote transactions (which costs them gas), validators sign
    /// attestations off-chain and a single caller submits all signatures at once.
    ///
    /// The caller does NOT need to be a validator - they are just relaying signatures.
    /// Each signature is verified via ecrecover against active validators.
    ///
    /// # Security Model
    ///
    /// - Each signature is verified against the deposit attestation digest
    /// - Only signatures from active validators are counted
    /// - Duplicate signatures from the same validator are ignored
    /// - Finalization requires 2/3+ of active validators
    pub fn register_and_finalize_with_signatures(
        &mut self,
        _sender: Address,
        call: IBridge::registerAndFinalizeWithSignaturesCall,
    ) -> Result<B256> {
        self.check_not_paused()?;

        // Validate inputs
        if call.amount == 0 {
            return Err(BridgeError::zero_amount().into());
        }
        if call.tempoRecipient == Address::ZERO {
            return Err(BridgeError::invalid_recipient().into());
        }

        // Get token mapping
        let key = Self::token_mapping_key(call.originChainId, call.originToken);
        let mapping = self.token_mappings[key].read()?;
        if !mapping.active {
            return Err(BridgeError::token_mapping_not_found().into());
        }

        // Compute canonical request ID
        let request_id = Self::compute_request_id(
            call.originChainId,
            call.originEscrow,
            call.originTxHash,
            call.originLogIndex,
        );

        // Check if already finalized - return success to be idempotent
        let existing = self.deposits[request_id].read()?;
        if existing.status == DEPOSIT_STATUS_FINALIZED {
            return Ok(request_id);
        }

        // Get active validators and compute validator set hash
        let validator_config = ValidatorConfig::new();
        let validators = validator_config.get_validators()?;
        let active_validators: std::collections::HashSet<Address> = validators
            .iter()
            .filter(|v| v.active)
            .map(|v| v.validatorAddress)
            .collect();
        let active_count = active_validators.len() as u64;

        if active_count == 0 {
            return Err(BridgeError::threshold_not_reached().into());
        }

        let threshold = (active_count * 2).div_ceil(3).max(1);

        // Compute validator set hash for the current active set
        let validator_set_hash = validator_config.compute_validator_set_hash()?;

        // Compute attestation digest (includes validator_set_hash to bind to this validator set)
        let tempo_chain_id = self.storage.chain_id();
        let digest = Self::compute_deposit_attestation_digest(
            tempo_chain_id,
            request_id,
            call.originChainId,
            call.originEscrow,
            call.originToken,
            call.originTxHash,
            call.originLogIndex,
            call.tempoRecipient,
            call.amount,
            call.originBlockNumber,
            validator_set_hash,
        );

        // Verify signatures and count unique valid validators
        let mut signed_validators = std::collections::HashSet::new();

        for sig_bytes in &call.signatures {
            if sig_bytes.len() != 65 {
                trace!("Invalid signature length: {}", sig_bytes.len());
                continue;
            }

            // Verify signature has low-s (prevent malleability per BIP-62)
            // s value is bytes 32..64 of the 65-byte signature
            let s = U256::from_be_slice(&sig_bytes[32..64]);
            if s > SECP256K1_N_DIV_2 {
                trace!("Signature has high-s value, rejecting for malleability protection");
                continue;
            }

            // Parse signature (r: 32 bytes, s: 32 bytes, v: 1 byte)
            let sig = match alloy::primitives::Signature::try_from(sig_bytes.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    trace!("Failed to parse signature: {}", e);
                    continue;
                }
            };

            // Recover signer address
            let signer = match sig.recover_address_from_prehash(&digest) {
                Ok(addr) => addr,
                Err(e) => {
                    trace!("Failed to recover signer: {}", e);
                    continue;
                }
            };

            // Check if signer is an active validator
            if active_validators.contains(&signer) {
                signed_validators.insert(signer);
            } else {
                trace!(%signer, "Signer is not an active validator");
            }
        }

        let voting_power = signed_validators.len() as u64;
        trace!(
            %request_id,
            voting_power,
            threshold,
            "Verified {} valid validator signatures",
            signed_validators.len()
        );

        if voting_power < threshold {
            return Err(BridgeError::threshold_not_reached().into());
        }

        // Register deposit if not already registered
        if existing.status == DEPOSIT_STATUS_NONE {
            let deposit = DepositRequest {
                origin_chain_id: call.originChainId,
                origin_escrow: call.originEscrow,
                origin_token: call.originToken,
                origin_tx_hash: call.originTxHash,
                origin_log_index: call.originLogIndex,
                tempo_recipient: call.tempoRecipient,
                amount: call.amount,
                origin_block_number: call.originBlockNumber,
                tempo_tip20: mapping.tempo_tip20,
                voting_power_signed: voting_power,
                status: DEPOSIT_STATUS_FINALIZED,
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
        } else {
            // Update existing deposit to finalized
            let mut deposit = existing;
            deposit.voting_power_signed = voting_power;
            deposit.status = DEPOSIT_STATUS_FINALIZED;
            self.deposits[request_id].write(deposit)?;
        }

        // Record signatures (for auditability)
        for validator in &signed_validators {
            self.deposit_signatures[request_id][*validator].write(true)?;
        }

        // Mint TIP-20 tokens
        let mut tip20 = TIP20Token::from_address(mapping.tempo_tip20)?;
        tip20.mint(
            self.address,
            tempo_contracts::precompiles::ITIP20::mintCall {
                to: call.tempoRecipient,
                amount: U256::from(call.amount),
            },
        )?;

        self.emit_event(IBridge::DepositFinalized {
            requestId: request_id,
            tempoTip20: mapping.tempo_tip20,
            recipient: call.tempoRecipient,
            amount: call.amount,
        })?;

        Ok(request_id)
    }

    /// Compute burn ID
    ///
    /// Domain separation includes:
    /// - Domain tag: "TEMPO_BRIDGE_BURN_V1"
    /// - Tempo chain ID: prevents replay across different Tempo networks
    /// - Bridge address: binds burn ID to specific bridge contract
    pub(crate) fn compute_burn_id(
        tempo_chain_id: u64,
        origin_chain_id: u64,
        origin_token: Address,
        origin_recipient: Address,
        amount: u64,
        nonce: u64,
        sender: Address,
    ) -> B256 {
        // abi.encodePacked(BURN_DOMAIN, tempo_chain_id, BRIDGE_ADDRESS, origin_chain_id, origin_token, origin_recipient, amount, nonce, sender)
        let mut buf = Vec::with_capacity(BURN_DOMAIN.len() + 8 + 20 + 8 + 20 + 20 + 8 + 8 + 20);
        buf.extend_from_slice(BURN_DOMAIN);
        buf.extend_from_slice(&tempo_chain_id.to_be_bytes());
        buf.extend_from_slice(BRIDGE_ADDRESS.as_slice());
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
        self.check_not_paused()?;

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

        // Compute burn ID with domain separation (tempo chain ID + bridge address)
        let tempo_chain_id = self.storage.chain_id();
        let burn_id = Self::compute_burn_id(
            tempo_chain_id,
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
