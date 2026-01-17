//! Unit tests for the Bridge precompile

use super::*;
use crate::{
    error::TempoPrecompileError,
    storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
    test_util::TIP20Setup,
    tip20::ISSUER_ROLE,
    validator_config::{IValidatorConfig, ValidatorConfig},
};
use alloy::primitives::{Address, B256, FixedBytes, U256};

/// Helper to setup a bridge with owner
fn setup_bridge(owner: Address) -> Result<Bridge> {
    let mut bridge = Bridge::new();
    bridge.initialize(owner)?;
    Ok(bridge)
}

/// Helper to register a token mapping
fn register_mapping(
    bridge: &mut Bridge,
    owner: Address,
    origin_chain_id: u64,
    origin_token: Address,
    tempo_tip20: Address,
) -> Result<()> {
    bridge.register_token_mapping(
        owner,
        IBridge::registerTokenMappingCall {
            originChainId: origin_chain_id,
            originToken: origin_token,
            tempoTip20: tempo_tip20,
        },
    )
}

/// Helper to add a validator
fn add_validator(
    validator_config: &mut ValidatorConfig,
    owner: Address,
    validator: Address,
    active: bool,
) -> Result<()> {
    let public_key = FixedBytes::<32>::from([0x44; 32]);
    validator_config.add_validator(
        owner,
        IValidatorConfig::addValidatorCall {
            newValidatorAddress: validator,
            publicKey: public_key,
            inboundAddress: "192.168.1.1:8000".to_string(),
            active,
            outboundAddress: "192.168.1.1:9000".to_string(),
        },
    )
}

#[test]
fn test_register_token_mapping() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();
    let non_owner = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let tempo_tip20 = Address::random();

    StorageCtx::enter(&mut storage, || {
        let mut bridge = setup_bridge(owner)?;

        // Owner can register token mapping
        register_mapping(
            &mut bridge,
            owner,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Verify mapping was registered
        let mapping = bridge.get_token_mapping(IBridge::getTokenMappingCall {
            originChainId: origin_chain_id,
            originToken: origin_token,
        })?;
        assert_eq!(mapping.tempoTip20, tempo_tip20);
        assert!(mapping.active);

        // Non-owner cannot register token mapping
        let result = register_mapping(
            &mut bridge,
            non_owner,
            2,
            Address::random(),
            Address::random(),
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::unauthorized()
            ))
        );

        // Cannot register duplicate mapping
        let result = register_mapping(
            &mut bridge,
            owner,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::token_mapping_exists()
            ))
        );

        Ok(())
    })
}

#[test]
fn test_register_deposit() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();
    let sender = Address::random();
    let recipient = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let tempo_tip20 = Address::random();
    let origin_tx_hash = B256::random();
    let amount = 1000000u64;

    StorageCtx::enter(&mut storage, || {
        let mut bridge = setup_bridge(owner)?;
        register_mapping(
            &mut bridge,
            owner,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Register deposit
        let request_id = bridge.register_deposit(
            sender,
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
                originTxHash: origin_tx_hash,
                originLogIndex: 0,
                tempoRecipient: recipient,
                amount,
                originBlockNumber: 12345,
            },
        )?;

        // Verify request ID is non-zero
        assert!(!request_id.is_zero());

        // Verify deposit was stored correctly
        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.originChainId, origin_chain_id);
        assert_eq!(deposit.originToken, origin_token);
        assert_eq!(deposit.originTxHash, origin_tx_hash);
        assert_eq!(deposit.tempoRecipient, recipient);
        assert_eq!(deposit.amount, amount);
        assert_eq!(deposit.tempoTip20, tempo_tip20);
        assert_eq!(deposit.status, IBridge::DepositStatus::Registered);
        assert_eq!(deposit.votingPowerSigned, 0);

        // Verify event was emitted
        let events = bridge.emitted_events();
        assert!(!events.is_empty());

        Ok(())
    })
}

#[test]
fn test_submit_deposit_vote() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();
    let validator1 = Address::random();
    let validator2 = Address::random();
    let non_validator = Address::random();
    let recipient = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let tempo_tip20 = Address::random();

    StorageCtx::enter(&mut storage, || {
        // Setup validator config
        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(owner)?;
        add_validator(&mut validator_config, owner, validator1, true)?;
        add_validator(&mut validator_config, owner, validator2, true)?;

        // Setup bridge
        let mut bridge = setup_bridge(owner)?;
        register_mapping(
            &mut bridge,
            owner,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Register deposit
        let request_id = bridge.register_deposit(
            Address::random(),
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
                originTxHash: B256::random(),
                originLogIndex: 0,
                tempoRecipient: recipient,
                amount: 1000000,
                originBlockNumber: 12345,
            },
        )?;

        // Only active validators can sign
        let result = bridge.submit_deposit_vote(
            non_validator,
            IBridge::submitDepositVoteCall {
                requestId: request_id,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::validator_not_active()
            ))
        );

        // Validator1 signs
        bridge.submit_deposit_vote(
            validator1,
            IBridge::submitDepositVoteCall {
                requestId: request_id,
            },
        )?;

        // Verify voting power increased
        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.votingPowerSigned, 1);

        // Verify validator has signed
        assert!(
            bridge.has_validator_signed_deposit(IBridge::hasValidatorSignedDepositCall {
                requestId: request_id,
                validator: validator1,
            })?
        );

        // Duplicates rejected
        let result = bridge.submit_deposit_vote(
            validator1,
            IBridge::submitDepositVoteCall {
                requestId: request_id,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::already_signed()
            ))
        );

        // Second validator can still sign
        bridge.submit_deposit_vote(
            validator2,
            IBridge::submitDepositVoteCall {
                requestId: request_id,
            },
        )?;

        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.votingPowerSigned, 2);

        Ok(())
    })
}

#[test]
fn test_finalize_deposit() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let validator1 = Address::random();
    let validator2 = Address::random();
    let validator3 = Address::random();
    let recipient = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let amount = 1000000u64;

    StorageCtx::enter(&mut storage, || {
        // Create TIP-20 token with minting capability (bridge as issuer)
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_role(tempo_contracts::precompiles::BRIDGE_ADDRESS, *ISSUER_ROLE)
            .apply()?;
        let tempo_tip20 = token.address();

        // Setup validator config with 3 validators
        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(admin)?;
        add_validator(&mut validator_config, admin, validator1, true)?;
        add_validator(&mut validator_config, admin, validator2, true)?;
        add_validator(&mut validator_config, admin, validator3, true)?;

        // Setup bridge
        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Register deposit
        let request_id = bridge.register_deposit(
            Address::random(),
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
                originTxHash: B256::random(),
                originLogIndex: 0,
                tempoRecipient: recipient,
                amount,
                originBlockNumber: 12345,
            },
        )?;

        // Only 1 vote - threshold not reached (need 2/3)
        bridge.submit_deposit_vote(
            validator1,
            IBridge::submitDepositVoteCall {
                requestId: request_id,
            },
        )?;

        let result = bridge.finalize_deposit(
            Address::random(),
            IBridge::finalizeDepositCall {
                requestId: request_id,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::threshold_not_reached()
            ))
        );

        // Get second signature to reach 2/3 threshold
        bridge.submit_deposit_vote(
            validator2,
            IBridge::submitDepositVoteCall {
                requestId: request_id,
            },
        )?;

        // Now finalize should succeed
        bridge.finalize_deposit(
            Address::random(),
            IBridge::finalizeDepositCall {
                requestId: request_id,
            },
        )?;

        // Verify deposit is finalized
        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.status, IBridge::DepositStatus::Finalized);

        // Verify TIP-20 tokens were minted to recipient
        let token = TIP20Token::from_address(tempo_tip20)?;
        let balance = token.balance_of(tempo_contracts::precompiles::ITIP20::balanceOfCall {
            account: recipient,
        })?;
        assert_eq!(balance, U256::from(amount));

        // Cannot finalize twice
        let result = bridge.finalize_deposit(
            Address::random(),
            IBridge::finalizeDepositCall {
                requestId: request_id,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::deposit_already_finalized()
            ))
        );

        Ok(())
    })
}

#[test]
fn test_burn_for_unlock() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let user = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let origin_recipient = Address::random();
    let amount = 1000000u64;

    StorageCtx::enter(&mut storage, || {
        // Create TIP-20 token and mint to user
        // The user needs ISSUER_ROLE to burn their own tokens
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_issuer(admin)
            .with_role(user, *ISSUER_ROLE)
            .with_mint(user, U256::from(amount))
            .apply()?;
        let tempo_tip20 = token.address();

        // Setup bridge
        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Burn for unlock
        let burn_id = bridge.burn_for_unlock(
            user,
            IBridge::burnForUnlockCall {
                originChainId: origin_chain_id,
                originToken: origin_token,
                originRecipient: origin_recipient,
                amount,
                nonce: 0,
            },
        )?;

        // Verify burn ID is non-zero
        assert!(!burn_id.is_zero());

        // Verify burn was stored
        let burn = bridge.get_burn(IBridge::getBurnCall { burnId: burn_id })?;
        assert_eq!(burn.originChainId, origin_chain_id);
        assert_eq!(burn.originToken, origin_token);
        assert_eq!(burn.originRecipient, origin_recipient);
        assert_eq!(burn.amount, amount);
        assert_eq!(burn.nonce, 0);
        assert_eq!(burn.status, IBridge::BurnStatus::Initiated);

        // Verify tokens were burned
        let token = TIP20Token::from_address(tempo_tip20)?;
        let balance = token
            .balance_of(tempo_contracts::precompiles::ITIP20::balanceOfCall { account: user })?;
        assert_eq!(balance, U256::ZERO);

        // Verify BurnInitiated event was emitted
        let events = bridge.emitted_events();
        assert!(!events.is_empty());

        Ok(())
    })
}

#[test]
fn test_replay_prevention() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();
    let sender = Address::random();
    let recipient = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let tempo_tip20 = Address::random();
    let origin_tx_hash = B256::random();
    let amount = 1000000u64;

    StorageCtx::enter(&mut storage, || {
        let mut bridge = setup_bridge(owner)?;
        register_mapping(
            &mut bridge,
            owner,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        let deposit_call = IBridge::registerDepositCall {
            originChainId: origin_chain_id,
            originEscrow: Address::repeat_byte(0xEE),
            originToken: origin_token,
            originTxHash: origin_tx_hash,
            originLogIndex: 0,
            tempoRecipient: recipient,
            amount,
            originBlockNumber: 12345,
        };

        // First registration succeeds
        let request_id = bridge.register_deposit(sender, deposit_call.clone())?;
        assert!(!request_id.is_zero());

        // Same deposit cannot be registered twice (replay prevention)
        let result = bridge.register_deposit(sender, deposit_call);
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::deposit_already_exists()
            ))
        );

        // Different log index is a different deposit
        let different_deposit = IBridge::registerDepositCall {
            originChainId: origin_chain_id,
            originEscrow: Address::repeat_byte(0xEE),
            originToken: origin_token,
            originTxHash: origin_tx_hash,
            originLogIndex: 1, // Different log index
            tempoRecipient: recipient,
            amount,
            originBlockNumber: 12345,
        };
        let request_id2 = bridge.register_deposit(sender, different_deposit)?;
        assert!(!request_id2.is_zero());
        assert_ne!(request_id, request_id2);

        Ok(())
    })
}

#[test]
fn test_register_deposit_validation() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();
    let sender = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let tempo_tip20 = Address::random();

    StorageCtx::enter(&mut storage, || {
        let mut bridge = setup_bridge(owner)?;
        register_mapping(
            &mut bridge,
            owner,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Zero amount rejected
        let result = bridge.register_deposit(
            sender,
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
                originTxHash: B256::random(),
                originLogIndex: 0,
                tempoRecipient: Address::random(),
                amount: 0,
                originBlockNumber: 12345,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(BridgeError::zero_amount()))
        );

        // Zero recipient rejected
        let result = bridge.register_deposit(
            sender,
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
                originTxHash: B256::random(),
                originLogIndex: 0,
                tempoRecipient: Address::ZERO,
                amount: 1000000,
                originBlockNumber: 12345,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::invalid_recipient()
            ))
        );

        // Unknown token mapping rejected
        let result = bridge.register_deposit(
            sender,
            IBridge::registerDepositCall {
                originChainId: 999, // Unknown chain
                originEscrow: Address::repeat_byte(0xEE),
                originToken: Address::random(),
                originTxHash: B256::random(),
                originLogIndex: 0,
                tempoRecipient: Address::random(),
                amount: 1000000,
                originBlockNumber: 12345,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::token_mapping_not_found()
            ))
        );

        Ok(())
    })
}

#[test]
fn test_burn_for_unlock_validation() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let user = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let amount = 1000000u64;

    StorageCtx::enter(&mut storage, || {
        // Create TIP-20 token and mint to user
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_issuer(admin)
            .with_mint(user, U256::from(amount))
            .apply()?;
        let tempo_tip20 = token.address();

        // Setup bridge
        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Zero amount rejected
        let result = bridge.burn_for_unlock(
            user,
            IBridge::burnForUnlockCall {
                originChainId: origin_chain_id,
                originToken: origin_token,
                originRecipient: Address::random(),
                amount: 0,
                nonce: 0,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(BridgeError::zero_amount()))
        );

        // Zero recipient rejected
        let result = bridge.burn_for_unlock(
            user,
            IBridge::burnForUnlockCall {
                originChainId: origin_chain_id,
                originToken: origin_token,
                originRecipient: Address::ZERO,
                amount,
                nonce: 0,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::invalid_recipient()
            ))
        );

        // Insufficient balance rejected
        let result = bridge.burn_for_unlock(
            user,
            IBridge::burnForUnlockCall {
                originChainId: origin_chain_id,
                originToken: origin_token,
                originRecipient: Address::random(),
                amount: amount + 1, // More than balance
                nonce: 0,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::insufficient_balance()
            ))
        );

        // Unknown token mapping rejected
        let result = bridge.burn_for_unlock(
            user,
            IBridge::burnForUnlockCall {
                originChainId: 999, // Unknown chain
                originToken: Address::random(),
                originRecipient: Address::random(),
                amount,
                nonce: 0,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::token_mapping_not_found()
            ))
        );

        Ok(())
    })
}

#[test]
fn test_burn_replay_prevention() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let user = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let origin_recipient = Address::random();
    let amount = 500000u64;

    StorageCtx::enter(&mut storage, || {
        // Create TIP-20 token and mint enough for two burns
        // The user needs ISSUER_ROLE to burn their own tokens
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_issuer(admin)
            .with_role(user, *ISSUER_ROLE)
            .with_mint(user, U256::from(amount * 2))
            .apply()?;
        let tempo_tip20 = token.address();

        // Setup bridge
        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        let burn_call = IBridge::burnForUnlockCall {
            originChainId: origin_chain_id,
            originToken: origin_token,
            originRecipient: origin_recipient,
            amount,
            nonce: 0,
        };

        // First burn succeeds
        let burn_id = bridge.burn_for_unlock(user, burn_call.clone())?;
        assert!(!burn_id.is_zero());

        // Same burn parameters cannot be used twice (replay prevention)
        let result = bridge.burn_for_unlock(user, burn_call);
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::burn_already_exists()
            ))
        );

        // Different nonce is allowed
        let different_burn = IBridge::burnForUnlockCall {
            originChainId: origin_chain_id,
            originToken: origin_token,
            originRecipient: origin_recipient,
            amount,
            nonce: 1, // Different nonce
        };
        let burn_id2 = bridge.burn_for_unlock(user, different_burn)?;
        assert!(!burn_id2.is_zero());
        assert_ne!(burn_id, burn_id2);

        Ok(())
    })
}
