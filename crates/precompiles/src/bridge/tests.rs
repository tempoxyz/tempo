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

#[test]
fn test_pause_unpause() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();
    let non_owner = Address::random();

    StorageCtx::enter(&mut storage, || {
        let mut bridge = setup_bridge(owner)?;

        // Initially not paused
        assert!(!bridge.paused()?);

        // Non-owner cannot pause
        let result = bridge.pause(non_owner);
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::unauthorized()
            ))
        );

        // Owner can pause
        bridge.pause(owner)?;
        assert!(bridge.paused()?);

        // Verify Paused event was emitted
        let events = bridge.emitted_events();
        assert!(!events.is_empty());

        // Non-owner cannot unpause
        let result = bridge.unpause(non_owner);
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::unauthorized()
            ))
        );

        // Owner can unpause
        bridge.unpause(owner)?;
        assert!(!bridge.paused()?);

        Ok(())
    })
}

#[test]
fn test_pause_blocks_register_deposit() -> eyre::Result<()> {
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

        // Pause the bridge
        bridge.pause(owner)?;

        // register_deposit should fail when paused
        let result = bridge.register_deposit(
            sender,
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
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
                BridgeError::contract_paused()
            ))
        );

        // Unpause and try again - should succeed
        bridge.unpause(owner)?;
        let request_id = bridge.register_deposit(
            sender,
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
                originTxHash: B256::random(),
                originLogIndex: 0,
                tempoRecipient: Address::random(),
                amount: 1000000,
                originBlockNumber: 12345,
            },
        )?;
        assert!(!request_id.is_zero());

        Ok(())
    })
}

#[test]
fn test_pause_blocks_finalize_deposit() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();
    let validator = Address::random();
    let recipient = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let tempo_tip20 = Address::random();

    StorageCtx::enter(&mut storage, || {
        // Setup validator config with single validator
        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(owner)?;
        add_validator(&mut validator_config, owner, validator, true)?;

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

        // Validator signs
        bridge.submit_deposit_vote(
            validator,
            IBridge::submitDepositVoteCall {
                requestId: request_id,
            },
        )?;

        // Pause the bridge
        bridge.pause(owner)?;

        // finalize_deposit should fail when paused
        let result = bridge.finalize_deposit(
            Address::random(),
            IBridge::finalizeDepositCall {
                requestId: request_id,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::contract_paused()
            ))
        );

        Ok(())
    })
}

#[test]
fn test_pause_blocks_burn_for_unlock() -> eyre::Result<()> {
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

        // Pause the bridge
        bridge.pause(admin)?;

        // burn_for_unlock should fail when paused
        let result = bridge.burn_for_unlock(
            user,
            IBridge::burnForUnlockCall {
                originChainId: origin_chain_id,
                originToken: origin_token,
                originRecipient: Address::random(),
                amount,
                nonce: 0,
            },
        );
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::contract_paused()
            ))
        );

        // Unpause and try again - should succeed
        bridge.unpause(admin)?;
        let burn_id = bridge.burn_for_unlock(
            user,
            IBridge::burnForUnlockCall {
                originChainId: origin_chain_id,
                originToken: origin_token,
                originRecipient: Address::random(),
                amount,
                nonce: 0,
            },
        )?;
        assert!(!burn_id.is_zero());

        Ok(())
    })
}

#[test]
fn test_pause_then_unpause_resumes_operations() -> eyre::Result<()> {
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

        // Pause the bridge
        bridge.pause(owner)?;
        assert!(bridge.paused()?);

        // Verify operations are blocked
        let result = bridge.register_deposit(
            sender,
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
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
                BridgeError::contract_paused()
            ))
        );

        // Unpause the bridge
        bridge.unpause(owner)?;
        assert!(!bridge.paused()?);

        // Verify operations resume
        let request_id = bridge.register_deposit(
            sender,
            IBridge::registerDepositCall {
                originChainId: origin_chain_id,
                originEscrow: Address::repeat_byte(0xEE),
                originToken: origin_token,
                originTxHash: B256::random(),
                originLogIndex: 0,
                tempoRecipient: Address::random(),
                amount: 1000000,
                originBlockNumber: 12345,
            },
        )?;
        assert!(!request_id.is_zero());

        Ok(())
    })
}

#[test]
fn test_double_pause_succeeds() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();

    StorageCtx::enter(&mut storage, || {
        let mut bridge = setup_bridge(owner)?;

        // Pause once
        bridge.pause(owner)?;
        assert!(bridge.paused()?);

        // Pause again - should succeed (idempotent)
        bridge.pause(owner)?;
        assert!(bridge.paused()?);

        Ok(())
    })
}

#[test]
fn test_double_unpause_succeeds() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();

    StorageCtx::enter(&mut storage, || {
        let mut bridge = setup_bridge(owner)?;

        // Initially not paused
        assert!(!bridge.paused()?);

        // Unpause when not paused - should succeed (idempotent)
        bridge.unpause(owner)?;
        assert!(!bridge.paused()?);

        // Unpause again - should still succeed
        bridge.unpause(owner)?;
        assert!(!bridge.paused()?);

        Ok(())
    })
}

#[test]
fn test_only_owner_can_pause() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let owner = Address::random();
    let non_owner = Address::random();

    StorageCtx::enter(&mut storage, || {
        let mut bridge = setup_bridge(owner)?;

        // Non-owner cannot pause
        let result = bridge.pause(non_owner);
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::unauthorized()
            ))
        );
        assert!(!bridge.paused()?);

        // Non-owner cannot unpause
        bridge.pause(owner)?;
        let result = bridge.unpause(non_owner);
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::unauthorized()
            ))
        );
        assert!(bridge.paused()?);

        Ok(())
    })
}

#[test]
fn test_deposit_id_differs_by_chain_id() {
    let escrow = Address::repeat_byte(0xEE);
    let tx_hash = B256::repeat_byte(0xAA);
    let log_index = 42u32;

    let id_chain_1 = Bridge::compute_request_id(1, escrow, tx_hash, log_index);
    let id_chain_2 = Bridge::compute_request_id(2, escrow, tx_hash, log_index);

    assert_ne!(
        id_chain_1, id_chain_2,
        "Deposit IDs must differ when origin_chain_id differs"
    );
}

#[test]
fn test_burn_id_differs_by_chain_id() {
    let origin_chain_id = 1u64;
    let origin_token = Address::repeat_byte(0x11);
    let origin_recipient = Address::repeat_byte(0x22);
    let amount = 1_000_000u64;
    let nonce = 0u64;
    let sender = Address::repeat_byte(0x33);

    let id_tempo_1 = Bridge::compute_burn_id(
        1, // tempo_chain_id
        origin_chain_id,
        origin_token,
        origin_recipient,
        amount,
        nonce,
        sender,
    );
    let id_tempo_2 = Bridge::compute_burn_id(
        2, // tempo_chain_id
        origin_chain_id,
        origin_token,
        origin_recipient,
        amount,
        nonce,
        sender,
    );

    assert_ne!(
        id_tempo_1, id_tempo_2,
        "Burn IDs must differ when tempo_chain_id differs"
    );
}

#[test]
fn test_deposit_id_differs_by_escrow_address() {
    let chain_id = 1u64;
    let tx_hash = B256::repeat_byte(0xAA);
    let log_index = 42u32;

    let escrow_a = Address::repeat_byte(0xEE);
    let escrow_b = Address::repeat_byte(0xFF);

    let id_escrow_a = Bridge::compute_request_id(chain_id, escrow_a, tx_hash, log_index);
    let id_escrow_b = Bridge::compute_request_id(chain_id, escrow_b, tx_hash, log_index);

    assert_ne!(
        id_escrow_a, id_escrow_b,
        "Deposit IDs must differ when escrow_address differs"
    );
}

#[test]
fn test_threshold_with_min_validators() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let validators: Vec<Address> = (0..3).map(|_| Address::random()).collect();
    let recipient = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let amount = 1000000u64;

    StorageCtx::enter(&mut storage, || {
        // Create TIP-20 token with minting capability
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_role(tempo_contracts::precompiles::BRIDGE_ADDRESS, *ISSUER_ROLE)
            .apply()?;
        let tempo_tip20 = token.address();

        // Setup validator config with exactly MIN_VALIDATORS (3)
        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(admin)?;
        for v in &validators {
            add_validator(&mut validator_config, admin, *v, true)?;
        }

        // Verify we have exactly 3 active validators
        let all_validators = validator_config.get_validators()?;
        let active_count = all_validators.iter().filter(|v| v.active).count();
        assert_eq!(active_count, 3, "Should have exactly MIN_VALIDATORS active");

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

        // With 3 validators, threshold = ceil(3 * 2 / 3) = 2
        // 1 vote should NOT be enough
        bridge.submit_deposit_vote(
            validators[0],
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

        // 2 votes should be enough (threshold = 2)
        bridge.submit_deposit_vote(
            validators[1],
            IBridge::submitDepositVoteCall {
                requestId: request_id,
            },
        )?;

        bridge.finalize_deposit(
            Address::random(),
            IBridge::finalizeDepositCall {
                requestId: request_id,
            },
        )?;

        // Verify deposit was finalized
        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.status, IBridge::DepositStatus::Finalized);

        Ok(())
    })
}

#[test]
fn test_cannot_finalize_with_zero_active_validators() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let recipient = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let tempo_tip20 = Address::random();

    StorageCtx::enter(&mut storage, || {
        // Setup validator config with NO active validators (empty)
        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(admin)?;

        // Verify no active validators
        let all_validators = validator_config.get_validators()?;
        let active_count = all_validators.iter().filter(|v| v.active).count();
        assert_eq!(active_count, 0, "Should have zero active validators");

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
                amount: 1000000,
                originBlockNumber: 12345,
            },
        )?;

        // Cannot finalize with zero active validators (no votes possible)
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

        Ok(())
    })
}

#[test]
fn test_threshold_increases_with_validator_count() -> eyre::Result<()> {
    // Test threshold calculation: ceil(n * 2 / 3)
    // 3 validators -> ceil(6/3) = 2
    // 4 validators -> ceil(8/3) = 3
    // 5 validators -> ceil(10/3) = 4
    // 10 validators -> ceil(20/3) = 7
    // 100 validators -> ceil(200/3) = 67

    let test_cases: Vec<(u64, u64)> = vec![
        (3, 2),    // ceil(6/3) = 2
        (4, 3),    // ceil(8/3) = 3
        (5, 4),    // ceil(10/3) = 4
        (10, 7),   // ceil(20/3) = 7
        (100, 67), // ceil(200/3) = 67
    ];

    for (validator_count, expected_threshold) in test_cases {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let recipient = Address::random();
        let origin_chain_id = 1u64;
        let origin_token = Address::random();
        let amount = 1000000u64;

        StorageCtx::enter(&mut storage, || {
            // Create TIP-20 token with minting capability
            let token = TIP20Setup::create("Bridged Token", "BT", admin)
                .with_role(tempo_contracts::precompiles::BRIDGE_ADDRESS, *ISSUER_ROLE)
                .apply()?;
            let tempo_tip20 = token.address();

            // Setup validator config with specified number of validators
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(admin)?;

            let validators: Vec<Address> =
                (0..validator_count).map(|_| Address::random()).collect();
            for v in &validators {
                add_validator(&mut validator_config, admin, *v, true)?;
            }

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

            // Submit threshold - 1 votes (should NOT be enough)
            for i in 0..(expected_threshold - 1) {
                bridge.submit_deposit_vote(
                    validators[i as usize],
                    IBridge::submitDepositVoteCall {
                        requestId: request_id,
                    },
                )?;
            }

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
                )),
                "With {} validators and {} votes, finalization should fail",
                validator_count,
                expected_threshold - 1
            );

            // Submit one more vote to reach threshold
            bridge.submit_deposit_vote(
                validators[(expected_threshold - 1) as usize],
                IBridge::submitDepositVoteCall {
                    requestId: request_id,
                },
            )?;

            // Now finalization should succeed
            bridge.finalize_deposit(
                Address::random(),
                IBridge::finalizeDepositCall {
                    requestId: request_id,
                },
            )?;

            let deposit = bridge.get_deposit(IBridge::getDepositCall {
                requestId: request_id,
            })?;
            assert_eq!(
                deposit.status,
                IBridge::DepositStatus::Finalized,
                "With {validator_count} validators and {expected_threshold} votes, deposit should be finalized"
            );

            Ok::<(), eyre::Report>(())
        })?;
    }

    Ok(())
}

#[test]
fn test_register_and_finalize_with_signatures() -> eyre::Result<()> {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_contracts::precompiles::ITIP20;

    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let origin_escrow = Address::repeat_byte(0xEE);
    let origin_tx_hash = B256::random();
    let origin_log_index = 0u32;
    let tempo_recipient = Address::random();
    let amount = 1_000_000u64;
    let origin_block_number = 12345u64;

    // Create validator signer
    let validator1_signer = PrivateKeySigner::random();
    let validator1_addr = validator1_signer.address();

    StorageCtx::enter(&mut storage, || {
        // Create TIP-20 token with minting capability (bridge as issuer)
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_role(tempo_contracts::precompiles::BRIDGE_ADDRESS, *ISSUER_ROLE)
            .apply()?;
        let tempo_tip20 = token.address();

        // Setup validator config
        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(admin)?;
        add_validator(&mut validator_config, admin, validator1_addr, true)?;

        // Setup bridge
        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Compute request ID (must match what precompile computes)
        let request_id = Bridge::compute_request_id(
            origin_chain_id,
            origin_escrow,
            origin_tx_hash,
            origin_log_index,
        );

        // Compute validator set hash (must match what precompile uses)
        let validator_set_hash = validator_config.compute_validator_set_hash()?;

        // Compute attestation digest (must match precompile computation)
        let chain_id = bridge.storage.chain_id();
        let digest = Bridge::compute_deposit_attestation_digest(
            chain_id,
            request_id,
            origin_chain_id,
            origin_escrow,
            origin_token,
            origin_tx_hash,
            origin_log_index,
            tempo_recipient,
            amount,
            origin_block_number,
            validator_set_hash,
        );

        // Sign the digest with validator key (synchronous)
        let signature = validator1_signer.sign_hash_sync(&digest)?;
        let sig_bytes = alloy::primitives::Bytes::from(signature.as_bytes().to_vec());

        // Submit registerAndFinalizeWithSignatures (from any account - not the validator)
        let relayer = Address::random();
        let result = bridge.register_and_finalize_with_signatures(
            relayer,
            IBridge::registerAndFinalizeWithSignaturesCall {
                originChainId: origin_chain_id,
                originEscrow: origin_escrow,
                originToken: origin_token,
                originTxHash: origin_tx_hash,
                originLogIndex: origin_log_index,
                tempoRecipient: tempo_recipient,
                amount,
                originBlockNumber: origin_block_number,
                signatures: vec![sig_bytes],
            },
        )?;

        assert_eq!(result, request_id);

        // Verify deposit is finalized
        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.status, IBridge::DepositStatus::Finalized);
        assert_eq!(deposit.votingPowerSigned, 1);

        // Verify validator signature was recorded
        let has_signed =
            bridge.has_validator_signed_deposit(IBridge::hasValidatorSignedDepositCall {
                requestId: request_id,
                validator: validator1_addr,
            })?;
        assert!(has_signed);

        // Verify tokens were minted
        let balance = token.balance_of(ITIP20::balanceOfCall {
            account: tempo_recipient,
        })?;
        assert_eq!(balance, U256::from(amount));

        Ok(())
    })
}

#[test]
fn test_register_and_finalize_with_signatures_idempotent() -> eyre::Result<()> {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let origin_escrow = Address::repeat_byte(0xEE);
    let origin_tx_hash = B256::random();
    let origin_log_index = 0u32;
    let tempo_recipient = Address::random();
    let amount = 1_000_000u64;
    let origin_block_number = 12345u64;

    let validator1_signer = PrivateKeySigner::random();
    let validator1_addr = validator1_signer.address();

    StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_role(tempo_contracts::precompiles::BRIDGE_ADDRESS, *ISSUER_ROLE)
            .apply()?;
        let tempo_tip20 = token.address();

        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(admin)?;
        add_validator(&mut validator_config, admin, validator1_addr, true)?;

        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        let request_id = Bridge::compute_request_id(
            origin_chain_id,
            origin_escrow,
            origin_tx_hash,
            origin_log_index,
        );

        // Compute validator set hash (must match what precompile uses)
        let validator_set_hash = validator_config.compute_validator_set_hash()?;

        let chain_id = bridge.storage.chain_id();
        let digest = Bridge::compute_deposit_attestation_digest(
            chain_id,
            request_id,
            origin_chain_id,
            origin_escrow,
            origin_token,
            origin_tx_hash,
            origin_log_index,
            tempo_recipient,
            amount,
            origin_block_number,
            validator_set_hash,
        );

        let signature = validator1_signer.sign_hash_sync(&digest)?;
        let sig_bytes = alloy::primitives::Bytes::from(signature.as_bytes().to_vec());

        let call = IBridge::registerAndFinalizeWithSignaturesCall {
            originChainId: origin_chain_id,
            originEscrow: origin_escrow,
            originToken: origin_token,
            originTxHash: origin_tx_hash,
            originLogIndex: origin_log_index,
            tempoRecipient: tempo_recipient,
            amount,
            originBlockNumber: origin_block_number,
            signatures: vec![sig_bytes],
        };

        // First call - should succeed and finalize
        let relayer = Address::random();
        let result1 = bridge.register_and_finalize_with_signatures(relayer, call.clone())?;
        assert_eq!(result1, request_id);

        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.status, IBridge::DepositStatus::Finalized);

        // Second call with same data - should return success (idempotent), not revert
        let result2 = bridge.register_and_finalize_with_signatures(relayer, call)?;
        assert_eq!(result2, request_id);

        // Deposit should still be finalized
        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.status, IBridge::DepositStatus::Finalized);

        Ok(())
    })
}

#[test]
fn test_register_and_finalize_with_signatures_threshold_not_reached() -> eyre::Result<()> {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let origin_escrow = Address::repeat_byte(0xEE);
    let origin_tx_hash = B256::random();
    let origin_log_index = 0u32;
    let tempo_recipient = Address::random();
    let amount = 1_000_000u64;
    let origin_block_number = 12345u64;

    // Create validator signers (3 validators, need 2/3 = 2 signatures)
    let validator1_signer = PrivateKeySigner::random();
    let validator1_addr = validator1_signer.address();
    let validator2_addr = Address::random();
    let validator3_addr = Address::random();

    StorageCtx::enter(&mut storage, || {
        // Create TIP-20 token with minting capability (bridge as issuer)
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_role(tempo_contracts::precompiles::BRIDGE_ADDRESS, *ISSUER_ROLE)
            .apply()?;
        let tempo_tip20 = token.address();

        // Add 3 validators
        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(admin)?;
        add_validator(&mut validator_config, admin, validator1_addr, true)?;
        add_validator(&mut validator_config, admin, validator2_addr, true)?;
        add_validator(&mut validator_config, admin, validator3_addr, true)?;

        // Setup bridge
        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        // Compute request ID
        let request_id = Bridge::compute_request_id(
            origin_chain_id,
            origin_escrow,
            origin_tx_hash,
            origin_log_index,
        );

        // Compute validator set hash
        let validator_set_hash = validator_config.compute_validator_set_hash()?;

        // Compute attestation digest
        let chain_id = bridge.storage.chain_id();
        let digest = Bridge::compute_deposit_attestation_digest(
            chain_id,
            request_id,
            origin_chain_id,
            origin_escrow,
            origin_token,
            origin_tx_hash,
            origin_log_index,
            tempo_recipient,
            amount,
            origin_block_number,
            validator_set_hash,
        );

        // Sign with only 1 validator (need 2 for threshold)
        let signature = validator1_signer.sign_hash_sync(&digest)?;
        let sig_bytes = alloy::primitives::Bytes::from(signature.as_bytes().to_vec());

        // Submit with only 1 signature - should fail threshold check
        let relayer = Address::random();
        let result = bridge.register_and_finalize_with_signatures(
            relayer,
            IBridge::registerAndFinalizeWithSignaturesCall {
                originChainId: origin_chain_id,
                originEscrow: origin_escrow,
                originToken: origin_token,
                originTxHash: origin_tx_hash,
                originLogIndex: origin_log_index,
                tempoRecipient: tempo_recipient,
                amount,
                originBlockNumber: origin_block_number,
                signatures: vec![sig_bytes],
            },
        );

        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::threshold_not_reached()
            ))
        );

        Ok(())
    })
}

/// Golden test vectors for cross-crate digest parity.
///
/// These MUST match the values in `tempo-bridge-exex::digest_parity_test::test_vectors`.
/// If you change these values, update both files.
mod digest_parity_vectors {
    use alloy::primitives::{Address, B256, address, b256, keccak256};
    use tempo_contracts::precompiles::BRIDGE_ADDRESS;

    pub(super) const TEMPO_CHAIN_ID: u64 = 42069;
    pub(super) const ORIGIN_CHAIN_ID: u64 = 1;
    pub(super) const ORIGIN_LOG_INDEX: u32 = 7;
    pub(super) const AMOUNT: u64 = 1_000_000_000_000_000_000; // 1e18
    pub(super) const ORIGIN_BLOCK_NUMBER: u64 = 19_500_000;

    pub(super) fn bridge_address() -> Address {
        BRIDGE_ADDRESS
    }

    pub(super) fn request_id() -> B256 {
        b256!("deadbeef00000000000000000000000000000000000000000000000000000001")
    }

    pub(super) fn origin_escrow() -> Address {
        address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    }

    pub(super) fn origin_token() -> Address {
        address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") // USDC on mainnet
    }

    pub(super) fn origin_tx_hash() -> B256 {
        b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    }

    pub(super) fn tempo_recipient() -> Address {
        address!("1111111111111111111111111111111111111111")
    }

    /// A fixed validator set hash for testing.
    /// In production, this is computed from active validator addresses.
    pub(super) fn validator_set_hash() -> B256 {
        b256!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    }

    /// Expected digest computed manually - must match bridge-exex computation.
    pub(super) fn expected_digest() -> B256 {
        let domain = b"TEMPO_BRIDGE_DEPOSIT_V2";
        let mut buf =
            Vec::with_capacity(domain.len() + 8 + 20 + 32 + 8 + 20 + 20 + 32 + 4 + 20 + 8 + 8 + 32);
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&TEMPO_CHAIN_ID.to_be_bytes());
        buf.extend_from_slice(bridge_address().as_slice());
        buf.extend_from_slice(request_id().as_slice());
        buf.extend_from_slice(&ORIGIN_CHAIN_ID.to_be_bytes());
        buf.extend_from_slice(origin_escrow().as_slice());
        buf.extend_from_slice(origin_token().as_slice());
        buf.extend_from_slice(origin_tx_hash().as_slice());
        buf.extend_from_slice(&ORIGIN_LOG_INDEX.to_be_bytes());
        buf.extend_from_slice(tempo_recipient().as_slice());
        buf.extend_from_slice(&AMOUNT.to_be_bytes());
        buf.extend_from_slice(&ORIGIN_BLOCK_NUMBER.to_be_bytes());
        buf.extend_from_slice(validator_set_hash().as_slice());
        keccak256(&buf)
    }
}

#[test]
fn test_deposit_attestation_digest_parity_with_bridge_exex() {
    use digest_parity_vectors::*;

    // Compute digest using the precompile's function
    let precompile_digest = Bridge::compute_deposit_attestation_digest(
        TEMPO_CHAIN_ID,
        request_id(),
        ORIGIN_CHAIN_ID,
        origin_escrow(),
        origin_token(),
        origin_tx_hash(),
        ORIGIN_LOG_INDEX,
        tempo_recipient(),
        AMOUNT,
        ORIGIN_BLOCK_NUMBER,
        validator_set_hash(),
    );

    let expected = expected_digest();
    assert_eq!(
        precompile_digest, expected,
        "Precompile digest mismatch with golden test vector!\n\
         This test ensures parity with tempo-bridge-exex::digest_parity_test.\n\
         If this fails, the two implementations have diverged.\n\
         \n\
         Computed: {precompile_digest}\n\
         Expected: {expected}"
    );
}

#[test]
fn test_deposit_attestation_digest_includes_origin_escrow() {
    use digest_parity_vectors::*;

    // Compute digest with the standard origin_escrow
    let digest1 = Bridge::compute_deposit_attestation_digest(
        TEMPO_CHAIN_ID,
        request_id(),
        ORIGIN_CHAIN_ID,
        origin_escrow(),
        origin_token(),
        origin_tx_hash(),
        ORIGIN_LOG_INDEX,
        tempo_recipient(),
        AMOUNT,
        ORIGIN_BLOCK_NUMBER,
        validator_set_hash(),
    );

    // Compute digest with a different origin_escrow
    let different_escrow = Address::repeat_byte(0xDD);
    let digest2 = Bridge::compute_deposit_attestation_digest(
        TEMPO_CHAIN_ID,
        request_id(),
        ORIGIN_CHAIN_ID,
        different_escrow,
        origin_token(),
        origin_tx_hash(),
        ORIGIN_LOG_INDEX,
        tempo_recipient(),
        AMOUNT,
        ORIGIN_BLOCK_NUMBER,
        validator_set_hash(),
    );

    assert_ne!(
        digest1, digest2,
        "origin_escrow MUST affect the digest - different escrows should produce different digests.\n\
         This is critical for security: deposits from different escrow contracts must not be confused."
    );
}

#[test]
fn test_deposit_attestation_digest_all_fields_affect_output() {
    use digest_parity_vectors::*;

    let base_digest = Bridge::compute_deposit_attestation_digest(
        TEMPO_CHAIN_ID,
        request_id(),
        ORIGIN_CHAIN_ID,
        origin_escrow(),
        origin_token(),
        origin_tx_hash(),
        ORIGIN_LOG_INDEX,
        tempo_recipient(),
        AMOUNT,
        ORIGIN_BLOCK_NUMBER,
        validator_set_hash(),
    );

    // Test each field individually
    let fields_and_digests = [
        (
            "tempo_chain_id",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID + 1,
                request_id(),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "request_id",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                B256::repeat_byte(0xFF),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "origin_chain_id",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID + 1,
                origin_escrow(),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "origin_escrow",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID,
                Address::repeat_byte(0x01),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "origin_token",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                Address::repeat_byte(0x01),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "origin_tx_hash",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                origin_token(),
                B256::repeat_byte(0xFF),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "origin_log_index",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX + 1,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "tempo_recipient",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                Address::repeat_byte(0x01),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "amount",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT + 1,
                ORIGIN_BLOCK_NUMBER,
                validator_set_hash(),
            ),
        ),
        (
            "origin_block_number",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER + 1,
                validator_set_hash(),
            ),
        ),
        (
            "validator_set_hash",
            Bridge::compute_deposit_attestation_digest(
                TEMPO_CHAIN_ID,
                request_id(),
                ORIGIN_CHAIN_ID,
                origin_escrow(),
                origin_token(),
                origin_tx_hash(),
                ORIGIN_LOG_INDEX,
                tempo_recipient(),
                AMOUNT,
                ORIGIN_BLOCK_NUMBER,
                B256::repeat_byte(0xFF),
            ),
        ),
    ];

    for (field_name, digest) in fields_and_digests {
        assert_ne!(base_digest, digest, "{field_name} must affect the digest");
    }
}

#[test]
fn test_low_s_signature_accepted() -> eyre::Result<()> {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_contracts::precompiles::ITIP20;

    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let origin_escrow = Address::repeat_byte(0xEE);
    let origin_tx_hash = B256::random();
    let origin_log_index = 0u32;
    let tempo_recipient = Address::random();
    let amount = 1_000_000u64;
    let origin_block_number = 12345u64;

    let validator_signer = PrivateKeySigner::random();
    let validator_addr = validator_signer.address();

    StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_role(tempo_contracts::precompiles::BRIDGE_ADDRESS, *ISSUER_ROLE)
            .apply()?;
        let tempo_tip20 = token.address();

        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(admin)?;
        add_validator(&mut validator_config, admin, validator_addr, true)?;

        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        let request_id = Bridge::compute_request_id(
            origin_chain_id,
            origin_escrow,
            origin_tx_hash,
            origin_log_index,
        );

        // Compute validator set hash
        let validator_set_hash = validator_config.compute_validator_set_hash()?;

        let chain_id = bridge.storage.chain_id();
        let digest = Bridge::compute_deposit_attestation_digest(
            chain_id,
            request_id,
            origin_chain_id,
            origin_escrow,
            origin_token,
            origin_tx_hash,
            origin_log_index,
            tempo_recipient,
            amount,
            origin_block_number,
            validator_set_hash,
        );

        // alloy-signer-local produces low-s signatures by default
        let signature = validator_signer.sign_hash_sync(&digest)?;
        let sig_bytes = alloy::primitives::Bytes::from(signature.as_bytes().to_vec());

        // Verify the s value is low (< n/2)
        let s = U256::from_be_slice(&sig_bytes[32..64]);
        let secp256k1_n_div_2 = U256::from_be_slice(&[
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ]);
        assert!(
            s <= secp256k1_n_div_2,
            "alloy signer should produce low-s signatures"
        );

        let relayer = Address::random();
        let result = bridge.register_and_finalize_with_signatures(
            relayer,
            IBridge::registerAndFinalizeWithSignaturesCall {
                originChainId: origin_chain_id,
                originEscrow: origin_escrow,
                originToken: origin_token,
                originTxHash: origin_tx_hash,
                originLogIndex: origin_log_index,
                tempoRecipient: tempo_recipient,
                amount,
                originBlockNumber: origin_block_number,
                signatures: vec![sig_bytes],
            },
        )?;

        assert_eq!(result, request_id);

        let deposit = bridge.get_deposit(IBridge::getDepositCall {
            requestId: request_id,
        })?;
        assert_eq!(deposit.status, IBridge::DepositStatus::Finalized);

        let balance = token.balance_of(ITIP20::balanceOfCall {
            account: tempo_recipient,
        })?;
        assert_eq!(balance, U256::from(amount));

        Ok(())
    })
}

#[test]
fn test_high_s_signature_rejected() -> eyre::Result<()> {
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    let mut storage = HashMapStorageProvider::new(1);
    let admin = Address::random();
    let origin_chain_id = 1u64;
    let origin_token = Address::random();
    let origin_escrow = Address::repeat_byte(0xEE);
    let origin_tx_hash = B256::random();
    let origin_log_index = 0u32;
    let tempo_recipient = Address::random();
    let amount = 1_000_000u64;
    let origin_block_number = 12345u64;

    let validator_signer = PrivateKeySigner::random();
    let validator_addr = validator_signer.address();

    StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::create("Bridged Token", "BT", admin)
            .with_role(tempo_contracts::precompiles::BRIDGE_ADDRESS, *ISSUER_ROLE)
            .apply()?;
        let tempo_tip20 = token.address();

        let mut validator_config = ValidatorConfig::new();
        validator_config.initialize(admin)?;
        add_validator(&mut validator_config, admin, validator_addr, true)?;

        let mut bridge = setup_bridge(admin)?;
        register_mapping(
            &mut bridge,
            admin,
            origin_chain_id,
            origin_token,
            tempo_tip20,
        )?;

        let request_id = Bridge::compute_request_id(
            origin_chain_id,
            origin_escrow,
            origin_tx_hash,
            origin_log_index,
        );

        // Compute validator set hash
        let validator_set_hash = validator_config.compute_validator_set_hash()?;

        let chain_id = bridge.storage.chain_id();
        let digest = Bridge::compute_deposit_attestation_digest(
            chain_id,
            request_id,
            origin_chain_id,
            origin_escrow,
            origin_token,
            origin_tx_hash,
            origin_log_index,
            tempo_recipient,
            amount,
            origin_block_number,
            validator_set_hash,
        );

        // Get a valid low-s signature first
        let signature = validator_signer.sign_hash_sync(&digest)?;
        let mut sig_bytes = signature.as_bytes().to_vec();

        // Convert s to high-s: s' = n - s (where n is the secp256k1 curve order)
        // secp256k1 curve order n
        let secp256k1_n = U256::from_be_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ]);
        let s = U256::from_be_slice(&sig_bytes[32..64]);
        let high_s = secp256k1_n - s;

        // Replace s with high-s
        let high_s_bytes: [u8; 32] = high_s.to_be_bytes();
        sig_bytes[32..64].copy_from_slice(&high_s_bytes);

        // Also flip v (27 <-> 28 or 0 <-> 1) to maintain signature validity for the same message
        // When we negate s, we need to flip the recovery id
        let v = sig_bytes[64];
        sig_bytes[64] = if v >= 27 { 27 + 28 - v } else { 1 - v };

        let secp256k1_n_div_2 = U256::from_be_slice(&[
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46,
            0x68, 0x1B, 0x20, 0xA0,
        ]);
        assert!(
            high_s > secp256k1_n_div_2,
            "high_s should be greater than n/2"
        );

        let high_s_sig_bytes = alloy::primitives::Bytes::from(sig_bytes);

        let relayer = Address::random();
        let result = bridge.register_and_finalize_with_signatures(
            relayer,
            IBridge::registerAndFinalizeWithSignaturesCall {
                originChainId: origin_chain_id,
                originEscrow: origin_escrow,
                originToken: origin_token,
                originTxHash: origin_tx_hash,
                originLogIndex: origin_log_index,
                tempoRecipient: tempo_recipient,
                amount,
                originBlockNumber: origin_block_number,
                signatures: vec![high_s_sig_bytes],
            },
        );

        // Should fail because the only signature has high-s and is rejected
        assert_eq!(
            result,
            Err(TempoPrecompileError::BridgeError(
                BridgeError::threshold_not_reached()
            ))
        );

        Ok(())
    })
}
