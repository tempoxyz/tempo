use super::*;
use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
use alloy::primitives::keccak256;
use tempo_chainspec::hardfork::TempoHardfork;

const OWNER: Address = Address::repeat_byte(1);
const OTHER: Address = Address::repeat_byte(2);
const SOURCE: Address = Address::repeat_byte(3);
const TOKEN: Address = Address::repeat_byte(4);
const POLICY: Address = Address::repeat_byte(5);

fn policy() -> IFundingPolicy::Policy {
    IFundingPolicy::Policy {
        admins: vec![OWNER],
        slippageBps: 100,
        routes: vec![IFundingPolicy::Route {
            token: TOKEN,
            sources: vec![IFundingPolicy::Source {
                target: SOURCE,
                data: Bytes::from_static(&[0xaa]),
            }],
        }],
    }
}

#[test]
fn policies_allocate_global_ids_and_preserve_rules() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut policies = FundingPolicy::new(POLICY);
        assert_eq!(policies.policy_id_counter()?, 1);
        assert!(!policies.policy_exists(0)?);
        assert!(!policies.policy_exists(1)?);
        assert!(matches!(
            policies.get_policy(1),
            Err(TempoPrecompileError::FundingPolicy(
                FundingPolicyError::PolicyNotFound(_)
            ))
        ));
        let original = policy();
        assert_eq!(policies.create_policy(OTHER, original.clone())?, 1);
        assert_eq!(policies.create_policy(OTHER, original.clone())?, 2);
        assert_eq!(policies.policy_id_counter()?, 3);
        assert_eq!(policies.get_policy(1)?, original);
        assert!(policies.policy_exists(2)?);
        assert!(!policies.policy_exists(3)?);
        Ok(())
    })
}

#[test]
fn replacement_requires_current_admin_and_preserves_other_fields() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut policies = FundingPolicy::new(POLICY);
        let id = policies.create_policy(OWNER, policy())?;
        assert_eq!(
            policies.modify_policy(OTHER, id, 0, vec![]),
            Err(unauthorized())
        );
        assert_eq!(
            policies.set_admins(OTHER, id, vec![OTHER]),
            Err(unauthorized())
        );
        policies.modify_policy(OWNER, id, 0, vec![])?;
        assert_eq!(policies.get_policy(id)?.admins, vec![OWNER]);
        policies.set_admins(OWNER, id, vec![OTHER])?;
        let replaced = policies.get_policy(id)?;
        assert_eq!(replaced.admins, vec![OTHER]);
        assert!(replaced.routes.is_empty());
        assert_eq!(replaced.slippageBps, 0);
        assert_eq!(
            policies.set_admins(OWNER, id, vec![OWNER]),
            Err(unauthorized())
        );
        policies.modify_policy(OTHER, id, 10_000, policy().routes)?;
        assert_eq!(policies.get_policy(id)?.slippageBps, 10_000);
        Ok(())
    })
}

#[test]
fn rejects_invalid_policies_before_allocating() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut policies = FundingPolicy::new(POLICY);
        let mutations: &[fn(&mut IFundingPolicy::Policy)] = &[
            |p| p.admins.clear(),
            |p| p.admins.push(OWNER),
            |p| p.admins.push(Address::ZERO),
            |p| p.slippageBps = 10_001,
            |p| p.routes[0].token = Address::ZERO,
            |p| p.routes.push(p.routes[0].clone()),
            |p| p.routes[0].sources[0].target = Address::ZERO,
            |p| {
                let duplicate = p.routes[0].sources[0].clone();
                p.routes[0].sources.push(duplicate);
            },
        ];
        for mutate in mutations {
            let mut invalid = policy();
            mutate(&mut invalid);
            assert_eq!(
                policies.create_policy(OWNER, invalid),
                Err(invalid_policy())
            );
            assert_eq!(policies.policy_id_counter()?, 1);
        }
        policies.next_policy_id.write(u64::MAX)?;
        assert_eq!(
            policies.create_policy(OWNER, policy()),
            Err(invalid_policy())
        );
        assert_eq!(policies.policy_id_counter()?, u64::MAX);
        assert!(policies.policies[u64::MAX].read()?.is_empty());
        Ok(())
    })
}

#[test]
fn routes_allow_empty_sources_and_reuse_across_tokens() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut policies = FundingPolicy::new(POLICY);
        let mut value = policy();
        let mut second = value.routes[0].clone();
        second.token = Address::repeat_byte(6);
        value.routes.push(second);
        let id = policies.create_policy(OWNER, value.clone())?;
        assert_eq!(policies.get_policy(id)?, value);
        value.routes.reverse();
        assert_eq!(policies.create_policy(OWNER, value), Err(invalid_policy()));
        let mut empty = policy();
        empty.routes[0].sources.clear();
        policies.create_policy(OWNER, empty)?;
        Ok(())
    })
}

#[test]
fn access_keys_cannot_create_or_administer_policies() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut policies = FundingPolicy::new(POLICY);
        let id = policies.create_policy(OWNER, policy())?;
        AccountKeychain::new().set_transaction_key(OTHER)?;
        assert_eq!(policies.create_policy(OWNER, policy()), Err(unauthorized()));
        assert_eq!(
            policies.modify_policy(OWNER, id, 0, vec![]),
            Err(unauthorized())
        );
        assert_eq!(
            policies.set_admins(OWNER, id, vec![OTHER]),
            Err(unauthorized())
        );
        assert_eq!(policies.get_policy(id)?, policy());
        Ok(())
    })
}

#[test]
fn callbacks_cannot_mutate_policies_even_without_account_inputs() -> eyre::Result<()> {
    use crate::tip20_funder::permission::FundingPermission;
    use alloy::primitives::U256;
    use tempo_contracts::precompiles::IFundingSource;

    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut policies = FundingPolicy::new(POLICY);
        let id = policies.create_policy(OWNER, policy())?;
        let permission = FundingPermission::new(
            Address::repeat_byte(7),
            OWNER,
            SOURCE,
            &IFundingSource::Quote {
                assetIn: Address::ZERO,
                rate: U256::ZERO,
                maxAmountIn: U256::ZERO,
                amountOut: U256::ONE,
                requestData: Bytes::from_static(&[1]),
            },
            U256::ZERO,
        )?;
        permission.enter(|| {
            assert_eq!(policies.create_policy(OWNER, policy()), Err(unauthorized()));
            assert_eq!(
                policies.modify_policy(OWNER, id, 0, vec![]),
                Err(unauthorized())
            );
            assert_eq!(
                policies.set_admins(OWNER, id, vec![OTHER]),
                Err(unauthorized())
            );
        })?;
        policies.set_admins(OWNER, id, vec![OTHER])?;
        Ok(())
    })
}

#[test]
fn policy_state_counter_and_events_follow_rollback() -> eyre::Result<()> {
    use alloy::sol_types::SolEvent;
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        let mut policies = FundingPolicy::new(POLICY);
        {
            let _rollback = StorageCtx.checkpoint();
            let id = policies.create_policy(OWNER, policy())?;
            policies.set_admins(OWNER, id, vec![OTHER])?;
        }
        assert_eq!(policies.policy_id_counter()?, 1);
        assert!(!policies.policy_exists(1)?);
        let id = policies.create_policy(OWNER, policy())?;
        policies.modify_policy(OWNER, id, 0, vec![])?;
        Ok(())
    })?;
    let events = storage.events.get(&POLICY).unwrap();
    assert_eq!(events.len(), 2);
    let created = IFundingPolicy::PolicyCreated::decode_log_data_validate(&events[0])?;
    assert_eq!(created.policyId, 1);
    assert_eq!(created.updater, OWNER);
    let updated = IFundingPolicy::PolicyUpdated::decode_log_data_validate(&events[1])?;
    // abi.encode(policy): outer offset, tuple heads, one admin, and no routes.
    let words = [32u64, 96, 0, 160, 1].map(alloy::primitives::U256::from);
    let mut encoded = words.abi_encode();
    encoded.extend(OWNER.abi_encode());
    encoded.extend(alloy::primitives::U256::ZERO.abi_encode());
    assert_eq!(updated.policyHash, keccak256(encoded));
    Ok(())
}
