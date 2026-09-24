use super::*;
use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
use alloy::primitives::keccak256;
use tempo_chainspec::hardfork::TempoHardfork;

const OWNER: Address = Address::repeat_byte(1);
const OTHER: Address = Address::repeat_byte(2);
const SOURCE: Address = Address::repeat_byte(3);
const TOKEN: Address = Address::repeat_byte(4);
const POLICY: Address = Address::repeat_byte(5);

fn policy() -> IFundingPolicy::Rules {
    IFundingPolicy::Rules {
        maxSlippageBps: 100,
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
        assert_eq!(
            policies.create_policy(OTHER, vec![OWNER], original.clone())?,
            1
        );
        assert_eq!(
            policies.create_policy(OTHER, vec![OWNER], original.clone())?,
            2
        );
        assert_eq!(policies.policy_id_counter()?, 3);
        let hash = policies.get_policy(1)?.rulesHash;
        assert_eq!(
            policies.verify_rules(hash, &original.abi_encode())?,
            original
        );
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
        let id = policies.create_policy(OWNER, vec![OWNER], policy())?;
        assert_eq!(
            policies.set_rules(
                OTHER,
                id,
                IFundingPolicy::Rules {
                    maxSlippageBps: 0,
                    routes: vec![]
                }
            ),
            Err(unauthorized())
        );
        assert_eq!(
            policies.set_admins(OTHER, id, vec![OTHER]),
            Err(unauthorized())
        );
        policies.set_rules(
            OWNER,
            id,
            IFundingPolicy::Rules {
                maxSlippageBps: 0,
                routes: vec![],
            },
        )?;
        assert_eq!(policies.get_policy(id)?.admins, vec![OWNER]);
        policies.set_admins(OWNER, id, vec![OTHER])?;
        let replaced = policies.get_policy(id)?;
        assert_eq!(replaced.admins, vec![OTHER]);
        assert_eq!(
            replaced.rulesHash,
            policies.hash_rules_data(
                &IFundingPolicy::Rules {
                    maxSlippageBps: 0,
                    routes: vec![]
                }
                .abi_encode()
            )?
        );
        assert_eq!(
            policies.set_admins(OWNER, id, vec![OWNER]),
            Err(unauthorized())
        );
        policies.set_rules(
            OTHER,
            id,
            IFundingPolicy::Rules {
                maxSlippageBps: 10_000,
                routes: policy().routes,
            },
        )?;
        assert_eq!(
            policies.get_policy(id)?.rulesHash,
            policies.hash_rules_data(
                &IFundingPolicy::Rules {
                    maxSlippageBps: 10_000,
                    routes: policy().routes
                }
                .abi_encode()
            )?
        );
        Ok(())
    })
}

#[test]
fn rejects_invalid_policies_before_allocating() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut policies = FundingPolicy::new(POLICY);
        let mutations: &[fn(&mut IFundingPolicy::Rules)] = &[
            |p| p.maxSlippageBps = 10_001,
            |p| p.routes[0].token = Address::ZERO,
            |p| p.routes.push(p.routes[0].clone()),
            |p| p.routes[0].sources[0].target = Address::ZERO,
        ];
        for mutate in mutations {
            let mut invalid = policy();
            mutate(&mut invalid);
            assert_eq!(
                policies.create_policy(OWNER, vec![OWNER], invalid),
                Err(invalid_policy())
            );
            assert_eq!(policies.policy_id_counter()?, 1);
        }
        policies.next_policy_id.write(u64::MAX)?;
        assert_eq!(
            policies.create_policy(OWNER, vec![OWNER], policy()),
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
        let id = policies.create_policy(OWNER, vec![OWNER], value.clone())?;
        assert_eq!(
            policies.get_policy(id)?.rulesHash,
            policies.hash_rules_data(&value.abi_encode())?
        );
        value.routes.reverse();
        assert_eq!(
            policies.create_policy(OWNER, vec![OWNER], value),
            Err(invalid_policy())
        );
        let mut empty = policy();
        empty.routes[0].sources.clear();
        policies.create_policy(OWNER, vec![OWNER], empty)?;
        Ok(())
    })
}

#[test]
fn access_keys_cannot_create_or_administer_policies() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut policies = FundingPolicy::new(POLICY);
        let id = policies.create_policy(OWNER, vec![OWNER], policy())?;
        AccountKeychain::new().set_transaction_key(OTHER)?;
        assert_eq!(
            policies.create_policy(OWNER, vec![OWNER], policy()),
            Err(unauthorized())
        );
        assert_eq!(
            policies.set_rules(
                OWNER,
                id,
                IFundingPolicy::Rules {
                    maxSlippageBps: 0,
                    routes: vec![]
                }
            ),
            Err(unauthorized())
        );
        assert_eq!(
            policies.set_admins(OWNER, id, vec![OTHER]),
            Err(unauthorized())
        );
        assert_eq!(
            policies.get_policy(id)?.rulesHash,
            policies.hash_rules_data(&policy().abi_encode())?
        );
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
        let id = policies.create_policy(OWNER, vec![OWNER], policy())?;
        let permission = FundingPermission::new(
            Address::repeat_byte(7),
            OWNER,
            SOURCE,
            &IFundingSource::Quote {
                assetIn: Address::ZERO,
                rate: U256::ZERO,
                maxAmountIn: U256::ZERO,
                amountOut: U256::ONE,
                executionData: Bytes::from_static(&[1]),
            },
            U256::ZERO,
        )?;
        permission.enter(|| {
            assert_eq!(
                policies.create_policy(OWNER, vec![OWNER], policy()),
                Err(unauthorized())
            );
            assert_eq!(
                policies.set_rules(
                    OWNER,
                    id,
                    IFundingPolicy::Rules {
                        maxSlippageBps: 0,
                        routes: vec![]
                    }
                ),
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
            let id = policies.create_policy(OWNER, vec![OWNER], policy())?;
            policies.set_admins(OWNER, id, vec![OTHER])?;
        }
        assert_eq!(policies.policy_id_counter()?, 1);
        assert!(!policies.policy_exists(1)?);
        let id = policies.create_policy(OWNER, vec![OWNER], policy())?;
        policies.set_rules(
            OWNER,
            id,
            IFundingPolicy::Rules {
                maxSlippageBps: 0,
                routes: vec![],
            },
        )?;
        Ok(())
    })?;
    let events = storage.events.get(&POLICY).unwrap();
    assert_eq!(events.len(), 2);
    let created = IFundingPolicy::PolicyCreated::decode_log_data_validate(&events[0])?;
    assert_eq!(created.policyId, 1);
    assert_eq!(created.updater, OWNER);
    assert_eq!(created.rules, policy());
    let updated = IFundingPolicy::PolicyRulesUpdated::decode_log_data_validate(&events[1])?;
    let expected = IFundingPolicy::Rules {
        maxSlippageBps: 0,
        routes: vec![],
    };
    assert_eq!(updated.rules, expected);
    assert_eq!(
        updated.rulesHash,
        keccak256(
            (
                keccak256("tempo.funding-policy.rules.v1"),
                Bytes::from(expected.abi_encode())
            )
                .abi_encode_params()
        )
    );
    Ok(())
}

#[test]
fn commitment_rejects_stale_mutated_and_noncanonical_rules() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut registry = FundingPolicy::new(POLICY);
        let rules = policy();
        let data = rules.abi_encode();
        let id = registry.create_policy(OWNER, vec![OWNER], rules.clone())?;
        let hash = registry.get_policy(id)?.rulesHash;
        assert_eq!(
            hash,
            keccak256(
                (
                    keccak256("tempo.funding-policy.rules.v1"),
                    Bytes::from(data.clone())
                )
                    .abi_encode_params()
            )
        );
        assert_eq!(registry.verify_rules(hash, &data)?, rules);
        assert!(registry.verify_rules(hash, &[]).is_err());
        let mut mutated = data.clone();
        *mutated.last_mut().unwrap() ^= 1;
        assert!(registry.verify_rules(hash, &mutated).is_err());
        let mut trailing = data.clone();
        trailing.extend([0; 32]);
        let trailing_hash = registry.hash_rules_data(&trailing)?;
        assert!(registry.verify_rules(trailing_hash, &trailing).is_err());
        registry.set_rules(
            OWNER,
            id,
            IFundingPolicy::Rules {
                maxSlippageBps: 0,
                routes: vec![],
            },
        )?;
        let next = registry.get_policy(id)?.rulesHash;
        assert!(registry.verify_rules(next, &data).is_err());
        registry.set_admins(OWNER, id, vec![OTHER])?;
        assert_eq!(registry.get_policy(id)?.rulesHash, next);
        Ok(())
    })
}

#[test]
fn repeated_source_entries_do_not_grow_persistent_policy_data() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    StorageCtx::enter(&mut storage, || {
        let mut registry = FundingPolicy::new(POLICY);
        for admins in [vec![], vec![OWNER, OWNER], vec![Address::ZERO]] {
            assert_eq!(
                registry.create_policy(OWNER, admins, policy()),
                Err(invalid_policy())
            );
        }
        let small = registry.create_policy(OWNER, vec![OWNER], policy())?;
        let mut large = policy();
        large.routes[0].sources = vec![large.routes[0].sources[0].clone(); 100];
        let big = registry.create_policy(OWNER, vec![OWNER], large)?;
        assert_eq!(registry.policies[small].read()?.len(), 160);
        assert_eq!(registry.policies[big].read()?.len(), 160);
        Ok(())
    })
}
