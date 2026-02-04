//! TIP403Registry policy actions

use alloy::{primitives::Address, providers::DynProvider};
use rand::{random_range, seq::IndexedRandom};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::{
    ITIP403Registry::ITIP403RegistryInstance, TIP403_REGISTRY_ADDRESS,
};

use super::{ActionContext, select_random_recipient};

/// Modify a policy (add/remove from blacklist/whitelist)
pub async fn modify_policy(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
    all_signers: &[Address],
) -> eyre::Result<()> {
    // Only admin can modify policies
    if caller != ctx.admin {
        return Ok(());
    }

    if ctx.policy_ids.is_empty() {
        return Ok(());
    }

    let registry = ITIP403RegistryInstance::new(TIP403_REGISTRY_ADDRESS, provider.clone());

    // Pick a random policy
    let policy_id = *ctx.policy_ids.choose(&mut rand::rng()).unwrap();

    // Pick a random account to add/remove
    let account = select_random_recipient(caller, all_signers);

    // Randomly add or remove from blacklist
    let add_to_list = random_range(0..2) == 0;

    // Our policies are blacklists, so use modifyPolicyBlacklist
    match registry
        .modifyPolicyBlacklist(policy_id, account, add_to_list)
        .send()
        .await
    {
        Ok(pending) => {
            let _ = pending.get_receipt().await;
        }
        Err(_) => {
            // May fail if policy doesn't exist or caller isn't admin
        }
    }

    Ok(())
}
