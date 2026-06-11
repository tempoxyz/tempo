use std::collections::BTreeSet;

use alloy_primitives::Address;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    IStablecoinDEX, ITIP1060StorageCredits, STABLECOIN_DEX_ADDRESS, STORAGE_CREDITS_ADDRESS,
};
use tempo_fuzz_types::StateInput;

use super::{HarnessEvm, fmt_addr, view_call};

const STORAGE_CREATION_COST: u64 = 250_000;

pub(super) fn validate(
    pre_evm: &mut HarnessEvm,
    post_evm: &mut HarnessEvm,
    side: &'static str,
    hardfork: TempoHardfork,
    pre_state: &StateInput,
    post_state: &StateInput,
    gas_used: u64,
    intrinsic_gas: u64,
) -> Result<(), String> {
    if !hardfork.is_t7() {
        return Ok(());
    }

    validate_dex_storage_credit_sum(post_evm, side, post_state)?;

    let mut unbacked_credit_increase = 0u64;
    let mut example_unbacked_owner = None;

    for owner in storage_credit_owners(pre_state, post_state) {
        let pre_balance = balance_of(pre_evm, owner)?.unwrap_or(0);
        let post_balance = balance_of(post_evm, owner)?.unwrap_or(0);
        let footprint_reductions = storage_footprint_reductions(pre_state, post_state, owner);
        let deletion_backed_balance = pre_balance.saturating_add(footprint_reductions);

        if post_balance > deletion_backed_balance {
            unbacked_credit_increase = unbacked_credit_increase
                .checked_add(post_balance - deletion_backed_balance)
                .unwrap();
            example_unbacked_owner.get_or_insert((
                owner,
                pre_balance,
                post_balance,
                footprint_reductions,
                deletion_backed_balance,
            ));
        }
    }

    let minimum_execution_gas = unbacked_credit_increase
        .checked_mul(STORAGE_CREATION_COST)
        .unwrap();
    let execution_gas = gas_used.saturating_sub(intrinsic_gas);

    if execution_gas < minimum_execution_gas {
        let example_unbacked_owner = example_unbacked_owner
            .map(
                |(
                    owner,
                    pre_balance,
                    post_balance,
                    footprint_reductions,
                    deletion_backed_balance,
                )| {
                    format!(
                        " example_unbacked_credit_owner={} example_pre_balance={pre_balance} example_post_balance={post_balance} example_real_storage_footprint_reductions={footprint_reductions} example_balance_backed_by_prior_balance_or_deletions={deletion_backed_balance}",
                        fmt_addr(owner),
                    )
                },
            )
            .unwrap_or_default();
        return Err(format!(
            "TEMPO-STORAGE-CREDIT-BALANCE-BACKING side={side} unbacked_credit_increase={unbacked_credit_increase} gas_used={gas_used} intrinsic_gas={intrinsic_gas} execution_gas={execution_gas} minimum_execution_gas={minimum_execution_gas}{example_unbacked_owner}"
        ));
    }

    Ok(())
}

fn validate_dex_storage_credit_sum(
    evm: &mut HarnessEvm,
    side: &'static str,
    state: &StateInput,
) -> Result<(), String> {
    let protocol_balance = balance_of(evm, STABLECOIN_DEX_ADDRESS)?.unwrap_or(0);
    let mut exchange_balance_sum = 0u64;
    let mut nonzero_holders = 0u64;
    let mut example_holder = None;

    for user in dex_storage_credit_candidate_users(state) {
        let balance = storage_credits(evm, user)?.unwrap_or(0);
        if balance == 0 {
            continue;
        }
        nonzero_holders = nonzero_holders.checked_add(1).unwrap();
        exchange_balance_sum = exchange_balance_sum.checked_add(balance).unwrap();
        example_holder.get_or_insert((user, balance));
    }

    if protocol_balance != exchange_balance_sum {
        let example_holder = example_holder
            .map(|(user, balance)| {
                format!(
                    " example_exchange_credit_holder={} example_exchange_credits={balance}",
                    fmt_addr(user),
                )
            })
            .unwrap_or_default();
        return Err(format!(
            "TEMPO-DEX-STORAGE-CREDIT-SUM side={side} protocol_dex_balance={protocol_balance} exchange_storage_credit_sum={exchange_balance_sum} exchange_credit_holders={nonzero_holders}{example_holder}"
        ));
    }

    Ok(())
}

fn storage_credit_owners(pre_state: &StateInput, post_state: &StateInput) -> BTreeSet<Address> {
    let mut owners = BTreeSet::new();
    owners.extend(state_account_addresses(pre_state));
    owners.extend(state_account_addresses(post_state));
    owners.extend(storage_credit_balance_owners(pre_state));
    owners.extend(storage_credit_balance_owners(post_state));
    owners.remove(&STORAGE_CREDITS_ADDRESS);
    owners
}

fn dex_storage_credit_candidate_users(state: &StateInput) -> BTreeSet<Address> {
    let mut users = BTreeSet::new();
    users.extend(state_account_addresses(state));
    users.extend(storage_credit_balance_owners(state));
    users.remove(&STABLECOIN_DEX_ADDRESS);
    users.remove(&STORAGE_CREDITS_ADDRESS);
    users
}

fn state_account_addresses(state: &StateInput) -> impl Iterator<Item = Address> + '_ {
    state
        .accounts
        .iter()
        .map(|account| Address::from(account.address))
}

fn storage_credit_balance_owners(state: &StateInput) -> impl Iterator<Item = Address> + '_ {
    state
        .accounts
        .iter()
        .filter(|account| Address::from(account.address) == STORAGE_CREDITS_ADDRESS)
        .flat_map(|account| &account.storage)
        .map(|entry| Address::from_slice(&entry.slot[12..]))
}

fn storage_footprint_reductions(
    pre_state: &StateInput,
    post_state: &StateInput,
    owner: Address,
) -> u64 {
    let pre_slots = nonzero_storage_slots(pre_state, owner);
    let post_slots = nonzero_storage_slots(post_state, owner);
    pre_slots.difference(&post_slots).count() as u64
}

fn nonzero_storage_slots(state: &StateInput, owner: Address) -> BTreeSet<[u8; 32]> {
    state
        .accounts
        .iter()
        .filter(|account| Address::from(account.address) == owner)
        .flat_map(|account| &account.storage)
        .filter(|entry| entry.value != [0; 32])
        .map(|entry| entry.slot)
        .collect()
}

fn balance_of(evm: &mut HarnessEvm, account: Address) -> Result<Option<u64>, String> {
    view_call::<ITIP1060StorageCredits::balanceOfCall>(
        evm,
        STORAGE_CREDITS_ADDRESS,
        ITIP1060StorageCredits::balanceOfCall { account },
    )
}

fn storage_credits(evm: &mut HarnessEvm, user: Address) -> Result<Option<u64>, String> {
    view_call::<IStablecoinDEX::storageCreditsCall>(
        evm,
        STABLECOIN_DEX_ADDRESS,
        IStablecoinDEX::storageCreditsCall { user },
    )
}
