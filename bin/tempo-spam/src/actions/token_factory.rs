//! TIP20Factory actions

use std::sync::atomic::Ordering;

use alloy::{
    primitives::{Address, B256},
    providers::DynProvider,
};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20Factory::ITIP20FactoryInstance, TIP20_FACTORY_ADDRESS,
};
use tempo_precompiles::tip20::ISSUER_ROLE;

use super::ActionContext;

/// Create a new TIP20 token
pub async fn create_token(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let factory = ITIP20FactoryInstance::new(TIP20_FACTORY_ADDRESS, provider.clone());

    // Generate unique salt
    let counter = ctx.token_salt_counter.fetch_add(1, Ordering::Relaxed);
    let salt = B256::from(alloy::primitives::keccak256(
        format!("spam_token_{}_{}", caller, counter).as_bytes(),
    ));

    let name = format!("SpamToken{}", counter);
    let symbol = format!("SP{}", counter % 1000);

    // Create token with pathUSD as quote
    let receipt = factory
        .createToken(name, symbol, "USD".to_string(), ctx.path_usd, caller, salt)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Grant issuer role to self
    if let Some(event) =
        receipt.decoded_log::<tempo_contracts::precompiles::ITIP20Factory::TokenCreated>()
    {
        let token_addr = event.token;
        let roles = IRolesAuth::new(token_addr, provider.clone());
        roles
            .grantRole(*ISSUER_ROLE, caller)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    Ok(())
}
