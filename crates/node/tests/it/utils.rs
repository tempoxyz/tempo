use alloy::{primitives::Address, providers::Provider, sol_types::SolEvent};
use tempo_node::node::TEMPO_BASE_FEE;
use tempo_precompiles::{
    TIP20_FACTORY_ADDRESS,
    contracts::{
        ITIP20::ITIP20Instance, ITIP20Factory, tip20::ISSUER_ROLE, token_id_to_address,
        types::IRolesAuth,
    },
};

pub async fn setup_test_token<P>(
    provider: P,
    caller: Address,
) -> eyre::Result<ITIP20Instance<impl Clone + Provider>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken(
            "Test".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            caller,
        )
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[0].inner).unwrap();

    let token_addr = token_id_to_address(event.tokenId.to());
    let token = ITIP20Instance::new(token_addr, provider.clone());
    let roles = IRolesAuth::new(*token.address(), provider);

    roles
        .grantRole(*ISSUER_ROLE, caller)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(token)
}
