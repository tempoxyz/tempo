use alloy::providers::DynProvider;

use super::*;

pub(super) type TIP20Instance = ITIP20Instance<DynProvider<TempoNetwork>, TempoNetwork>;

const GAS_LIMIT: u64 = 300_000;

pub(super) async fn transfer(
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    token: TIP20Instance,
) -> eyre::Result<Vec<u8>> {
    Ok(token
        .transfer(Address::random(), U256::ONE)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .chain_id(chain_id)
        .nonce(nonce)
        .build_raw_transaction(signer)
        .await?)
}
