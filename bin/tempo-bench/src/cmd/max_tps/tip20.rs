use super::*;

const GAS_LIMIT: u64 = 300_000;

pub(super) fn transfer(
    signer: &PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    token_address: Address,
) -> eyre::Result<Vec<u8>> {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: TEMPO_BASE_FEE as u128,
        gas_limit: GAS_LIMIT,
        to: TxKind::Call(token_address),
        value: U256::ZERO,
        input: ITIP20::transferCall {
            to: Address::random(),
            amount: U256::ONE,
        }
        .abi_encode()
        .into(),
    };

    into_signed_encoded(tx, signer)
}
