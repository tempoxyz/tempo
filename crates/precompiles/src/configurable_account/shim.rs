//! Stateless dispatcher executed by the protocol-installed account marker.

use crate::{
    EncodePrecompileResult, charge_input_cost, dispatch::ABI_DECODER_MEMORY_LIMIT, input_cost,
    signature_verifier::SignatureVerifier, storage::StorageCtx,
};
use alloy::{
    primitives::{Address, Bytes, FixedBytes},
    sol_types::{SolCall, abi::AbiDecoderConfig},
};
use evm2::{
    evm::precompile::PrecompileOutput,
    precompiles::{PrecompileError, PrecompileResult},
};
use tempo_contracts::precompiles::configurable_account::IConfigurableAccountShim;

/// Hook decoder configuration, matching Solidity callees: values are validated, but unlike
/// precompile dispatch, trailing data and a final `bytes` without its padding are accepted, since
/// ERC-1271 and ERC-721 caller libraries send them. Truncated input still fails.
const DECODER_CONFIG: AbiDecoderConfig = AbiDecoderConfig::new()
    .memory_limit(ABI_DECODER_MEMORY_LIMIT)
    .validate(true);

/// Executes the account shim in `account`'s call context without writing state.
pub fn call(account: Address, input: &[u8]) -> PrecompileResult {
    if let Some(err) = charge_input_cost(&mut StorageCtx, input) {
        return err;
    }
    if input.is_empty() {
        return Ok(PrecompileOutput::new(Bytes::new()));
    }
    if input.starts_with(&IConfigurableAccountShim::isValidSignatureCall::SELECTOR) {
        let call = IConfigurableAccountShim::isValidSignatureCall::abi_decode_with_config(
            input,
            DECODER_CONFIG,
        )
        .map_err(|_| PrecompileError::Revert(Bytes::new()))?;
        return (|| -> crate::Result<bool> {
            // Match the verifier entrypoint's costs: its input carries one more word, `account`.
            StorageCtx.deduct_gas(input_cost(StorageCtx.spec(), 32)?)?;
            SignatureVerifier::new().verify_configurable_account(
                account,
                call.hash,
                &call.signature,
            )
        })()
        .encode_precompile_result(|valid| {
            IConfigurableAccountShim::isValidSignatureCall::abi_encode_returns(
                &FixedBytes::<4>::from(if valid {
                    IConfigurableAccountShim::isValidSignatureCall::SELECTOR
                } else {
                    [0xff; 4]
                }),
            )
            .into()
        });
    }
    if input.starts_with(&IConfigurableAccountShim::onERC721ReceivedCall::SELECTOR) {
        IConfigurableAccountShim::onERC721ReceivedCall::abi_decode_with_config(
            input,
            DECODER_CONFIG,
        )
        .map_err(|_| PrecompileError::Revert(Bytes::new()))?;
        return Ok(PrecompileOutput::new(
            IConfigurableAccountShim::onERC721ReceivedCall::abi_encode_returns(
                &FixedBytes::<4>::from(IConfigurableAccountShim::onERC721ReceivedCall::SELECTOR),
            )
            .into(),
        ));
    }
    Err(PrecompileError::Revert(Bytes::new()))
}
