//! Stateless dispatcher executed by the protocol-installed account marker.

use crate::{
    EncodePrecompileResult, charge_input_cost, input_cost, signature_verifier::SignatureVerifier,
    storage::StorageCtx,
};
use alloy::{
    primitives::{Address, Bytes, FixedBytes},
    sol_types::SolCall,
};
use evm2::{
    evm::precompile::PrecompileOutput,
    precompiles::{PrecompileError, PrecompileResult},
};
use tempo_contracts::precompiles::configurable_account::IConfigurableAccountShim;

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
            crate::dispatch::abi_decoder_config_for_spec(StorageCtx.spec())
                .validate_allow_trailing_bytes(false),
        )
        .map_err(|_| PrecompileError::Revert(Bytes::new()))?;
        let result: crate::Result<bool> = (|| {
            // Match the verifier entrypoint's costs: its input carries one more word, `account`.
            StorageCtx.deduct_gas(input_cost(StorageCtx.spec(), 32)?)?;
            SignatureVerifier::new().verify_configurable_account(
                account,
                call.hash,
                &call.signature,
            )
        })();
        return result.encode_precompile_result(|valid| {
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
            crate::dispatch::abi_decoder_config_for_spec(StorageCtx.spec())
                .validate_allow_trailing_bytes(false),
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
