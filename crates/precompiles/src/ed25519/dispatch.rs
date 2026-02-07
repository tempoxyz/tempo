use crate::{Precompile, input_cost, unknown_selector};
use alloy::{
    primitives::Address,
    sol_types::{SolInterface, SolValue},
};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use tempo_contracts::precompiles::IEd25519::IEd25519Calls;

use super::Ed25519Verifier;

impl Precompile for Ed25519Verifier {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if calldata.len() < 4 {
            return Err(PrecompileError::Other(
                "Invalid input: missing function selector".into(),
            ));
        }

        let call = match IEd25519Calls::abi_decode(calldata) {
            Ok(call) => call,
            Err(alloy::sol_types::Error::UnknownSelector { selector, .. }) => {
                return unknown_selector(*selector, input_cost(calldata.len()));
            }
            Err(_) => {
                return Ok(PrecompileOutput::new_reverted(
                    input_cost(calldata.len()),
                    alloy::primitives::Bytes::new(),
                ));
            }
        };

        match call {
            IEd25519Calls::verify(c) => {
                let (valid, gas) = self
                    .verify(c)
                    .map_err(|e| {
                        PrecompileError::Other(format!("Ed25519 verify error: {e:?}").into())
                    })?;
                Ok(PrecompileOutput::new(
                    gas,
                    SolValue::abi_encode(&valid).into(),
                ))
            }
            IEd25519Calls::verifyPacked(c) => match self.verify_packed(c) {
                Ok((valid, gas)) => Ok(PrecompileOutput::new(
                    gas,
                    SolValue::abi_encode(&valid).into(),
                )),
                Err(e) => e.into_precompile_result(0),
            },
            IEd25519Calls::verifyBatch(c) => match self.verify_batch(c) {
                Ok((valid, gas)) => Ok(PrecompileOutput::new(
                    gas,
                    SolValue::abi_encode(&valid).into(),
                )),
                Err(e) => e.into_precompile_result(0),
            },
        }
    }
}
