use super::SignatureVerifier;
use crate::{Precompile, dispatch_call, input_cost, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::ISignatureVerifier::ISignatureVerifierCalls;

impl Precompile for SignatureVerifier {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(
            calldata,
            ISignatureVerifierCalls::abi_decode,
            |call| match call {
                ISignatureVerifierCalls::verify(call) => {
                    view(call, |c| self.verify(c))
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };

    #[test]
    fn test_signature_verifier_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut verifier = SignatureVerifier::new();

            let unsupported = check_selector_coverage(
                &mut verifier,
                ISignatureVerifierCalls::SELECTORS,
                "ISignatureVerifier",
                ISignatureVerifierCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
