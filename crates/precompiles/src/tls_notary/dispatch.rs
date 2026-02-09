use crate::{
    Precompile, dispatch_call, input_cost, mutate, view,
    tls_notary::TLSNotary,
};
use alloy::{
    primitives::Address,
    sol_types::SolInterface,
};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::ITLSNotary::ITLSNotaryCalls;

impl Precompile for TLSNotary {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(
            calldata,
            ITLSNotaryCalls::abi_decode,
            |call| match call {
                ITLSNotaryCalls::verifyAttestation(call) => {
                    view(call, |c| self.verify_attestation(c))
                }
                ITLSNotaryCalls::registerAttestation(call) => {
                    mutate(call, msg_sender, |s, c| self.register_attestation(s, c))
                }
                ITLSNotaryCalls::getSession(call) => {
                    view(call, |c| self.get_session(c))
                }
                ITLSNotaryCalls::isProofRegistered(call) => {
                    view(call, |c| self.is_proof_registered(c))
                }
                ITLSNotaryCalls::getSessionId(call) => {
                    view(call, |c| {
                        Ok(TLSNotary::get_session_id(c.epoch, c.proofHash))
                    })
                }
            },
        )
    }
}
