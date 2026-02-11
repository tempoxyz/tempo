use crate::{
    Precompile, dispatch_call, input_cost, metadata, mutate, mutate_void, view,
    tls_notary::TLSNotary,
};
use alloy::{
    primitives::Address,
    sol_types::SolInterface,
};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::ITLSNotary;
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
                // Notary management
                ITLSNotaryCalls::addNotary(call) => {
                    mutate_void(call, msg_sender, |s, c| self.add_notary(s, c))
                }
                ITLSNotaryCalls::removeNotary(call) => {
                    mutate_void(call, msg_sender, |s, c| self.remove_notary(s, c))
                }
                ITLSNotaryCalls::isNotary(call) => {
                    view(call, |c| self.is_notary(c))
                }
                ITLSNotaryCalls::owner(_) => {
                    metadata::<ITLSNotary::ownerCall>(|| self.owner())
                }
                ITLSNotaryCalls::transferOwnership(call) => {
                    mutate_void(call, msg_sender, |s, c| self.transfer_ownership(s, c))
                }
                // Attestations
                ITLSNotaryCalls::registerAttestation(call) => {
                    mutate(call, msg_sender, |s, c| self.register_attestation(s, c))
                }
                // Email claims
                ITLSNotaryCalls::claimEmail(call) => {
                    mutate(call, msg_sender, |s, c| self.claim_email(s, c))
                }
                ITLSNotaryCalls::emailOwner(call) => {
                    view(call, |c| self.email_owner(c))
                }
                // Queries
                ITLSNotaryCalls::getSession(call) => {
                    view(call, |c| self.get_session(c))
                }
                ITLSNotaryCalls::isProofRegistered(call) => {
                    view(call, |c| self.is_proof_registered(c))
                }
            },
        )
    }
}
