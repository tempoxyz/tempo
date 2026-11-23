//! When the harness turns mock signatures on, and evm2's view of them.

use alloy_consensus::crypto::secp256k1::recover_signer_unchecked;
use alloy_primitives::{B256, Signature};
use evm2::precompiles::{DefaultCrypto, PrecompileHalt, install_crypto};
use std::sync::OnceLock;
use tempo_primitives::crypto::mock;

/// Whether mocks are on, fixed by [`enable`] or the first execution, whichever comes first.
static MODE: OnceLock<bool> = OnceLock::new();

/// Turns mocks on unless an input already ran. Returns whether they are on.
pub(crate) fn enable() -> bool {
    *MODE.get_or_init(install)
}

/// Fixes the mode before an input runs, with mocks always on in unit tests.
pub(crate) fn settle() {
    MODE.get_or_init(|| cfg!(test) && install());
}

fn install() -> bool {
    install_crypto(EvmCrypto) && mock::install()
}

/// Mock-aware ECRECOVER and P256VERIFY for evm2.
#[derive(Debug)]
struct EvmCrypto;

impl evm2::precompiles::Crypto for EvmCrypto {
    fn secp256k1_ecrecover(
        &self,
        sig: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        // alloy's recovery goes through the mock-aware provider [`mock::install`] installs.
        (recid <= 1)
            .then(|| Signature::from_bytes_and_parity(sig, recid == 1))
            .and_then(|signature| recover_signer_unchecked(&signature, B256::from(*msg)).ok())
            .map(|signer| signer.into_word().0)
            .ok_or(PrecompileHalt::Secp256k1RecoverFailed)
    }

    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        let word = B256::from_slice;
        mock::verify_p256(
            &word(&sig[..32]),
            &word(&sig[32..]),
            &word(&pk[..32]),
            &word(&pk[32..]),
            &B256::from(*msg),
        ) || DefaultCrypto::new().secp256r1_verify_signature(msg, sig, pk)
    }
}
