//! Signature stand-ins ([`tempo_primitives::fuzz_crypto`]) for every signature check the harness runs.
//!
//! Tempo's own checks (P256, WebAuthn, Ed25519, P-384) accept stand-ins through their
//! `fuzz-crypto` feature. secp256k1 goes through two libraries instead, so this installs one
//! provider into each: alloy's, for transactions, fee payers, keychain, key and 7702
//! authorizations, permits and vouchers, and evm2's, for the ECRECOVER and P256VERIFY precompiles
//! and Ethereum 7702 authorities. Anything that is not a stand-in gets evm2's real check.

use alloy_consensus::crypto::{
    RecoveryError,
    backend::{CryptoProvider, install_default_provider},
};
use alloy_primitives::Address;
use evm2::precompiles::{Crypto, DefaultCrypto, PrecompileHalt, install_crypto};
use std::sync::{Arc, OnceLock};
use tempo_primitives::fuzz_crypto;

/// Makes the harness accept stand-ins from now on. Returns whether both providers are installed,
/// which fails only when something else installed one first.
pub(crate) fn enable() -> bool {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    *INSTALLED.get_or_init(|| {
        let alloy = install_default_provider(Arc::new(StandIns)).is_ok();
        let evm = install_crypto(StandIns);
        if alloy && evm {
            fuzz_crypto::enable();
        }
        alloy && evm
    })
}

/// Accepts secp256k1 and P256 stand-ins, and checks everything else for real.
#[derive(Debug)]
struct StandIns;

impl CryptoProvider for StandIns {
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let (rs, recid) = sig.split_at(64);
        let word = self
            .secp256k1_ecrecover(rs.try_into().expect("65 bytes"), recid[0], msg)
            .map_err(|_| RecoveryError::new())?;
        Ok(Address::from_word(word.into()))
    }

    fn verify_and_compute_signer_unchecked(
        &self,
        pubkey: &[u8; 65],
        sig: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        // A signature verifies under a key exactly when one of its recovery ids recovers that key.
        let signer = Address::from_raw_public_key(&pubkey[1..]);
        [0, 1]
            .into_iter()
            .filter_map(|recid| self.secp256k1_ecrecover(sig, recid, msg).ok())
            .any(|word| Address::from_word(word.into()) == signer)
            .then_some(signer)
            .ok_or_else(RecoveryError::new)
    }
}

impl Crypto for StandIns {
    fn secp256k1_ecrecover(
        &self,
        sig: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let (r, s) = sig.split_at(32);
        match fuzz_crypto::secp256k1_signer(r, s, msg).filter(|_| recid <= 1) {
            Some(signer) => Ok(signer.into_word().0),
            None => DefaultCrypto::new().secp256k1_ecrecover(sig, recid, msg),
        }
    }

    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        let ((r, s), (x, y)) = (sig.split_at(32), pk.split_at(32));
        fuzz_crypto::p256_accepts(r, s, x, y, msg)
            || DefaultCrypto::new().secp256r1_verify_signature(msg, sig, pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::crypto::secp256k1::{recover_signer, sign_message};
    use alloy_primitives::{B256, Signature, address, b256};

    #[test]
    fn stand_ins_recover_their_signer_and_real_signatures_still_do() {
        assert!(enable());
        let digest = B256::repeat_byte(7);
        let signer = Address::repeat_byte(9);
        let (r, s) = fuzz_crypto::secp256k1(signer, &digest);
        for parity in [false, true] {
            let signature = Signature::new(r, s, parity);
            assert_eq!(recover_signer(&signature, digest).ok(), Some(signer));
            assert_ne!(
                recover_signer(&signature, B256::repeat_byte(8)).ok(),
                Some(signer)
            );
        }

        // Dev account 0.
        let key = b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let real = sign_message(key, digest).unwrap();
        assert_eq!(
            recover_signer(&real, digest).ok(),
            Some(address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
        );
    }
}
