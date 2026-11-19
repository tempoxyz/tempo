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
use secp256k1::{Message, PublicKey, SECP256K1, ecdsa::Signature};
use std::sync::{Arc, OnceLock};
use tempo_primitives::fuzz_crypto;

/// Whether this process accepts stand-ins, settled once by whichever comes first: [`enable`] or
/// the first execution ([`settle`]). So stand-ins can't switch on while an input runs, and
/// nothing can install evm2's default crypto before the providers here.
static MODE: OnceLock<bool> = OnceLock::new();

/// Installs the providers. With stand-ins off they check everything for real.
fn install() -> bool {
    let alloy = install_default_provider(Arc::new(StandIns)).is_ok();
    let evm = install_crypto(StandIns);
    alloy && evm
}

/// Makes the harness accept stand-ins, if nothing has executed yet. Returns whether it does.
pub(crate) fn enable() -> bool {
    *MODE.get_or_init(|| {
        let installed = install();
        if installed {
            fuzz_crypto::enable();
        }
        installed
    })
}

/// Settles the mode before an input executes: stand-ins stay off unless [`enable`] came first.
/// Unit tests run in one process in any order, so there stand-ins are always on.
pub(crate) fn settle() {
    if cfg!(test) {
        enable();
    } else {
        MODE.get_or_init(|| {
            install();
            false
        });
    }
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
        // Parse the key as alloy's own backend does, then accept its stand-in or a real signature.
        let key = PublicKey::from_slice(pubkey).map_err(RecoveryError::from_source)?;
        let signer = Address::from_raw_public_key(&key.serialize_uncompressed()[1..]);
        let (r, s) = sig.split_at(32);
        if fuzz_crypto::secp256k1_signer(r, s, msg) == Some(signer) {
            return Ok(signer);
        }
        let signature = Signature::from_compact(sig).map_err(RecoveryError::from_source)?;
        SECP256K1
            .verify_ecdsa(&Message::from_digest(*msg), &signature, &key)
            .map_err(RecoveryError::from_source)?;
        Ok(signer)
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
    use secp256k1::SecretKey;

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

    #[test]
    fn explicit_key_checks_parse_the_key_and_verify_real_signatures() {
        assert!(enable());
        let digest = B256::repeat_byte(7);
        let key = SecretKey::from_byte_array(&[0x11; 32]).unwrap();
        let mut pubkey = PublicKey::from_secret_key(SECP256K1, &key).serialize_uncompressed();
        let signer = Address::from_raw_public_key(&pubkey[1..]);

        let real = sign_message(B256::from(key.secret_bytes()), digest).unwrap();
        let real: [u8; 64] = real.as_bytes()[..64].try_into().unwrap();
        let (r, s) = fuzz_crypto::secp256k1(signer, &digest);
        let mut stand_in = [0; 64];
        stand_in[..32].copy_from_slice(&r.to_be_bytes::<32>());
        stand_in[32..].copy_from_slice(&s.to_be_bytes::<32>());
        for sig in [real, stand_in] {
            assert_eq!(
                StandIns
                    .verify_and_compute_signer_unchecked(&pubkey, &sig, &digest.0)
                    .ok(),
                Some(signer)
            );
            assert!(
                StandIns
                    .verify_and_compute_signer_unchecked(&pubkey, &sig, &[8; 32])
                    .is_err()
            );
        }
        pubkey[0] = 0x05;
        assert!(
            StandIns
                .verify_and_compute_signer_unchecked(&pubkey, &stand_in, &digest.0)
                .is_err(),
            "a key with a bad SEC1 prefix is rejected"
        );
    }
}
