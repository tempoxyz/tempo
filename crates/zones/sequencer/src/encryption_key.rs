//! Sequencer encryption-key registration on Tempo L1.

use alloy_network::ReceiptResponse as _;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_provider::Provider;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use tempo_alloy::TempoNetwork;
use tempo_contracts::zones::ZonePortal;

/// Proof of possession for a sequencer encryption public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionKeyProof {
    /// Compressed public-key X coordinate.
    pub x: B256,
    /// Canonical SEC1 compressed prefix (`0x02` or `0x03`).
    pub y_parity: u8,
    /// Ethereum address derived from the public key.
    pub address: Address,
    /// Recovery identifier (`v`) with the Ethereum `+ 27` offset.
    pub pop_v: u8,
    /// Signature `r`.
    pub pop_r: B256,
    /// Signature `s`.
    pub pop_s: B256,
}

/// Derive the compressed secp256k1 public identity for `signer`.
pub fn encryption_key_identity(signer: &PrivateKeySigner) -> eyre::Result<(B256, u8, Address)> {
    let encoded = signer.credential().verifying_key().to_encoded_point(true);
    let x = B256::from_slice(encoded.x().expect("compressed point has x").as_slice());
    let y_parity = encoded.as_bytes()[0];
    Ok((x, y_parity, signer.address()))
}

/// Sign a proof of possession over `(portal, x, yParity)` for `signer`.
pub fn prove_encryption_key_possession(
    portal: Address,
    signer: &PrivateKeySigner,
) -> eyre::Result<EncryptionKeyProof> {
    let (x, y_parity, address) = encryption_key_identity(signer)?;
    let message = keccak256((portal, x, U256::from(y_parity)).abi_encode());
    let signature = signer.sign_hash_sync(&message)?;
    Ok(EncryptionKeyProof {
        x,
        y_parity,
        address,
        pop_v: signature.v_byte(),
        pop_r: signature.r().into(),
        pop_s: signature.s().into(),
    })
}

/// Registers `signer` as the sequencer encryption key on `portal`.
///
/// Derives the secp256k1 public key, signs a proof-of-possession over
/// `(portal, x, yParity)`, and returns the registration transaction hash.
pub async fn register_encryption_key<P: Provider<TempoNetwork>>(
    provider: &P,
    portal: Address,
    signer: &PrivateKeySigner,
) -> eyre::Result<B256> {
    let proof = prove_encryption_key_possession(portal, signer)?;
    let receipt = ZonePortal::new(portal, provider)
        .setSequencerEncryptionKey(
            proof.x,
            proof.y_parity,
            proof.pop_v,
            proof.pop_r,
            proof.pop_s,
        )
        .max_fee_per_gas(crate::TEMPO_L1_MAX_FEE_PER_GAS)
        .max_priority_fee_per_gas(0)
        .send_sync()
        .await?;
    let tx_hash = receipt.transaction_hash();
    eyre::ensure!(
        receipt.status(),
        "setSequencerEncryptionKey reverted (tx: {tx_hash})"
    );
    Ok(tx_hash)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use alloy_signer_local::PrivateKeySigner;

    use super::{encryption_key_identity, prove_encryption_key_possession};

    #[test]
    fn proof_covers_the_derived_public_identity() {
        let signer = PrivateKeySigner::from_slice(&[0x11; 32]).unwrap();
        let portal = Address::repeat_byte(0x42);
        let (x, y_parity, address) = encryption_key_identity(&signer).unwrap();
        let proof = prove_encryption_key_possession(portal, &signer).unwrap();

        assert_eq!(proof.x, x);
        assert_eq!(proof.y_parity, y_parity);
        assert_eq!(proof.address, address);
        assert_eq!(proof.address, signer.address());
        assert!(proof.y_parity == 0x02 || proof.y_parity == 0x03);
        assert!(proof.pop_v == 27 || proof.pop_v == 28);
    }
}
