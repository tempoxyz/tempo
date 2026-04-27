use std::net::SocketAddr;

use eyre::{Context, ensure};
use reth_network_peers::pk2id;

/// Derive the enode URL from a 32-byte secp256k1 secret key.
///
/// The enode identifier is the uncompressed secp256k1 public key with the
/// leading 0x04 tag stripped (64 bytes = 128 hex characters).
#[derive(Debug, clap::Parser)]
pub(crate) struct EnodeFromSecret {
    /// 64-character hex string of the 32-byte secp256k1 secret key.
    ///
    /// May optionally start with "0x".
    #[arg(long)]
    secret_key: String,

    /// Optional socket address (ip:port) to produce the full enode URL.
    ///
    /// If omitted only the public key is printed.
    #[arg(long)]
    address: Option<SocketAddr>,
}

impl EnodeFromSecret {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let mut hex = self.secret_key.trim();
        hex = hex.strip_prefix("0x").unwrap_or(hex);
        hex = hex.strip_prefix("0X").unwrap_or(hex);

        ensure!(
            hex.len() == 64,
            "secret key must be exactly 64 hex characters (32 bytes), got {}",
            hex.len()
        );

        let bytes = const_hex::decode(hex).wrap_err("invalid hex string")?;

        let sk = secp256k1::SecretKey::from_slice(&bytes)
            .wrap_err("invalid secp256k1 secret key")?;
        let pk = sk.public_key(secp256k1::SECP256K1);
        let peer_id = pk2id(&pk);

        if let Some(addr) = self.address {
            println!("enode://{peer_id:x}@{addr}");
        } else {
            println!("{peer_id:x}");
        }
        Ok(())
    }
}
