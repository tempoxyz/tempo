//! ED25519 key generation for ceremony participation.

use commonware_codec::Encode;
use commonware_cryptography::{PrivateKeyExt, Signer, ed25519::PrivateKey};
use std::path::PathBuf;
use tempo_commonware_node_config::SigningKey;

use crate::error::Error;

/// Arguments for the keygen command.
pub struct KeygenArgs {
    /// Output directory for key files.
    pub output_dir: PathBuf,
    /// Overwrite existing key files.
    pub force: bool,
}

/// Generate a new keypair, returning (private_key, public_key_hex).
fn generate() -> (PrivateKey, String) {
    let private_key = PrivateKey::from_rng(&mut rand::thread_rng());
    let public_key = private_key.public_key();
    let public_hex = const_hex::encode_prefixed(public_key.encode().as_ref());
    (private_key, public_hex)
}

/// Run the keygen command.
pub fn run(args: KeygenArgs) -> eyre::Result<()> {
    std::fs::create_dir_all(&args.output_dir)?;

    let private_key_path = args.output_dir.join("identity-private.hex");
    let public_key_path = args.output_dir.join("identity-public.hex");

    if !args.force && (private_key_path.exists() || public_key_path.exists()) {
        return Err(Error::KeysAlreadyExist.into());
    }

    let (private_key, public_hex) = generate();

    SigningKey::from(private_key).write_to_file(&private_key_path)?;
    std::fs::write(&public_key_path, &public_hex)?;

    println!("Key generation complete!");
    println!();
    println!("Public key: {public_hex}");
    println!();
    println!("Share your public key with the ceremony coordinator.");
    println!("Keep identity-private.hex SECURE - you will need it for the ceremony.");

    Ok(())
}
