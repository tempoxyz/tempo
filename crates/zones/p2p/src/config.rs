use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_primitives::Address as EthereumAddress;
use alloy_signer_local::PrivateKeySigner;
use commonware_cryptography::ed25519::{PrivateKey, PublicKey};

use crate::{
    ZoneManifest,
    identity::{Ed25519Identity, Secp256k1Identity},
};

/// Fully validated configuration for one node's Zone P2P runtime.
#[derive(Clone)]
pub struct P2pConfig {
    zone_id: u32,
    manifest: Arc<ZoneManifest>,
    ed25519_identity: Ed25519Identity,
    /// Individual key registered with `ZonePortal`; signs and submits this node's settlements.
    secp256k1_identity: Secp256k1Identity,
    listen: SocketAddr,
    bypass_ip_check: bool,
    storage_directory: Option<PathBuf>,
}

impl P2pConfig {
    /// Loads the Commonware Ed25519 key, the individual secp256k1 key, and the manifest, then
    /// validates that both keys belong to the same manifest member. `zone_id` comes from the
    /// node's genesis configuration.
    pub fn load(
        manifest_path: impl AsRef<Path>,
        ed25519_key_path: impl AsRef<Path>,
        secp256k1_key_path: impl AsRef<Path>,
        listen: SocketAddr,
        bypass_ip_check: bool,
        zone_id: u32,
    ) -> eyre::Result<Self> {
        let ed25519_identity = Ed25519Identity::read_from_file(ed25519_key_path)?;
        let secp256k1_identity = Secp256k1Identity::read_from_file(secp256k1_key_path)?;
        let manifest = ZoneManifest::read_from_file(manifest_path)?;
        eyre::ensure!(
            !manifest.has_dns_addresses() || bypass_ip_check,
            "DNS peer addresses require --p2p.bypass-ip-check because their egress IPs are not known; this disables pre-authentication source-IP filtering for all inbound P2P connections"
        );
        manifest.validate_node(
            &ed25519_identity.ed25519_public_key(),
            secp256k1_identity.address(),
        )?;
        Ok(Self {
            zone_id,
            manifest: Arc::new(manifest),
            ed25519_identity,
            secp256k1_identity,
            listen,
            bypass_ip_check,
            storage_directory: None,
        })
    }

    /// The validated static topology manifest.
    pub fn manifest(&self) -> &Arc<ZoneManifest> {
        &self.manifest
    }

    /// This node's Ed25519 public key used by Commonware.
    pub fn ed25519_public_key(&self) -> PublicKey {
        self.ed25519_identity.ed25519_public_key()
    }

    /// This node's address derived from its individual secp256k1 key.
    pub fn secp256k1_address(&self) -> EthereumAddress {
        self.secp256k1_identity.address()
    }

    /// Signer for this node's L1 settlement transactions and attestations.
    pub fn l1_transaction_signer(&self) -> PrivateKeySigner {
        self.secp256k1_identity.signer()
    }

    /// Local socket bound by Commonware.
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Whether pre-authentication source-IP filtering is disabled.
    pub(crate) const fn bypass_ip_check(&self) -> bool {
        self.bypass_ip_check
    }

    /// Commonware runtime storage directory, when configured.
    pub(crate) fn storage_directory(&self) -> Option<&Path> {
        self.storage_directory.as_deref()
    }

    /// This node's Ed25519 private key, also its Simplex vote key.
    pub(crate) fn ed25519_private_key(&self) -> PrivateKey {
        self.ed25519_identity.clone().into_private_key()
    }

    /// Zone ID bound into the network namespace.
    pub fn zone_id(&self) -> u32 {
        self.zone_id
    }

    /// Sets the Commonware runtime's storage directory, including its startup lock file.
    /// Defaults to Commonware's temporary directory when not configured.
    pub fn with_storage_directory(mut self, directory: PathBuf) -> Self {
        self.storage_directory = Some(directory);
        self
    }
}

impl std::fmt::Debug for P2pConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pConfig")
            .field("zone_id", &self.zone_id)
            .field("ed25519_public_key", &self.ed25519_public_key())
            .field("secp256k1_address", &self.secp256k1_address())
            .field("listen", &self.listen)
            .field("bypass_ip_check", &self.bypass_ip_check)
            .finish_non_exhaustive()
    }
}
