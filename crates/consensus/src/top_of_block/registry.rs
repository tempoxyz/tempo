//! The registry of top-of-block operators, read from the `TopOfBlockRegistry`
//! contract.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};

use alloy_evm::Evm as _;
use alloy_primitives::{Address, B256, Bytes};
use alloy_sol_types::SolCall;
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::ordered;
use eyre::WrapErr as _;
use parking_lot::RwLock;
use reth_ethereum::evm::revm::{
    State, context::result::ExecutionResult, database::StateProviderDatabase,
};
use tempo_contracts::TopOfBlockRegistry;
use tempo_payload_types::TopOfBlockLimits;
use tracing::warn;

use crate::validators::ExecutionNode;

/// Operators allowed to submit to the top-of-block lane, and the lane window,
/// as read from the registry contract at one block.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    /// Time the builder waits for operators after opening the lane. Zero
    /// disables the lane.
    pub window: Duration,
    operators: HashMap<PublicKey, OperatorPolicy>,
}

/// What an operator may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorPolicy {
    /// The IP the operator connects from.
    pub ip: IpAddr,
    pub expires_at: Option<SystemTime>,
    pub limits: TopOfBlockLimits,
}

impl Registry {
    /// Reads the registry at `address` from the post-state of `block_hash`.
    pub(crate) fn read(
        node: impl ExecutionNode,
        block_hash: B256,
        address: Address,
    ) -> eyre::Result<Self> {
        let header = node.header(block_hash)?;
        let state = node.state_by_block_hash(block_hash)?;
        let db = State::builder()
            .with_database(StateProviderDatabase::new(state))
            .build();
        let mut evm = node.evm_for_block(db, &header)?;
        let mut call = |data: Vec<u8>| -> eyre::Result<Bytes> {
            match evm
                .transact_system_call(Address::ZERO, address, data.into())?
                .result
            {
                ExecutionResult::Success { output, .. } => Ok(output.into_data()),
                other => Err(eyre::eyre!("registry call did not succeed: {other:?}")),
            }
        };
        let window_ms = TopOfBlockRegistry::windowMsCall::abi_decode_returns(&call(
            TopOfBlockRegistry::windowMsCall {}.abi_encode(),
        )?)?;
        let operators = TopOfBlockRegistry::operatorsCall::abi_decode_returns(&call(
            TopOfBlockRegistry::operatorsCall {}.abi_encode(),
        )?)?;
        Ok(Self::from_contract(window_ms, operators))
    }

    /// Builds the registry from contract entries, skipping malformed ones.
    fn from_contract(window_ms: u64, entries: Vec<TopOfBlockRegistry::Operator>) -> Self {
        let mut operators = HashMap::new();
        for entry in entries {
            let key = PublicKey::decode(entry.publicKey.as_slice());
            let ip = entry.ip.parse::<IpAddr>();
            let (Ok(key), Ok(ip)) = (key, ip) else {
                warn!(
                    public_key = %entry.publicKey,
                    ip = entry.ip,
                    "skipping malformed top-of-block operator",
                );
                continue;
            };
            operators.insert(
                key,
                OperatorPolicy {
                    ip,
                    expires_at: (entry.expiresAt != 0)
                        .then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(entry.expiresAt)),
                    limits: TopOfBlockLimits {
                        max_txs: entry.maxTxsPerBlock as usize,
                        max_gas: entry.maxGasPerBlock,
                    },
                },
            );
        }
        Self {
            window: Duration::from_millis(window_ms),
            operators,
        }
    }

    /// Returns the policy of `operator` if its access has not expired at `now`.
    pub(crate) fn authorize(
        &self,
        operator: &PublicKey,
        now: SystemTime,
    ) -> Option<&OperatorPolicy> {
        self.operators
            .get(operator)
            .filter(|policy| policy.expires_at.is_none_or(|expiry| now < expiry))
    }

    /// Operators whose access has not expired at `now`.
    pub(crate) fn active(&self, now: SystemTime) -> Vec<PublicKey> {
        self.operators
            .keys()
            .filter(|key| self.authorize(key, now).is_some())
            .cloned()
            .collect()
    }

    /// All operators with the addresses they connect from.
    pub(crate) fn peers(&self) -> ordered::Map<PublicKey, commonware_p2p::Address> {
        ordered::Map::from_iter_dedup(self.operators.iter().map(|(key, policy)| {
            (
                key.clone(),
                commonware_p2p::Address::Symmetric(SocketAddr::new(policy.ip, 0)),
            )
        }))
    }
}

/// The latest registry, written by the peer manager whenever it reads
/// finalized state and read by the top-of-block actor.
#[derive(Clone, Debug, Default)]
pub struct RegistryHandle(Arc<RwLock<Arc<Registry>>>);

impl RegistryHandle {
    pub(crate) fn get(&self) -> Arc<Registry> {
        self.0.read().clone()
    }

    pub(crate) fn set(&self, registry: Registry) {
        *self.0.write() = Arc::new(registry);
    }
}

pub(super) fn parse_public_key(value: &str) -> eyre::Result<PublicKey> {
    let bytes = alloy_primitives::hex::decode(value.trim()).wrap_err("public key is not hex")?;
    PublicKey::decode(bytes.as_slice()).wrap_err("not an ed25519 public key")
}

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::*;

    fn entry(key: &PublicKey, ip: &str, expires_at: u64) -> TopOfBlockRegistry::Operator {
        TopOfBlockRegistry::Operator {
            publicKey: FixedBytes::from_slice(key.as_ref()),
            ip: ip.into(),
            expiresAt: expires_at,
            maxTxsPerBlock: 10,
            maxGasPerBlock: 1_000_000,
        }
    }

    #[test]
    fn expired_and_malformed_operators_are_not_authorized() {
        let key = PrivateKey::from_seed(1).public_key();
        let other = PrivateKey::from_seed(2).public_key();
        let registry = Registry::from_contract(
            100,
            vec![
                entry(&key, "127.0.0.1", 1000),
                entry(&other, "not an ip", 0),
            ],
        );
        let at = |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        assert_eq!(registry.window, Duration::from_millis(100));
        assert!(registry.authorize(&key, at(999)).is_some());
        assert!(registry.authorize(&key, at(1000)).is_none());
        assert!(registry.authorize(&other, at(0)).is_none());
        assert_eq!(registry.active(at(1000)), Vec::<PublicKey>::new());
        assert_eq!(registry.peers().len(), 1, "expired operators stay peers");
    }
}
