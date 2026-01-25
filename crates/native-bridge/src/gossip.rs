//! P2P gossip for bridge partial signatures.
//!
//! Validators broadcast their partial signatures to other validators.
//! Once threshold signatures are collected, any validator can aggregate
//! and submit the threshold signature.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::attestation::PartialSignature;

/// A gossip message containing a partial signature and context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeGossipMessage {
    /// The attestation hash that was signed.
    pub attestation_hash: B256,
    /// The partial signature from this validator.
    pub partial: PartialSignature,
    /// Message context needed for aggregation.
    pub context: MessageContext,
}

/// Context about the message being attested.
/// Needed so receivers can reconstruct the full Message for aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContext {
    pub sender: Address,
    pub message_hash: B256,
    pub origin_chain_id: u64,
    pub destination_chain_id: u64,
}

impl BridgeGossipMessage {
    /// Create a new gossip message.
    pub fn new(attestation_hash: B256, partial: PartialSignature, context: MessageContext) -> Self {
        Self {
            attestation_hash,
            partial,
            context,
        }
    }

    /// Serialize to bytes for network transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialization should not fail")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl MessageContext {
    /// Create context from a Message.
    pub fn from_message(msg: &crate::message::Message) -> Self {
        Self {
            sender: msg.sender,
            message_hash: msg.message_hash,
            origin_chain_id: msg.origin_chain_id,
            destination_chain_id: msg.destination_chain_id,
        }
    }

    /// Reconstruct the Message from context.
    pub fn to_message(&self) -> crate::message::Message {
        crate::message::Message::new(
            self.sender,
            self.message_hash,
            self.origin_chain_id,
            self.destination_chain_id,
        )
    }
}

/// Trait for sending and receiving bridge gossip messages.
///
/// This abstracts the P2P layer so the bridge service doesn't depend
/// on specific networking implementation.
#[async_trait::async_trait]
pub trait BridgeGossip: Send + Sync {
    /// Broadcast a partial signature to all validators.
    async fn broadcast(&self, message: BridgeGossipMessage) -> crate::error::Result<()>;

    /// Receive the next gossip message from peers.
    /// Returns None if the channel is closed.
    async fn recv(&mut self) -> Option<BridgeGossipMessage>;
}

/// A no-op gossip implementation for single-validator mode.
///
/// Used when P2P gossip is not configured (e.g., testing or single validator).
pub struct NoOpGossip;

#[async_trait::async_trait]
impl BridgeGossip for NoOpGossip {
    async fn broadcast(&self, _message: BridgeGossipMessage) -> crate::error::Result<()> {
        Ok(())
    }

    async fn recv(&mut self) -> Option<BridgeGossipMessage> {
        std::future::pending().await
    }
}

/// P2P gossip implementation using commonware_p2p.
///
/// This adapter wraps the validator's P2P network channels to implement
/// the BridgeGossip trait.
pub mod p2p {
    use alloy_primitives::Bytes;
    use commonware_cryptography::ed25519::PublicKey;
    use commonware_p2p::{Receiver as P2pReceiver, Recipients, Sender as P2pSender};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use super::{BridgeGossip, BridgeGossipMessage};
    use crate::error::{BridgeError, Result};

    /// P2P gossip implementation that broadcasts to all validators.
    pub struct P2pGossip<S, R>
    where
        S: P2pSender<PublicKey = PublicKey>,
        R: P2pReceiver<PublicKey = PublicKey>,
    {
        sender: Arc<Mutex<S>>,
        receiver: Arc<Mutex<R>>,
    }

    impl<S, R> P2pGossip<S, R>
    where
        S: P2pSender<PublicKey = PublicKey>,
        R: P2pReceiver<PublicKey = PublicKey>,
    {
        /// Create a new P2P gossip adapter.
        pub fn new(sender: S, receiver: R) -> Self {
            Self {
                sender: Arc::new(Mutex::new(sender)),
                receiver: Arc::new(Mutex::new(receiver)),
            }
        }
    }

    #[async_trait::async_trait]
    impl<S, R> BridgeGossip for P2pGossip<S, R>
    where
        S: P2pSender<PublicKey = PublicKey> + Send,
        R: P2pReceiver<PublicKey = PublicKey> + Send,
    {
        async fn broadcast(&self, message: BridgeGossipMessage) -> Result<()> {
            let bytes: Bytes = message.to_bytes().into();

            self.sender
                .lock()
                .await
                .send(Recipients::All, bytes, true)
                .await
                .map_err(|e| BridgeError::Gossip(format!("broadcast failed: {e:?}")))?;

            tracing::trace!(
                hash = %message.attestation_hash,
                index = message.partial.index,
                "bridge: broadcasted partial to peers"
            );

            Ok(())
        }

        async fn recv(&mut self) -> Option<BridgeGossipMessage> {
            loop {
                let (sender_pk, payload) = self.receiver.lock().await.recv().await.ok()?;

                match BridgeGossipMessage::from_bytes(&payload) {
                    Ok(msg) => {
                        tracing::trace!(
                            from = %const_hex::encode(sender_pk.as_ref()),
                            hash = %msg.attestation_hash,
                            index = msg.partial.index,
                            "bridge: received partial from peer"
                        );
                        return Some(msg);
                    }
                    Err(e) => {
                        tracing::warn!(
                            from = %const_hex::encode(sender_pk.as_ref()),
                            error = %e,
                            "bridge: failed to deserialize gossip message"
                        );
                        // Continue to next message
                    }
                }
            }
        }
    }
}

pub use p2p::P2pGossip;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::G1_COMPRESSED_LEN;

    #[test]
    fn test_gossip_message_serialization() {
        let msg = BridgeGossipMessage {
            attestation_hash: B256::repeat_byte(0x42),
            partial: PartialSignature::new(1, [0xAB; G1_COMPRESSED_LEN]),
            context: MessageContext {
                sender: Address::repeat_byte(0x01),
                message_hash: B256::repeat_byte(0x02),
                origin_chain_id: 1,
                destination_chain_id: 12345,
            },
        };

        let bytes = msg.to_bytes();
        let decoded = BridgeGossipMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.attestation_hash, decoded.attestation_hash);
        assert_eq!(msg.partial.index, decoded.partial.index);
        assert_eq!(msg.partial.signature, decoded.partial.signature);
        assert_eq!(msg.context.sender, decoded.context.sender);
    }
}
