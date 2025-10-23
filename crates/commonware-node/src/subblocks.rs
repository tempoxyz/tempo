use crate::consensus::Supervisor;
use alloy_primitives::{BlockHash, map::HashMap};
use alloy_rlp::Decodable;
use commonware_codec::DecodeExt;
use commonware_consensus::{ThresholdSupervisor, Viewable, threshold_simplex::types::Activity};
use commonware_cryptography::{
    Signer, Verifier,
    bls12381::primitives::variant::MinSig,
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::Spawner;
use tempo_commonware_node_cryptography::Digest;
use tempo_payload_types::SignedSubBlock;
use tokio::sync::{mpsc, oneshot};

/// Actions processed by the subblocks service.
#[derive(Debug)]
enum Action {
    /// Returns all subblocks collected so far.
    ///
    /// This will return nothing if parent hash does not match the current chain view
    /// of the [`SubBlocksService`] or if no subblocks have been collected yet.
    GetSubBlocks {
        /// Parent block to return subblocks for.
        parent: BlockHash,
        /// Response channel.
        response: oneshot::Sender<Vec<SignedSubBlock>>,
    },
}

/// Task managing collected subblocks.
pub struct SubBlocksService {
    consensus_events: mpsc::UnboundedReceiver<Activity<MinSig, Digest>>,
    actions_rx: mpsc::UnboundedReceiver<Action>,

    supervisor: Supervisor,
    signer: PrivateKey,

    next_proposer: Option<PublicKey>,
    next_parent_hash: Option<BlockHash>,
    subblocks: HashMap<PublicKey, SignedSubBlock>,
}

impl SubBlocksService {
    pub fn new(
        signer: PrivateKey,
        supervisor: Supervisor,
        consensus_events: mpsc::UnboundedReceiver<Activity<MinSig, Digest>>,
    ) -> (Self, SubBlocksHandle) {
        let (actions_tx, actions_rx) = mpsc::unbounded_channel();
        let this = Self {
            consensus_events,
            actions_rx,
            supervisor,
            signer,
            next_proposer: None,
            next_parent_hash: None,
            subblocks: Default::default(),
        };

        (this, SubBlocksHandle { actions_tx })
    }
}

impl SubBlocksService {
    pub async fn run(
        mut self,
        (network_tx, mut network_rx): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        loop {
            tokio::select! {
                Some(Activity::Notarization(event)) = self.consensus_events.recv() => {
                    // On a notarization, we need to find who is the next proposer.
                    let Some(next_proposer) = self
                        .supervisor
                        .leader(event.view() + 1, event.seed_signature)
                    else {
                        continue;
                    };

                    // Clear older subblocks if we have a new parent.
                    if self
                        .next_parent_hash
                        .is_some_and(|hash| hash != event.proposal.payload.0)
                    {
                        self.subblocks.clear();
                    }

                    // Record next proposer and parent hash.
                    self.next_proposer = Some(next_proposer);
                    self.next_parent_hash = Some(event.proposal.payload.0);
                }
                Ok((sender, message)) = network_rx.recv() => {
                    let Ok(subblock) = SignedSubBlock::decode(&mut &*message) else {
                        continue;
                    };

                    let Ok(signature) = Signature::decode(&mut subblock.signature.as_ref()) else {
                        continue;
                    };

                    if !sender.verify(None, subblock.signature_hash().as_slice(), &signature) {
                        continue;
                    }

                    // Skip subblocks that are not built on top of the tip.
                    if self.next_parent_hash != Some(subblock.parent_hash) {
                        continue;
                    }

                    // Skip subblocks if we are not proposing
                    if self.next_proposer != Some(self.signer.public_key()) {
                        continue;
                    }

                    self.subblocks.insert(sender, subblock);
                }
                Some(action) = self.actions_rx.recv() => {
                    match action {
                        Action::GetSubBlocks { parent, response } => {
                            // This should never happen, but just in case.
                            if self.next_parent_hash != Some(parent) {
                                let _ = response.send(Vec::new());
                                continue;
                            }
                            // Return all subblocks for the next proposer.
                            let subblocks = self.subblocks.values().cloned().collect();
                            let _ = response.send(subblocks);
                        }
                    }
                }
            }
        }
    }
}

/// Handle to the spawned subblocks service.
#[derive(Clone)]
pub struct SubBlocksHandle {
    actions_tx: mpsc::UnboundedSender<Action>,
}

impl SubBlocksHandle {
    pub fn get_subblocks(&self, parent: BlockHash) -> oneshot::Receiver<Vec<SignedSubBlock>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.actions_tx.send(Action::GetSubBlocks {
            parent,
            response: tx,
        });
        rx
    }
}
