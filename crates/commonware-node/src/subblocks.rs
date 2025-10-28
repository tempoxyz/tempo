use crate::{consensus::Digest, epoch::manager::EpochContext};
use alloy_consensus::{BlockHeader, Transaction};
use alloy_primitives::{BlockHash, Bytes, map::HashMap};
use alloy_rlp::Decodable;
use commonware_codec::DecodeExt;
use commonware_consensus::{
    Reporter,
    simplex::{
        select_leader,
        signing_scheme::{Scheme as _, bls12381_threshold::Scheme},
        types::{Activity, Notarization},
    },
    types::Round,
};
use commonware_cryptography::{
    Signer, Verifier,
    bls12381::primitives::variant::MinSig,
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use futures::future::OptionFuture;
use reth_evm::{Evm, revm::database::State};
use reth_node_builder::ConfigureEvm;
use reth_primitives_traits::SignedTransaction;
use reth_provider::{BlockReader, ProviderError, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use tempo_node::{TempoFullNode, consensus::TEMPO_SHARED_GAS_DIVISOR};
use tempo_payload_types::{SignedSubBlock, SubBlock};
use tempo_primitives::TempoTxEnvelope;
use tokio::sync::{mpsc, oneshot, watch};

/// Actions processed by the subblocks service.
#[derive(Debug)]
enum Message {
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

    /// Sends a new transaction to the subblocks service.
    AddTransaction(Box<TempoTxEnvelope>),

    /// Reports a new consensus event.
    Consensus(Box<Activity<Scheme<MinSig>, Digest>>),
}

/// Task managing collected subblocks.
pub struct SubBlocksService<Ctx> {
    actions_rx: mpsc::UnboundedReceiver<Message>,
    epoch_context_rx: watch::Receiver<Option<EpochContext>>,
    subblock_builder_handle: Option<Handle<eyre::Result<SubBlock>>>,

    context: Ctx,
    signer: PrivateKey,

    next_proposer: Option<PublicKey>,
    next_parent_hash: Option<BlockHash>,
    subblocks: HashMap<PublicKey, SignedSubBlock>,
    subblock_transactions: Vec<TempoTxEnvelope>,
    node: TempoFullNode,
}

impl<Ctx: Spawner> SubBlocksService<Ctx> {
    pub(crate) fn new(
        context: Ctx,
        signer: PrivateKey,
        epoch_context_rx: watch::Receiver<Option<EpochContext>>,
        node: TempoFullNode,
    ) -> (Self, SubBlocksHandle) {
        let (actions_tx, actions_rx) = mpsc::unbounded_channel();
        let this = Self {
            subblock_builder_handle: None,
            epoch_context_rx,
            actions_rx,
            context,
            signer,
            node,
            next_proposer: None,
            next_parent_hash: None,
            subblocks: Default::default(),
            subblock_transactions: Default::default(),
        };

        (this, SubBlocksHandle { tx: actions_tx })
    }

    fn on_new_notarization(&mut self, event: Notarization<Scheme<MinSig>, Digest>) {
        let epoch_context = self.epoch_context_rx.borrow();
        let Some(EpochContext {
            epoch,
            participants,
            scheme,
        }) = epoch_context.as_ref()
        else {
            return;
        };

        // Find out who is the next proposer
        if epoch != &event.proposal.round.epoch() {
            return;
        }

        let Some(seed) = scheme.seed(event.proposal.round, &event.certificate) else {
            return;
        };

        let leader_idx = select_leader::<Scheme<MinSig>, _>(
            participants.as_ref(),
            Round::new(*epoch, event.proposal.round.view() + 1),
            Some(seed),
        );

        let Some(next_proposer) = participants.get(leader_idx as usize).cloned() else {
            return;
        };

        // Clear older subblocks if we have a new parent.
        if self
            .next_parent_hash
            .is_some_and(|hash| hash != event.proposal.payload.0)
        {
            self.subblocks.clear();
        }

        let num_validators = participants.len();

        // Record next proposer and parent hash.
        self.next_proposer = Some(next_proposer.clone());
        self.next_parent_hash = Some(event.proposal.payload.0);

        // If next proposer is not us, we need to build a new subblock.
        if next_proposer != self.signer.public_key() {
            if let Some(existing) = self.subblock_builder_handle.take() {
                existing.abort();
            }

            let transactions = self.subblock_transactions.clone();
            let node = self.node.clone();
            let parent_hash = event.proposal.payload.0;
            let handle =
                self.context.clone().shared(true).spawn(move |_| {
                    build_subblock(transactions, node, parent_hash, num_validators)
                });

            self.subblock_builder_handle = Some(handle);
        }
    }

    fn on_new_action(&mut self, action: Message) {
        match action {
            Message::GetSubBlocks { parent, response } => {
                // This should never happen, but just in case.
                if self.next_parent_hash != Some(parent) {
                    let _ = response.send(Vec::new());
                    return;
                }
                // Return all subblocks for the next proposer.
                let subblocks = self.subblocks.values().cloned().collect();
                let _ = response.send(subblocks);
            }
            Message::AddTransaction(transaction) => {
                if transaction.subblock_proposer().as_ref().map(|v| v.as_ref())
                    != Some(self.signer.public_key().as_ref())
                {
                    return;
                }
                self.subblock_transactions.push(*transaction);
            }
            Message::Consensus(activity) => {
                if let Activity::Notarization(event) = *activity {
                    self.on_new_notarization(event);
                }
            }
        }
    }
}

impl<Ctx: Spawner> SubBlocksService<Ctx> {
    pub async fn run(
        mut self,
        (mut network_tx, mut network_rx): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        loop {
            tokio::select! {
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
                    self.on_new_action(action);
                }
                Some(our_subblock) = OptionFuture::from(self.subblock_builder_handle.as_mut()) => {
                    self.subblock_builder_handle = None;

                    let Some(next_parent_hash) = self.next_parent_hash else {
                        continue;
                    };
                    let Some(next_proposer) = &self.next_proposer else {
                        continue;
                    };

                    let subblock = if let Ok(Ok(subblock)) = our_subblock {
                        subblock
                    } else {
                        SubBlock { parent_hash: next_parent_hash, transactions: Default::default() }
                    };

                    if subblock.parent_hash != next_parent_hash {
                        continue;
                    }

                    let signature = self.signer.sign(None, subblock.signature_hash().as_slice());
                    let signed_subblock = SignedSubBlock {
                        inner: subblock,
                        signature: Bytes::copy_from_slice(signature.as_ref()),
                    };

                    let _ = network_tx.send(Recipients::One(next_proposer.clone()), alloy_rlp::encode(&signed_subblock).into(), true).await;
                }
            }
        }
    }
}

/// Handle to the spawned subblocks service.
#[derive(Clone)]
pub struct SubBlocksHandle {
    tx: mpsc::UnboundedSender<Message>,
}

impl SubBlocksHandle {
    pub fn get_subblocks(&self, parent: BlockHash) -> oneshot::Receiver<Vec<SignedSubBlock>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(Message::GetSubBlocks {
            parent,
            response: tx,
        });
        rx
    }

    pub fn add_transaction(&self, tx: TempoTxEnvelope) {
        let _ = self.tx.send(Message::AddTransaction(tx.into()));
    }
}

impl Reporter for SubBlocksHandle {
    type Activity = Activity<Scheme<MinSig>, Digest>;

    async fn report(&mut self, activity: Self::Activity) -> () {
        let _ = self.tx.send(Message::Consensus(Box::new(activity)));
    }
}

async fn build_subblock(
    transactions: Vec<TempoTxEnvelope>,
    node: TempoFullNode,
    parent_hash: BlockHash,
    num_validators: usize,
) -> eyre::Result<SubBlock> {
    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.provider.state_by_block_hash(parent_hash)?,
        ))
        .build();
    let block = node
        .provider
        .sealed_block_with_senders(parent_hash.into(), Default::default())?
        .ok_or(ProviderError::BestBlockNotFound)?;

    let mut evm = node.evm_config.evm_for_block(db, block.sealed_block())?;

    let mut selected_transactions = Vec::new();
    let mut gas_left = block.gas_limit() / TEMPO_SHARED_GAS_DIVISOR / num_validators as u64;
    for tx in transactions {
        if tx.gas_limit() > gas_left {
            continue;
        }
        let Ok(sender) = tx.try_recover() else {
            continue;
        };
        if evm.transact_commit(tx.with_signer_ref(sender)).is_err() {
            continue;
        }
        selected_transactions.push(tx.clone());
        gas_left -= tx.gas_limit();
    }

    Ok(SubBlock {
        parent_hash,
        transactions: selected_transactions,
    })
}
