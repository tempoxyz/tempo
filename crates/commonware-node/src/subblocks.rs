use crate::{consensus::Digest, epoch::SchemeProvider};
use alloy_consensus::Transaction;
use alloy_primitives::{B256, BlockHash, Bytes, map::HashMap};
use alloy_rlp::Decodable;
use commonware_codec::DecodeExt;
use commonware_consensus::{
    Epochable, Reporter,
    marshal::SchemeProvider as _,
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
use reth_provider::{BlockReader, ProviderError, StateProviderBox, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use tempo_node::{TempoFullNode, consensus::TEMPO_SHARED_GAS_DIVISOR, evm::evm::TempoEvm};
use tempo_payload_types::{RecoveredSubBlock, SignedSubBlock, SubBlock, SubBlockVersion};
use tempo_primitives::TempoTxEnvelope;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

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
        response: oneshot::Sender<Vec<RecoveredSubBlock>>,
    },

    /// Sends a new transaction to the subblocks service.
    AddTransaction(Box<TempoTxEnvelope>),

    /// Reports a new consensus event.
    Consensus(Box<Activity<Scheme<PublicKey, MinSig>, Digest>>),
}

/// Task managing collected subblocks.
pub struct SubBlocksService<Ctx> {
    actions_rx: mpsc::UnboundedReceiver<Message>,
    scheme_provider: SchemeProvider,
    subblock_builder_handle: Option<Handle<RecoveredSubBlock>>,
    validated_subblocks_tx: mpsc::UnboundedSender<RecoveredSubBlock>,
    validated_subblocks_rx: mpsc::UnboundedReceiver<RecoveredSubBlock>,

    context: Ctx,
    signer: PrivateKey,

    next_proposer: Option<PublicKey>,
    next_parent_hash: Option<BlockHash>,
    subblocks: HashMap<B256, RecoveredSubBlock>,
    subblock_transactions: Vec<TempoTxEnvelope>,
    node: TempoFullNode,
}

impl<Ctx: Spawner> SubBlocksService<Ctx> {
    pub(crate) fn new(
        context: Ctx,
        signer: PrivateKey,
        scheme_provider: SchemeProvider,
        node: TempoFullNode,
    ) -> (Self, SubBlocksHandle) {
        let (actions_tx, actions_rx) = mpsc::unbounded_channel();
        let (validated_subblocks_tx, validated_subblocks_rx) = mpsc::unbounded_channel();
        let this = Self {
            subblock_builder_handle: None,
            validated_subblocks_rx,
            validated_subblocks_tx,
            scheme_provider,
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

    fn on_new_message(&mut self, action: Message) {
        match action {
            Message::GetSubBlocks { parent, response } => {
                // This should never happen, but just in case.
                if self.next_parent_hash != Some(parent) {
                    let _ = response.send(Vec::new());
                    return;
                }
                // Return all subblocks we've collected for this block.
                let subblocks = self.subblocks.values().cloned().collect();
                let _ = response.send(subblocks);
            }
            Message::AddTransaction(transaction) => {
                if !transaction
                    .subblock_proposer()
                    .is_some_and(|k| k.matches(self.signer.public_key()))
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

    fn on_new_notarization(&mut self, event: Notarization<Scheme<PublicKey, MinSig>, Digest>) {
        let epoch = event.epoch();

        let Some(scheme) = self.scheme_provider.scheme(epoch) else {
            return;
        };

        let Some(seed) = scheme.seed(event.proposal.round, &event.certificate) else {
            return;
        };

        let leader_idx = select_leader::<Scheme<PublicKey, MinSig>, _>(
            scheme.participants().as_ref(),
            Round::new(epoch, event.proposal.round.view() + 1),
            Some(seed),
        );

        let Some(next_proposer) = scheme.participants().get(leader_idx as usize).cloned() else {
            return;
        };

        // Clear older subblocks if we have a new parent.
        if self
            .next_parent_hash
            .is_some_and(|hash| hash != event.proposal.payload.0)
        {
            self.subblocks.clear();
        }

        let num_validators = scheme.participants().len();

        // Record next proposer and parent hash.
        self.next_proposer = Some(next_proposer.clone());
        self.next_parent_hash = Some(event.proposal.payload.0);

        if let Some(existing) = self.subblock_builder_handle.take() {
            existing.abort();
        }

        let transactions = self.subblock_transactions.clone();
        let node = self.node.clone();
        let parent_hash = event.proposal.payload.0;
        let signer = self.signer.clone();
        let handle = self.context.clone().shared(true).spawn(move |_| {
            build_subblock(transactions, node, parent_hash, num_validators, signer)
        });

        self.subblock_builder_handle = Some(handle);
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
                // First, handle messages from consensus engine and handle.
                Some(action) = self.actions_rx.recv() => {
                    self.on_new_message(action);
                }
                // Handle messages from the network.
                Ok((sender, message)) = network_rx.recv() => {
                    let Ok(subblock) = SignedSubBlock::decode(&mut &*message) else {
                        continue;
                    };

                    let Some(next_parent_hash) = self.next_parent_hash else {
                        continue;
                    };

                    // Skip subblocks that are not built on top of the tip.
                    if next_parent_hash != subblock.parent_hash {
                        continue;
                    }

                    // Skip subblocks if we are not proposing
                    if self.next_proposer != Some(self.signer.public_key()) {
                        continue;
                    }

                    // Spawn task to validate the subblock.
                    let node = self.node.clone();
                    let validated_subblocks_tx = self.validated_subblocks_tx.clone();
                    self.context.clone().shared(true).spawn(move |_| async move {
                        if let Err(err) = validate_subblock(sender.clone(), node, subblock, next_parent_hash, validated_subblocks_tx).await {
                            warn!(
                                %sender,
                                %err,
                                "received invalid subblock"
                            );
                        }
                    });
                }
                // Handle validated subblocks.
                Some(subblock) = self.validated_subblocks_rx.recv() => {
                    // SKip subblock if we are already past its parent
                    if Some(subblock.parent_hash) != self.next_parent_hash {
                        return;
                    }

                    debug!(subblock = ?subblock, "validated subblock");

                    self.subblocks.insert(subblock.validator(), subblock);
                }
                // Handle built subblocks.
                Some(subblock) = OptionFuture::from(self.subblock_builder_handle.as_mut()) => {
                    self.subblock_builder_handle = None;

                    debug!(?subblock, "built subblock");

                    let Some(next_parent_hash) = self.next_parent_hash else {
                        continue;
                    };
                    let Some(next_proposer) = &self.next_proposer else {
                        continue;
                    };

                    let subblock = match subblock {
                        Ok(subblock) => subblock,
                        Err(err) => {
                            warn!(%err, "failed to build subblock, skipping");
                            continue;
                        }
                    };

                    if subblock.parent_hash != next_parent_hash {
                        continue;
                    }

                    debug!(?subblock, ?next_proposer, "sending subblock to the next proposer");
                    if next_proposer != &self.signer.public_key() {
                        let _ = network_tx.send(Recipients::One(next_proposer.clone()), alloy_rlp::encode(&*subblock).into(), true).await;
                    } else {
                        let _ = self.validated_subblocks_tx.send(subblock);
                    }

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
    pub fn get_subblocks(&self, parent: BlockHash) -> oneshot::Receiver<Vec<RecoveredSubBlock>> {
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
    type Activity = Activity<Scheme<PublicKey, MinSig>, Digest>;

    async fn report(&mut self, activity: Self::Activity) -> () {
        let _ = self.tx.send(Message::Consensus(Box::new(activity)));
    }
}

fn evm_at_block(
    node: &TempoFullNode,
    hash: BlockHash,
) -> eyre::Result<TempoEvm<State<StateProviderDatabase<StateProviderBox>>>> {
    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.provider.state_by_block_hash(hash)?,
        ))
        .build();
    let block = node
        .provider
        .sealed_block_with_senders(hash.into(), Default::default())?
        .ok_or(ProviderError::BestBlockNotFound)?;

    Ok(node.evm_config.evm_for_block(db, block.sealed_block())?)
}

async fn build_subblock(
    transactions: Vec<TempoTxEnvelope>,
    node: TempoFullNode,
    parent_hash: BlockHash,
    num_validators: usize,
    signer: PrivateKey,
) -> RecoveredSubBlock {
    let (transactions, senders) = match evm_at_block(&node, parent_hash) {
        Ok(mut evm) => {
            let mut selected_transactions = Vec::new();
            let mut senders = Vec::new();
            let mut gas_left =
                evm.block().gas_limit / TEMPO_SHARED_GAS_DIVISOR / num_validators as u64;

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
                gas_left -= tx.gas_limit();
                selected_transactions.push(tx);
                senders.push(sender);
            }

            (selected_transactions, senders)
        }
        Err(err) => {
            warn!(%err, "failed to build an evm at block, building an empty subblock");

            Default::default()
        }
    };

    let subblock = SubBlock {
        version: SubBlockVersion::V1,
        parent_hash,
        transactions,
    };

    let signature = signer.sign(None, subblock.signature_hash().as_slice());
    let signed_subblock = SignedSubBlock {
        inner: subblock,
        signature: Bytes::copy_from_slice(signature.as_ref()),
    };

    RecoveredSubBlock::new_unchecked(
        signed_subblock,
        senders,
        B256::from_slice(&signer.public_key()),
    )
}

async fn validate_subblock(
    sender: PublicKey,
    node: TempoFullNode,
    subblock: SignedSubBlock,
    parent_hash: BlockHash,
    validated_subblocks_tx: mpsc::UnboundedSender<RecoveredSubBlock>,
) -> eyre::Result<()> {
    let Ok(signature) = Signature::decode(&mut subblock.signature.as_ref()) else {
        return Err(eyre::eyre!("invalid signature"));
    };

    if !sender.verify(None, subblock.signature_hash().as_slice(), &signature) {
        return Err(eyre::eyre!("invalid signature"));
    }

    if subblock.transactions.iter().any(|tx| {
        tx.subblock_proposer()
            .is_none_or(|proposer| !proposer.matches(&sender))
    }) {
        return Err(eyre::eyre!(
            "all transactions must specify the subblock validator"
        ));
    }

    let subblock = subblock.try_into_recovered(B256::from_slice(&sender))?;

    let mut evm = evm_at_block(&node, parent_hash)?;

    for tx in subblock.transactions_recovered() {
        if let Err(err) = evm.transact_commit(tx) {
            return Err(eyre::eyre!("transaction failed to execute: {err:?}"));
        }
    }

    let _ = validated_subblocks_tx.send(subblock);

    Ok(())
}
