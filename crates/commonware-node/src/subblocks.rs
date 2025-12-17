use crate::{consensus::Digest, epoch::SchemeProvider};
use alloy_consensus::{BlockHeader, Transaction, transaction::TxHashRef};
use alloy_primitives::{Address, B256, BlockHash, Bytes, TxHash};
use alloy_rlp::Decodable;
use commonware_codec::DecodeExt;
use commonware_consensus::{
    Epochable, Reporter, Viewable,
    marshal::SchemeProvider as _,
    simplex::{
        select_leader,
        signing_scheme::{
            Scheme as _,
            bls12381_threshold::{self, Scheme},
        },
        types::Activity,
    },
    types::{Round, View},
    utils,
};
use commonware_cryptography::{
    Signer, Verifier,
    bls12381::primitives::variant::MinSig,
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Metrics, Pacer, Spawner};
use eyre::{Context, OptionExt};
use futures::{FutureExt as _, StreamExt, channel::mpsc};
use indexmap::IndexMap;
use parking_lot::Mutex;
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_evm::{Evm, revm::database::State};
use reth_node_builder::ConfigureEvm;
use reth_primitives_traits::Recovered;
use reth_provider::{
    BlockReader, BlockSource, ProviderError, StateProviderBox, StateProviderFactory,
};
use reth_revm::database::StateProviderDatabase;
use std::{
    pin::Pin,
    sync::{Arc, mpsc::RecvError},
    time::{Duration, Instant},
};
use tempo_node::{TempoFullNode, consensus::TEMPO_SHARED_GAS_DIVISOR, evm::evm::TempoEvm};
use tempo_primitives::{
    RecoveredSubBlock, SignedSubBlock, SubBlock, SubBlockVersion, TempoTxEnvelope,
};
use tokio::sync::broadcast;
use tracing::{Instrument, Level, Span, debug, instrument, warn};

/// Maximum number of stored subblock transactions. Used to prevent DOS attacks.
///
/// NOTE: included txs are organically cleared when building the next subblock
/// because they become invalid once their nonce is used.
const MAX_SUBBLOCK_TXS: usize = 100_000;

pub(crate) struct Config<TContext> {
    pub(crate) context: TContext,
    pub(crate) signer: PrivateKey,
    pub(crate) scheme_provider: SchemeProvider,
    pub(crate) node: TempoFullNode,
    pub(crate) fee_recipient: Address,
    pub(crate) time_to_build_subblock: Duration,
    pub(crate) subblock_broadcast_interval: Duration,
    pub(crate) epoch_length: u64,
}

/// Task managing collected subblocks.
///
/// This actor is responsible for tracking consensus events and determining
/// current tip of the chain and next block's proposer.
///
/// Once next block proposer is known, we immediately start building a new subblock.
/// Once it's built, we broadcast it to the next proposer directly.
///
/// Upon receiving a subblock from the network, we ensure that we are
/// the proposer and verify the block on top of latest state.
pub(crate) struct Actor<TContext> {
    /// Sender of messages to the service.
    actions_tx: mpsc::UnboundedSender<Message>,
    /// Receiver of events to the service.
    actions_rx: mpsc::UnboundedReceiver<Message>,
    /// Stream of subblock transactions from RPC.
    subblock_transactions_rx: broadcast::Receiver<Recovered<TempoTxEnvelope>>,
    /// Handle to a task building a new subblock.
    our_subblock: PendingSubblock,

    /// Scheme provider to track participants of each epoch.
    scheme_provider: SchemeProvider,
    /// Commonware runtime context.
    context: TContext,
    /// ed25519 private key used for consensus.
    signer: PrivateKey,
    /// Execution layer node.
    node: TempoFullNode,
    /// Fee recipient address to set for subblocks.
    fee_recipient: Address,
    /// Timeout for building a subblock.
    time_to_build_subblock: Duration,
    /// How often to broadcast subblocks to the current proposer.
    subblock_broadcast_interval: Duration,
    /// Length of an epoch in blocks.
    epoch_length: u64,

    /// Current consensus tip. Includes highest observed round, digest and certificate.
    consensus_tip: Option<(Round, BlockHash, bls12381_threshold::Signature<MinSig>)>,

    /// Collected subblocks keyed by validator public key.
    subblocks: IndexMap<B256, RecoveredSubBlock>,
    /// Subblock candidate transactions.
    subblock_transactions: Arc<Mutex<IndexMap<TxHash, Arc<Recovered<TempoTxEnvelope>>>>>,
}

impl<TContext: Spawner + Metrics + Pacer> Actor<TContext> {
    pub(crate) fn new(
        Config {
            context,
            signer,
            scheme_provider,
            node,
            fee_recipient,
            time_to_build_subblock,
            subblock_broadcast_interval,
            epoch_length,
        }: Config<TContext>,
    ) -> Self {
        let (actions_tx, actions_rx) = mpsc::unbounded();
        Self {
            our_subblock: PendingSubblock::None,
            subblock_transactions_rx: node.add_ons_handle.eth_api().subblock_transactions_rx(),
            scheme_provider,
            actions_tx,
            actions_rx,
            context,
            signer,
            node,
            fee_recipient,
            time_to_build_subblock,
            subblock_broadcast_interval,
            epoch_length,
            consensus_tip: None,
            subblocks: Default::default(),
            subblock_transactions: Default::default(),
        }
    }

    /// Returns a handle to the subblocks service.
    pub(crate) fn mailbox(&self) -> Mailbox {
        Mailbox {
            tx: self.actions_tx.clone(),
        }
    }

    pub(crate) async fn run(
        mut self,
        (mut network_tx, mut network_rx): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        loop {
            let (subblock_task, broadcast_interval) = match &mut self.our_subblock {
                PendingSubblock::None => (None, None),
                PendingSubblock::Task(task) => (Some(task), None),
                PendingSubblock::Built(built) => (None, Some(&mut built.broadcast_interval)),
            };

            tokio::select! {
                biased;

                // Handle messages from consensus engine and service handle.
                Some(action) = self.actions_rx.next() => {
                    self.on_new_message(action);
                },
                // Handle new subblock transactions.
                Ok(transaction) = self.subblock_transactions_rx.recv() => {
                    self.on_new_subblock_transaction(transaction);
                },
                // Handle messages from the network.
                Ok((sender, message)) = network_rx.recv() => {
                    let _ = self.on_network_message(sender, message, &mut network_tx).await;
                },
                // Handle built subblocks.
                subblock = if let Some(task) = subblock_task {
                    (&mut task.handle).fuse()
                } else {
                    futures::future::Fuse::terminated()
                } => {
                    let task = self.our_subblock.take_task().unwrap();
                    self.on_built_subblock(subblock, task.proposer).await;
                }
                // Handle subblocks broadcast.
                _ = if let Some(broadcast_interval) = broadcast_interval {
                    broadcast_interval.fuse()
                } else {
                    futures::future::Fuse::terminated()
                } => {
                    self.broadcast_built_subblock(&mut network_tx).await;
                }
            }
        }
    }

    /// Returns the current consensus tip.
    fn tip(&self) -> Option<BlockHash> {
        self.consensus_tip.as_ref().map(|(_, tip, _)| *tip)
    }

    fn on_new_message(&mut self, action: Message) {
        match action {
            Message::GetSubBlocks { parent, response } => {
                // This should never happen, but just in case.
                if self.tip() != Some(parent) {
                    let _ = response.send(Vec::new());
                    return;
                }
                // Return all subblocks we've collected for this block.
                let subblocks = self.subblocks.values().cloned().collect();
                let _ = response.send(subblocks);
            }
            Message::Consensus(activity) => self.on_consensus_event(*activity),
            Message::ValidatedSubblock(subblock) => self.on_validated_subblock(subblock),
        }
    }

    #[instrument(skip_all, fields(transaction.tx_hash = %transaction.tx_hash()))]
    fn on_new_subblock_transaction(&self, transaction: Recovered<TempoTxEnvelope>) {
        if !transaction
            .subblock_proposer()
            .is_some_and(|k| k.matches(self.signer.public_key()))
        {
            return;
        }
        let mut txs = self.subblock_transactions.lock();
        if txs.len() >= MAX_SUBBLOCK_TXS {
            return;
        }
        txs.insert(*transaction.tx_hash(), Arc::new(transaction));
    }

    /// Tracking of the current sconsensus state by listening to notarizations and nullifications.
    #[instrument(skip_all, fields(event.epoch = event.epoch().get(), event.view = event.view().get()))]
    fn on_consensus_event(&mut self, event: Activity<Scheme<PublicKey, MinSig>, Digest>) {
        let (new_tip, new_round, new_cert) = match event {
            Activity::Notarization(n) => {
                (Some(n.proposal.payload.0), n.proposal.round, n.certificate)
            }
            Activity::Finalization(n) => {
                (Some(n.proposal.payload.0), n.proposal.round, n.certificate)
            }
            Activity::Nullification(n) => (None, n.round, n.certificate),
            _ => return,
        };

        if let Some((round, tip, cert)) = &mut self.consensus_tip
            && *round <= new_round
        {
            *round = new_round;
            *cert = new_cert;

            if let Some(new_tip) = new_tip
                && *tip != new_tip
            {
                // Clear collected subblocks if we have a new tip.
                self.subblocks.clear();
                *tip = new_tip;
            }
        } else if self.consensus_tip.is_none()
            && let Some(new_tip) = new_tip
        {
            // Initialize consensus tip once we know the tip block hash.
            self.consensus_tip = Some((new_round, new_tip, new_cert));
        }

        let Some((round, tip, certificate)) = &self.consensus_tip else {
            return;
        };

        let Ok(Some(header)) = self
            .node
            .provider
            .find_block_by_hash(*tip, BlockSource::Any)
        else {
            debug!(?tip, "missing header for the tip block at {tip}");
            return;
        };

        let epoch_of_next_block = utils::epoch(self.epoch_length, header.number() + 1);

        // Can't proceed without knowing a validator set for the current epoch.
        let Some(scheme) = self.scheme_provider.scheme(epoch_of_next_block) else {
            debug!(
                epoch_of_next_block = epoch_of_next_block.get(),
                "scheme not found for epoch"
            );
            return;
        };

        let next_round = if round.epoch() == epoch_of_next_block {
            Round::new(round.epoch(), round.view().next())
        } else {
            Round::new(epoch_of_next_block, View::new(1))
        };

        let seed = if next_round.view() == View::new(1) {
            // First view does not have a seed.
            None
        } else {
            scheme.seed(*round, certificate)
        };

        let (next_proposer, _) = select_leader::<Scheme<PublicKey, MinSig>, _>(
            scheme.participants().as_ref(),
            next_round,
            seed,
        );

        debug!(?next_proposer, ?next_round, "determined next proposer");

        // Spawn new subblock building task if the current one is assuming different proposer or parent hash.
        if self.our_subblock.parent_hash() != Some(*tip)
            || self.our_subblock.target_proposer() != Some(&next_proposer)
        {
            debug!(%tip, %next_proposer, "building new subblock");
            self.build_new_subblock(*tip, next_proposer, scheme);
        }
    }

    fn build_new_subblock(
        &mut self,
        parent_hash: BlockHash,
        next_proposer: PublicKey,
        scheme: Arc<Scheme<PublicKey, MinSig>>,
    ) {
        let transactions = self.subblock_transactions.clone();
        let node = self.node.clone();
        let num_validators = scheme.participants().len();
        let signer = self.signer.clone();
        let fee_recipient = self.fee_recipient;
        let timeout = self.time_to_build_subblock;
        let span = Span::current();
        let handle = self
            .context
            .with_label("validate_subblock")
            .shared(true)
            .spawn(move |_| {
                build_subblock(
                    transactions,
                    node,
                    parent_hash,
                    num_validators,
                    signer,
                    fee_recipient,
                    timeout,
                )
                .instrument(span)
            });

        self.our_subblock = PendingSubblock::Task(BuildSubblockTask {
            handle,
            parent_hash,
            proposer: next_proposer,
        });
    }

    #[instrument(skip_all, err(level = Level::WARN), fields(sender = %sender, msg_bytes = message.len()))]
    async fn on_network_message(
        &mut self,
        sender: PublicKey,
        message: bytes::Bytes,
        network_tx: &mut impl Sender<PublicKey = PublicKey>,
    ) -> eyre::Result<()> {
        let message =
            SubblocksMessage::decode(message).wrap_err("failed to decode network message")?;

        let subblock = match message {
            SubblocksMessage::Subblock(subblock) => subblock,
            // Process acknowledgements
            SubblocksMessage::Ack(ack) => {
                if let PendingSubblock::Built(built) = &mut self.our_subblock
                    && built.proposer == sender
                    && ack == built.subblock.signature_hash()
                {
                    debug!("received acknowledgement from the next proposer");
                    built.stop_broadcasting();
                } else {
                    warn!(%ack, "received invalid acknowledgement");
                }

                return Ok(());
            }
        };

        let Some(tip) = self.tip() else {
            return Err(eyre::eyre!("missing tip of the chain"));
        };

        // Skip subblocks that are not built on top of the tip.
        eyre::ensure!(
            subblock.parent_hash == tip,
            "invalid subblock parent, expected {tip}, got {}",
            subblock.parent_hash
        );

        // Send acknowledgement to the sender.
        //
        // We only send it after we've validated the tip to make sure that our view
        // of the chain matches the one of the view of subblock sender. Otherwise,
        // we expect to receive the subblock again.
        let _ = network_tx
            .send(
                Recipients::One(sender.clone()),
                SubblocksMessage::Ack(subblock.signature_hash()).encode(),
                true,
            )
            .await;

        debug!("validating new subblock");

        // Spawn task to validate the subblock.
        let node = self.node.clone();
        let validated_subblocks_tx = self.actions_tx.clone();
        let scheme_provider = self.scheme_provider.clone();
        let epoch_length = self.epoch_length;
        let span = Span::current();
        self.context.clone().shared(true).spawn(move |_| {
            validate_subblock(
                sender.clone(),
                node,
                subblock,
                validated_subblocks_tx,
                scheme_provider,
                epoch_length,
            )
            .instrument(span)
        });

        Ok(())
    }

    #[instrument(skip_all, fields(subblock.validator = %subblock.validator(), subblock.parent_hash = %subblock.parent_hash))]
    fn on_validated_subblock(&mut self, subblock: RecoveredSubBlock) {
        // Skip subblock if we are already past its parent
        if Some(subblock.parent_hash) != self.tip() {
            return;
        }

        debug!(subblock = ?subblock, "validated subblock");

        self.subblocks.insert(subblock.validator(), subblock);
    }

    #[instrument(skip_all)]
    async fn on_built_subblock(
        &mut self,
        subblock: Result<RecoveredSubBlock, commonware_runtime::Error>,
        next_proposer: PublicKey,
    ) {
        let subblock = match subblock {
            Ok(subblock) => subblock,
            Err(error) => {
                warn!(%error, "failed to build subblock");
                return;
            }
        };

        if Some(subblock.parent_hash) != self.tip() {
            return;
        }

        self.our_subblock = PendingSubblock::Built(BuiltSubblock {
            subblock,
            proposer: next_proposer,
            // ticks immediately
            broadcast_interval: Box::pin(futures::future::ready(())),
        });
    }

    #[instrument(skip_all)]
    async fn broadcast_built_subblock(
        &mut self,
        network_tx: &mut impl Sender<PublicKey = PublicKey>,
    ) {
        let PendingSubblock::Built(built) = &mut self.our_subblock else {
            return;
        };

        // Schedule next broadcast in `subblock_broadcast_interval`
        built.broadcast_interval = Box::pin(self.context.sleep(self.subblock_broadcast_interval));

        debug!(
            ?built.subblock,
            next_proposer = %built.proposer,
            "sending subblock to the next proposer"
        );

        if built.proposer != self.signer.public_key() {
            let _ = network_tx
                .send(
                    Recipients::One(built.proposer.clone()),
                    SubblocksMessage::Subblock((*built.subblock).clone()).encode(),
                    true,
                )
                .await;
        } else {
            let subblock = built.subblock.clone();
            built.stop_broadcasting();
            self.on_validated_subblock(subblock);
        }
    }
}

/// Actions processed by the subblocks service.
#[derive(Debug)]
enum Message {
    /// Returns all subblocks collected so far.
    ///
    /// This will return nothing if parent hash does not match the current chain view
    /// of the service or if no subblocks have been collected yet.
    GetSubBlocks {
        /// Parent block to return subblocks for.
        parent: BlockHash,
        /// Response channel.
        response: std::sync::mpsc::SyncSender<Vec<RecoveredSubBlock>>,
    },

    /// Reports a new consensus event.
    Consensus(Box<Activity<Scheme<PublicKey, MinSig>, Digest>>),

    /// Reports a new validated subblock.
    ValidatedSubblock(RecoveredSubBlock),
}

/// The current state of our subblock.
#[derive(Default)]
enum PendingSubblock {
    /// No subblock is available.
    #[default]
    None,
    /// Subblock is currently being built.
    Task(BuildSubblockTask),
    /// Subblock has been built and is ready to be sent.
    Built(BuiltSubblock),
}

impl PendingSubblock {
    /// Returns the current [`BuildSubblockTask`] if it exists and switches state to [`PendingSubblock::None`].
    fn take_task(&mut self) -> Option<BuildSubblockTask> {
        if let Self::Task(task) = std::mem::take(self) {
            Some(task)
        } else {
            None
        }
    }

    /// Returns the parent hash of the subblock that was built or is being built.
    fn parent_hash(&self) -> Option<BlockHash> {
        match self {
            Self::Task(task) => Some(task.parent_hash),
            Self::Built(built) => Some(built.subblock.parent_hash),
            Self::None => None,
        }
    }

    /// Returns the proposer we are going to send the subblock to.
    fn target_proposer(&self) -> Option<&PublicKey> {
        match self {
            Self::Task(task) => Some(&task.proposer),
            Self::Built(built) => Some(&built.proposer),
            Self::None => None,
        }
    }
}

/// Task for building a subblock.
struct BuildSubblockTask {
    /// Handle to the spawned task.
    handle: Handle<RecoveredSubBlock>,
    /// Parent hash subblock is being built on top of.
    parent_hash: BlockHash,
    /// Proposer we are going to send the subblock to.
    proposer: PublicKey,
}

/// A built subblock ready to be sent.
struct BuiltSubblock {
    /// Subblock that has been built.
    subblock: RecoveredSubBlock,
    /// Proposer we are going to send the subblock to.
    proposer: PublicKey,
    /// Interval for subblock broadcast.
    broadcast_interval: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl BuiltSubblock {
    /// Stops broadcasting the subblock once the acknowledgement is received.
    fn stop_broadcasting(&mut self) {
        self.broadcast_interval = Box::pin(futures::future::pending());
    }
}

/// Network messages used in the subblocks service.
#[derive(Debug)]
enum SubblocksMessage {
    /// A new subblock sent to the proposer.
    Subblock(SignedSubBlock),
    /// Acknowledgment about receiving a subblock with given hash.
    Ack(B256),
}

impl SubblocksMessage {
    /// Encodes the message into a [`bytes::Bytes`].
    fn encode(self) -> bytes::Bytes {
        match self {
            Self::Subblock(subblock) => alloy_rlp::encode(&subblock).into(),
            Self::Ack(hash) => bytes::Bytes::copy_from_slice(hash.as_ref()),
        }
    }

    /// Decodes a message from the given [`bytes::Bytes`].
    fn decode(message: bytes::Bytes) -> alloy_rlp::Result<Self> {
        if message.len() == 32 {
            let hash = B256::from_slice(&message);
            Ok(Self::Ack(hash))
        } else {
            let subblock = SignedSubBlock::decode(&mut &*message)?;
            Ok(Self::Subblock(subblock))
        }
    }
}

/// Handle to the spawned subblocks service.
#[derive(Clone)]
pub(crate) struct Mailbox {
    tx: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(crate) fn get_subblocks(
        &self,
        parent: BlockHash,
    ) -> Result<Vec<RecoveredSubBlock>, RecvError> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let _ = self.tx.unbounded_send(Message::GetSubBlocks {
            parent,
            response: tx,
        });
        rx.recv()
    }
}

impl Reporter for Mailbox {
    type Activity = Activity<Scheme<PublicKey, MinSig>, Digest>;

    async fn report(&mut self, activity: Self::Activity) -> () {
        let _ = self
            .tx
            .unbounded_send(Message::Consensus(Box::new(activity)));
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
    let header = node
        .provider
        .find_block_by_hash(hash, BlockSource::Any)?
        .ok_or(ProviderError::BestBlockNotFound)?;

    Ok(node.evm_config.evm_for_block(db, &header)?)
}

/// Builds a subblock from candidate transactions we've collected so far.
///
/// This will include as many valid transactions as possible within the given timeout.
#[instrument(skip_all, fields(parent_hash = %parent_hash))]
async fn build_subblock(
    transactions: Arc<Mutex<IndexMap<TxHash, Arc<Recovered<TempoTxEnvelope>>>>>,
    node: TempoFullNode,
    parent_hash: BlockHash,
    num_validators: usize,
    signer: PrivateKey,
    fee_recipient: Address,
    timeout: Duration,
) -> RecoveredSubBlock {
    let start = Instant::now();

    let (transactions, senders) = match evm_at_block(&node, parent_hash) {
        Ok(mut evm) => {
            let mut selected_transactions = Vec::new();
            let mut senders = Vec::new();
            let mut gas_left =
                evm.block().gas_limit / TEMPO_SHARED_GAS_DIVISOR / num_validators as u64;

            let txs = transactions.lock().clone();
            for (tx_hash, tx) in txs {
                if tx.gas_limit() > gas_left {
                    continue;
                }
                if let Err(err) = evm.transact_commit(&*tx) {
                    warn!(%err, tx_hash = %tx_hash, "invalid subblock candidate transaction");
                    // Remove invalid transactions from the set.
                    transactions.lock().swap_remove(&tx_hash);
                    continue;
                }

                gas_left -= tx.gas_limit();
                selected_transactions.push(tx.inner().clone());
                senders.push(tx.signer());

                if start.elapsed() > timeout {
                    break;
                }
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
        fee_recipient,
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

/// Validates a subblock and reports it to the subblocks service.
///
/// Validation checks include:
/// 1. Signature verification
/// 2. Ensuring that sender is a validator for the block's epoch
/// 3. Ensuring that all transactions have corresponding nonce key set.
/// 4. Ensuring that all transactions are valid.
#[instrument(skip_all, err(level = Level::WARN), fields(sender = %sender))]
async fn validate_subblock(
    sender: PublicKey,
    node: TempoFullNode,
    subblock: SignedSubBlock,
    actions_tx: mpsc::UnboundedSender<Message>,
    scheme_provider: SchemeProvider,
    epoch_length: u64,
) -> eyre::Result<()> {
    let Ok(signature) =
        Signature::decode(&mut subblock.signature.as_ref()).wrap_err("invalid signature")
    else {
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

    // Recover subblock transactions and convert it into a `RecoveredSubBlock`.
    let subblock = subblock.try_into_recovered(B256::from_slice(&sender))?;

    let mut evm = evm_at_block(&node, subblock.parent_hash)?;

    let epoch = utils::epoch(epoch_length, evm.block().number.to::<u64>() + 1);
    let scheme = scheme_provider
        .scheme(epoch)
        .ok_or_eyre("scheme not found")?;

    eyre::ensure!(
        scheme.participants().iter().any(|p| p == &sender),
        "sender is not a validator"
    );

    // Bound subblock size at a value proportional to `TEMPO_SHARED_GAS_DIVISOR`.
    //
    // This ensures we never collect too many subblocks to fit into a new proposal.
    let max_size = MAX_RLP_BLOCK_SIZE
        / TEMPO_SHARED_GAS_DIVISOR as usize
        / scheme.participants().len() as usize;
    if subblock.total_tx_size() > max_size {
        warn!(
            size = subblock.total_tx_size(),
            max_size, "subblock is too large, skipping"
        );
        return Ok(());
    }

    for tx in subblock.transactions_recovered() {
        if let Err(err) = evm.transact_commit(tx) {
            return Err(eyre::eyre!("transaction failed to execute: {err:?}"));
        }
    }

    let _ = actions_tx.unbounded_send(Message::ValidatedSubblock(subblock));

    Ok(())
}
