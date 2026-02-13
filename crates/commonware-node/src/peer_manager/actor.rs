use commonware_consensus::marshal::Update;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{AddressableManager, Provider};
use commonware_runtime::{ContextCell, Spawner, spawn_cell};
use commonware_utils::Acknowledgement;
use futures::{StreamExt as _, channel::mpsc};
use tempo_node::TempoFullNode;
use tracing::{Span, info, info_span, instrument, warn};

use crate::consensus::block::Block;

use super::ingress::{Message, MessageWithCause};

pub(crate) struct Actor<TPeerManager>
where
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    oracle: TPeerManager,
    #[allow(dead_code)]
    execution_node: TempoFullNode,
    mailbox: mpsc::UnboundedReceiver<MessageWithCause>,
}

impl<TPeerManager> Actor<TPeerManager>
where
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    pub(super) fn new(
        oracle: TPeerManager,
        execution_node: TempoFullNode,
        mailbox: mpsc::UnboundedReceiver<MessageWithCause>,
    ) -> Self {
        Self {
            oracle,
            execution_node,
            mailbox,
        }
    }

    async fn run(mut self) {
        while let Some(msg) = self.mailbox.next().await {
            self.handle_message(msg.cause, msg.message).await;
        }
        info_span!("peer_manager").in_scope(|| info!("mailbox closed, agent shutting down"));
    }

    pub(crate) fn start(self, context: impl Spawner) -> commonware_runtime::Handle<()> {
        let mut context = ContextCell::new(context);
        spawn_cell!(context, self.run().await)
    }

    #[instrument(parent = &cause, skip_all)]
    async fn handle_message(&mut self, cause: Span, message: Message) {
        match message {
            Message::Track { id, peers } => {
                AddressableManager::track(&mut self.oracle, id, peers).await;
            }
            Message::Overwrite { peers } => {
                AddressableManager::overwrite(&mut self.oracle, peers).await;
            }
            Message::PeerSet { id, response } => {
                let result = Provider::peer_set(&mut self.oracle, id).await;
                let _ = response.send(result);
            }
            Message::Subscribe { response } => {
                let receiver = Provider::subscribe(&mut self.oracle).await;
                let _ = response.send(receiver);
            }
            Message::Finalized(update) => {
                self.handle_finalized(*update).await;
            }
        }
    }

    async fn handle_finalized(&mut self, update: Update<Block>) {
        let Update::Block(block, ack) = update else {
            return;
        };

        if is_past_hardfork(&block) {
            // TODO: After the hardfork, read Val Config V2 getActiveValidators()
            // from the execution node, build ordered::Map<PublicKey, Address>
            // using Address::Asymmetric { ingress, egress }, and call
            // oracle.overwrite(peers).
            warn!("hardfork detected but V2 peer management not yet implemented");
        }

        ack.acknowledge();
    }
}

/// Stub to implement hardfork logic.
fn is_past_hardfork(_block: &Block) -> bool {
    false
}
