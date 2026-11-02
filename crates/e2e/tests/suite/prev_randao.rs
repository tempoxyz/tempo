//! TIP-1153: `mix_hash` (`PREVRANDAO`) carries the seed of the parent's round.

use std::{net::SocketAddr, time::Duration};

use alloy_primitives::{B256, keccak256};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::simplex::{
    scheme::bls12381_threshold::vrf::{Scheme, Seedable as _},
    types::Finalization,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{self, Runner},
};
use futures::channel::oneshot;
use jsonrpsee::http_client::HttpClientBuilder;
use reth_ethereum::primitives::AlloyBlockHeader as _;
use tempo_consensus::consensus::Digest;
use tempo_node::rpc::consensus::{Query, TempoConsensusApiClient};

use crate::{Setup, metrics::wait_for_height, setup_validators};

/// Checks every block against the finalization of its parent, across two
/// epoch boundaries. The e2e chainspec activates TIP-1153 at genesis.
#[tokio::test]
#[test_traced]
async fn mix_hash_is_seed_of_parent_round() {
    let _ = tempo_eyre::install();

    const EPOCH_LENGTH: u64 = 10;
    const LAST_CHECKED: u64 = 2 * EPOCH_LENGTH + 3;

    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default()
        .with_seed(setup.seed)
        .with_timeout(Some(Duration::from_secs(120)));

    let (addr_tx, addr_rx) = oneshot::channel::<SocketAddr>();
    let (done_tx, done_rx) = oneshot::channel::<()>();

    let executor_handle = std::thread::spawn(move || {
        Runner::from(cfg).start(|mut context| async move {
            let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
            futures::future::join_all(validators.iter_mut().map(|node| node.start(&context))).await;
            wait_for_height(&context, &validators[0], LAST_CHECKED).await;

            let execution = validators[0].execution();
            addr_tx
                .send(execution.rpc_server_handles.rpc.http_local_addr().unwrap())
                .unwrap();
            let _ = done_rx.await;
        });
    });

    let http_addr = addr_rx.await.unwrap();
    let client = HttpClientBuilder::default()
        .build(format!("http://{http_addr}"))
        .unwrap();

    let mut finalized = Vec::new();
    for height in 1..=LAST_CHECKED {
        finalized.push(
            client
                .get_finalization(Query::Height(height))
                .await
                .unwrap(),
        );
    }

    // Block 1 builds on genesis, the first block of epoch 0.
    assert_eq!(finalized[0].block.header().mix_hash(), Some(B256::ZERO));

    let mut first_blocks = 0;
    for pair in finalized.windows(2) {
        let (parent, block) = (&pair[0], &pair[1]);
        let parent_ctx = parent.block.header().consensus_context.unwrap();
        let ctx = block.block.header().consensus_context.unwrap();
        let mix_hash = block.block.header().mix_hash().unwrap();

        if parent_ctx.epoch < ctx.epoch {
            first_blocks += 1;
            assert_eq!(mix_hash, B256::ZERO, "first block of epoch {}", ctx.epoch);
            continue;
        }

        let bytes = alloy_primitives::hex::decode(&parent.certificate).unwrap();
        let finalization =
            Finalization::<Scheme<PublicKey, MinSig>, Digest>::decode(&*bytes).unwrap();
        let seed = finalization.seed();
        assert_eq!(seed.round.epoch().get(), parent_ctx.epoch);
        assert_eq!(seed.round.view().get(), parent_ctx.view);
        assert_eq!(
            mix_hash,
            keccak256(seed.signature.encode()),
            "block {}",
            block.block.header().number()
        );
    }
    assert_eq!(first_blocks, 2);

    drop(done_tx);
    executor_handle.join().unwrap();
}
