//! `tempo-zone corpus`: capture a zone archive range, with the Tempo L1 state each block reads,
//! into an object-store corpus, and replay it without a database or L1 access.

use crate::{ZoneConsensus, ZoneNode, cli::cli_l1_provider};
use alloy_primitives::{Address, B256};
use clap::{Parser, Subcommand};
use evm2::evm::Database;
use parking_lot::Mutex;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_cli_util::cancellation::CancellationToken;
use reth_evm::ConfigureEvm;
use reth_primitives_traits::RecoveredBlock;
use reth_tasks::Runtime;
use std::{path::PathBuf, sync::Arc};
use tempo_corpus::{
    exec::{
        chain::{Chain, Evm, Source},
        fill, replay, workers,
    },
    gc,
    store::Store,
    types::{L1Read, L1Reads},
};
use tempo_precompiles::zone_factory::portal_address;
use tempo_primitives::Block;
use zone_chainspec::{ZoneChainSpec, ZoneChainSpecParser};
use zone_evm::{ZoneBlockExecutor, ZoneEvmConfig, ZoneExecutorState};
use zone_precompiles::{L1StateError, L1StorageReader};

/// Why replay refused an L1 read.
const UNRECORDED: &str = "not recorded in the corpus";

/// Historical execution corpus commands.
#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    /// Capture archive blocks and the L1 state they read into `--corpus s3://bucket/prefix`,
    /// appending to an existing corpus.
    Fill(Box<FillCommand>),
    /// Replay a corpus range without opening a database or reading L1.
    Replay(ReplayCommand),
    /// Delete the superseded checkpoints and unreferenced files of a complete corpus.
    Gc(GcCommand),
}

impl CorpusCommand {
    /// Runs the command; `runtime` opens the archive a fill reads.
    pub async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        match self {
            Self::Fill(cmd) => cmd.execute(runtime).await,
            Self::Replay(cmd) => cmd.execute().await,
            Self::Gc(cmd) => cmd.execute().await,
        }
    }
}

/// Capture archive blocks from a zone archive datadir up to a pinned exclusive end, appending
/// after the blocks a corpus already published. Every Tempo L1 read a block makes is read over
/// `L1_HTTP_RPC_URL` and stored with it.
#[derive(Debug, Parser)]
pub struct FillCommand {
    #[command(flatten)]
    env: EnvironmentArgs<ZoneChainSpecParser>,
    /// Tempo L1 HTTP RPC URL the L1 state blocks read is read from.
    #[arg(long = "l1.http-rpc-url", env = "L1_HTTP_RPC_URL")]
    l1_http_rpc_url: url::Url,
    /// First block of a new corpus (genesis is context, not a captured block); an existing
    /// corpus must start here.
    #[arg(long, default_value = "1")]
    from: u64,
    /// Exclusive end, clamped to the available head; defaults to the head.
    #[arg(long)]
    to: Option<u64>,
    /// Destination s3://bucket/prefix. Existing incompatible data is rejected.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint. Credentials come from AWS env vars, web identity, ECS or IMDS.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// Re-read and fully replay published records instead of checking metadata only.
    #[arg(long)]
    verify_existing: bool,
    /// Capture worker threads; defaults to the available parallelism.
    #[arg(long)]
    workers: Option<usize>,
}

impl FillCommand {
    async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let Environment {
            provider_factory, ..
        } = self.env.init::<ZoneNode>(AccessRights::RO, runtime)?;
        let chain = ZoneChain::new(self.env.chain.clone());
        let source = ZoneSource {
            l1: cli_l1_provider(chain.portal, self.l1_http_rpc_url),
            chain,
        };
        let consensus = ZoneConsensus::new(self.env.chain.clone());
        let args = fill::FillArgs {
            from: self.from,
            to: self.to,
            verify_existing: self.verify_existing,
            workers: workers(self.workers),
        };
        let cancellation = CancellationToken::new();
        let _guard = cancellation.drop_guard();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            fill::fill(
                provider_factory,
                store,
                &source,
                &consensus,
                args,
                &cancellation,
                handle,
            )
        })
        .await?
    }
}

/// Replay a published corpus range.
#[derive(Debug, Parser)]
pub struct ReplayCommand {
    /// The zone genesis the corpus was captured from.
    #[arg(long, value_name = "CHAIN_OR_PATH", value_parser = ZoneChainSpecParser::parser())]
    chain: Arc<ZoneChainSpec>,
    /// Source s3://bucket/prefix.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint. Credentials come from AWS env vars, web identity, ECS or IMDS.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// First block; defaults to the corpus start.
    #[arg(long)]
    from: Option<u64>,
    /// Exclusive end; defaults to the end of the published blocks.
    #[arg(long)]
    to: Option<u64>,
    /// Replay only transactions with ordinal in [tx-from, tx-to), each independently.
    #[arg(long, requires = "tx_to")]
    tx_from: Option<u64>,
    /// Exclusive end of the standalone transaction ordinal range.
    #[arg(long, requires = "tx_from")]
    tx_to: Option<u64>,
    /// Execution worker threads; defaults to the available parallelism.
    #[arg(long)]
    workers: Option<usize>,
    /// Replay only the blocks a block list file names, such as a fuzz corpus minimizer's.
    #[arg(long, conflicts_with_all = ["from", "to", "tx_from"])]
    blocks: Option<PathBuf>,
}

impl ReplayCommand {
    async fn execute(self) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let (catalog, _) = store
            .catalog()
            .await?
            .ok_or_else(|| eyre::eyre!("no corpus catalog at {}", self.corpus))?;
        let request = replay::Request {
            from: self.from,
            to: self.to,
            transactions: self.tx_from.zip(self.tx_to),
            blocks: self.blocks,
            workers: workers(self.workers),
        };
        let consensus = ZoneConsensus::new(self.chain.clone());
        let chain = ZoneChain::new(self.chain);
        let cancellation = CancellationToken::new();
        let _guard = cancellation.drop_guard();
        tokio::task::spawn_blocking(move || {
            replay::run_request(store, catalog, chain, consensus, request, cancellation)
        })
        .await?
    }
}

/// Shrink a complete corpus to its published checkpoint.
#[derive(Debug, Parser)]
pub struct GcCommand {
    /// Corpus s3://bucket/prefix or file:///directory; must be complete.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint. Credentials come from AWS env vars, web identity, ECS or IMDS.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// Take over a corpus an interrupted gc left marked as collecting. Only when no gc is
    /// still running on it.
    #[arg(long)]
    force: bool,
}

impl GcCommand {
    async fn execute(self) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        gc::gc(&store, self.force).await
    }
}

/// A zone whose blocks a corpus replays.
#[derive(Clone, Debug)]
struct ZoneChain {
    chain_spec: Arc<ZoneChainSpec>,
    /// The portal the zone ID in `chain_spec` derives.
    portal: Address,
}

impl ZoneChain {
    fn new(chain_spec: Arc<ZoneChainSpec>) -> Self {
        let portal = portal_address(chain_spec.zone_id());
        Self { chain_spec, portal }
    }

    /// Zone execution reading Tempo L1 state through `reader`.
    fn evm<R: L1StorageReader>(&self, reader: R) -> CorpusEvm<R> {
        CorpusEvm {
            config: ZoneEvmConfig::new(self.chain_spec.clone(), reader.clone(), self.portal),
            reader,
        }
    }
}

impl Chain for ZoneChain {
    type Evm = CorpusEvm<RecordedReader>;
    type Spec = ZoneChainSpec;

    fn chain_spec(&self) -> &ZoneChainSpec {
        &self.chain_spec
    }

    fn portal(&self) -> Option<Address> {
        Some(self.portal)
    }

    fn replaying(&self, reads: &L1Reads) -> eyre::Result<Self::Evm> {
        Ok(self.evm(RecordedReader(Arc::new(reads.clone()))))
    }
}

/// A zone whose blocks a corpus captures, reading Tempo L1 state through `l1`.
#[derive(Clone, Debug)]
struct ZoneSource<L1> {
    chain: ZoneChain,
    l1: L1,
}

impl<L1: L1StorageReader + Unpin> Chain for ZoneSource<L1> {
    type Evm = CorpusEvm<RecordedReader>;
    type Spec = ZoneChainSpec;

    fn chain_spec(&self) -> &ZoneChainSpec {
        self.chain.chain_spec()
    }

    fn portal(&self) -> Option<Address> {
        self.chain.portal()
    }

    fn replaying(&self, reads: &L1Reads) -> eyre::Result<Self::Evm> {
        self.chain.replaying(reads)
    }
}

impl<L1: L1StorageReader + Unpin> Source for ZoneSource<L1> {
    type Capture = CorpusEvm<RecordingReader<L1>>;

    fn capturing(&self) -> Self::Capture {
        self.chain.evm(RecordingReader {
            l1: self.l1.clone(),
            reads: Default::default(),
        })
    }

    fn recorded(evm: &Self::Capture) -> L1Reads {
        std::mem::take(&mut evm.reader.reads.lock())
    }
}

/// Zone block execution over `reader`, kept to take the L1 reads it recorded.
struct CorpusEvm<R> {
    config: ZoneEvmConfig<R>,
    reader: R,
}

impl<R: L1StorageReader + Unpin> Evm for CorpusEvm<R> {
    type Executor<'a> = ZoneBlockExecutor<'a>;
    type Boundary = ZoneExecutorState;

    fn executor<'a, DB: Database + 'a>(
        &'a self,
        db: DB,
        block: &'a RecoveredBlock<Block>,
    ) -> eyre::Result<ZoneBlockExecutor<'a>> {
        Ok(self.config.executor_for_block(db, block.sealed_block())?)
    }

    fn boundary(executor: &ZoneBlockExecutor<'_>) -> ZoneExecutorState {
        executor.executor_state()
    }

    fn restore(executor: &mut ZoneBlockExecutor<'_>, boundary: ZoneExecutorState) {
        executor.with_executor_state(boundary);
    }
}

/// Reads Tempo L1 state from `l1`, recording every successful read and its value.
#[derive(Clone, Debug)]
struct RecordingReader<L1> {
    l1: L1,
    reads: Arc<Mutex<L1Reads>>,
}

impl<L1: L1StorageReader> L1StorageReader for RecordingReader<L1> {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        let value = self.l1.read_l1_storage(account, slot, block_number)?;
        self.reads
            .lock()
            .0
            .insert(l1_read(account, Some(slot), block_number), value.0);
        Ok(value)
    }

    fn read_l1_commitment(
        &self,
        account: Address,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        let commitment = self.l1.read_l1_commitment(account, block_number)?;
        self.reads
            .lock()
            .0
            .insert(l1_read(account, None, block_number), commitment.0);
        Ok(commitment)
    }
}

/// Serves Tempo L1 reads only from the ones a block recorded; any other read fails.
#[derive(Clone, Debug)]
struct RecordedReader(Arc<L1Reads>);

impl L1StorageReader for RecordedReader {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        self.0
            .0
            .get(&l1_read(account, Some(slot), block_number))
            .map(|value| B256::from(*value))
            .ok_or_else(|| L1StateError::StorageUnavailable {
                account,
                slot,
                block_number,
                reason: UNRECORDED.into(),
            })
    }

    fn read_l1_commitment(
        &self,
        account: Address,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        self.0
            .0
            .get(&l1_read(account, None, block_number))
            .map(|value| B256::from(*value))
            .ok_or_else(|| L1StateError::AccountUnavailable {
                account,
                block_number,
                reason: UNRECORDED.into(),
            })
    }
}

/// The corpus key of a read of `account`'s `slot`, or of its commitment when `None`.
fn l1_read(account: Address, slot: Option<B256>, block: u64) -> L1Read {
    L1Read {
        block,
        account: account.into_array(),
        slot: slot.map(|slot| slot.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{CliL1Access, ZoneCli, ZoneSubcommand};
    use alloy_consensus::{
        Header, Sealable, SignableTransaction, TxLegacy, TxReceipt,
        constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_WITHDRAWALS},
        proofs::{calculate_receipt_root, calculate_transaction_root},
    };
    use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
    use alloy_primitives::{Bloom, U256};
    use alloy_sol_types::SolCall;
    use evm2::evm::InMemoryDB;
    use reth_chainspec::EthChainSpec;
    use reth_db_api::models::{AccountBeforeTx, BlockNumberAddress};
    use reth_ethereum::cli::Commands;
    use reth_evm::execute::BlockExecutor;
    use reth_execution_types::BundleSource;
    use reth_primitives_traits::{Account, Recovered, SealedBlock, StorageEntry};
    use reth_provider::ProviderResult;
    use reth_storage_api::{ChangeSetReader, StorageChangeSetReader};
    use reth_trie_common::bundle_state::{AccountInfoRevert, RevertToSlot};
    use std::{collections::HashMap, ops::RangeBounds};
    use tempo_chainspec::spec::DEV;
    use tempo_contracts::zones::IZoneInbox;
    use tempo_corpus::{
        exec::capture,
        store::{self, CaseRecord, Record},
    };
    use tempo_primitives::{
        BlockBody, TempoHeader, TempoTxEnvelope,
        transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
    };
    use zone_precompiles::{
        tempo_state::{TEMPO_BLOCK_NUMBER_SLOT, slots::TEMPO_BLOCK_HASH},
        test_utils::MockL1Reader,
    };
    use zone_primitives::constants::{TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS, zone_chain_id};

    /// Blocks of the in-memory zone archive.
    const BLOCKS: u64 = 3;

    /// A zone archive: its blocks, the state after each block from genesis, and the historical
    /// changesets an archive database stores.
    struct Archive {
        blocks: Vec<RecoveredBlock<Block>>,
        states: Vec<InMemoryDB>,
        changesets: Changesets,
    }

    /// Per-block changesets, as an archive database returns them.
    #[derive(Default)]
    struct Changesets {
        accounts: HashMap<u64, Vec<AccountBeforeTx>>,
        storage: HashMap<u64, Vec<(BlockNumberAddress, StorageEntry)>>,
    }

    impl ChangeSetReader for Changesets {
        fn account_block_changeset(
            &self,
            block_number: u64,
        ) -> ProviderResult<Vec<AccountBeforeTx>> {
            Ok(self.accounts[&block_number].clone())
        }

        fn get_account_before_block(
            &self,
            _: u64,
            _: Address,
        ) -> ProviderResult<Option<AccountBeforeTx>> {
            unimplemented!("capture reads whole block changesets")
        }

        fn account_changesets_range(
            &self,
            _: impl RangeBounds<u64>,
        ) -> ProviderResult<Vec<(u64, AccountBeforeTx)>> {
            unimplemented!("capture reads whole block changesets")
        }
    }

    impl StorageChangeSetReader for Changesets {
        fn storage_changeset(
            &self,
            block_number: u64,
        ) -> ProviderResult<Vec<(BlockNumberAddress, StorageEntry)>> {
            Ok(self.storage[&block_number].clone())
        }

        fn get_storage_before_block(
            &self,
            _: u64,
            _: Address,
            _: B256,
        ) -> ProviderResult<Option<StorageEntry>> {
            unimplemented!("capture reads whole block changesets")
        }

        fn storage_changesets_range(
            &self,
            _: impl RangeBounds<u64>,
        ) -> ProviderResult<Vec<(BlockNumberAddress, StorageEntry)>> {
            unimplemented!("capture reads whole block changesets")
        }
    }

    fn chain() -> ZoneChain {
        let mut genesis = DEV.genesis().clone();
        genesis.config.chain_id = zone_chain_id(DEV.chain_id(), 1).unwrap();
        ZoneChain::new(Arc::new(ZoneChainSpec::from_genesis(genesis).unwrap()))
    }

    /// Builds [`BLOCKS`] zone blocks, each opening with the `advanceTempo` that imports the next
    /// Tempo block, so each reads the portal's L1 state at its own Tempo block.
    fn archive(chain: &ZoneChain, l1: &MockL1Reader) -> Archive {
        let mut tempo = TempoHeader::default();
        let mut state = InMemoryDB::default();
        state.insert_account_info(&TEMPO_STATE_ADDRESS, Default::default());
        state.insert_account_storage(
            &TEMPO_STATE_ADDRESS,
            &TEMPO_BLOCK_HASH,
            &tempo.hash_slow().into(),
        );
        state.insert_account_storage(&TEMPO_STATE_ADDRESS, &TEMPO_BLOCK_NUMBER_SLOT, &U256::ZERO);
        let config = ZoneEvmConfig::new(chain.chain_spec.clone(), l1.clone(), chain.portal);
        let mut archive = Archive {
            blocks: Vec::new(),
            states: vec![state.clone()],
            changesets: Changesets::default(),
        };
        let mut parent = chain.chain_spec.genesis_hash();
        for number in 1..=BLOCKS {
            tempo = TempoHeader {
                inner: Header {
                    parent_hash: tempo.hash_slow(),
                    number,
                    ..Default::default()
                },
                ..Default::default()
            };
            let advance = IZoneInbox::advanceTempoCall {
                header: alloy_rlp::encode(&tempo).into(),
                deposits: Vec::new(),
                decryptions: Vec::new(),
                enabledTokens: Vec::new(),
            };
            let tx = TempoTxEnvelope::Legacy(
                TxLegacy {
                    to: ZONE_INBOX_ADDRESS.into(),
                    input: advance.abi_encode().into(),
                    ..Default::default()
                }
                .into_signed(TEMPO_SYSTEM_TX_SIGNATURE),
            );
            let mut block = Block {
                header: TempoHeader {
                    inner: Header {
                        parent_hash: parent,
                        number,
                        timestamp: number,
                        gas_limit: 30_000_000,
                        base_fee_per_gas: Some(0),
                        ommers_hash: EMPTY_OMMER_ROOT_HASH,
                        transactions_root: calculate_transaction_root(std::slice::from_ref(&tx)),
                        withdrawals_root: Some(EMPTY_WITHDRAWALS),
                        parent_beacon_block_root: Some(B256::ZERO),
                        blob_gas_used: Some(0),
                        excess_blob_gas: Some(0),
                        requests_hash: Some(EMPTY_REQUESTS_HASH),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                body: BlockBody {
                    transactions: vec![tx],
                    ommers: Vec::new(),
                    withdrawals: Some(Default::default()),
                },
            };
            // Execute once to fill in the header's execution outputs.
            let sealed = SealedBlock::seal_slow(block.clone());
            let mut executor = config.executor_for_block(&mut state, &sealed).unwrap();
            executor.apply_pre_execution_changes().unwrap();
            for tx in &sealed.body().transactions {
                executor
                    .execute_transaction(Recovered::new_unchecked(tx, TEMPO_SYSTEM_TX_SENDER))
                    .unwrap();
            }
            let output = executor.finish().unwrap();
            let receipts: Vec<_> = output
                .result
                .receipts
                .iter()
                .map(|receipt| receipt.with_bloom_ref())
                .collect();
            block.header.inner.receipts_root = calculate_receipt_root(&receipts);
            block.header.inner.logs_bloom = receipts
                .iter()
                .fold(Bloom::ZERO, |bloom, receipt| bloom | receipt.bloom());
            block.header.inner.gas_used = output.result.gas_used;

            let reverts = output.state.reverts.last().unwrap();
            archive.changesets.accounts.insert(
                number,
                reverts
                    .iter()
                    .filter_map(|(address, revert)| {
                        let info = match &revert.account {
                            AccountInfoRevert::DoNothing => return None,
                            AccountInfoRevert::DeleteIt => None,
                            AccountInfoRevert::RevertTo(info) => Some(Account::from(info)),
                        };
                        Some(AccountBeforeTx {
                            address: *address,
                            info,
                        })
                    })
                    .collect(),
            );
            archive.changesets.storage.insert(
                number,
                reverts
                    .iter()
                    .flat_map(|(address, revert)| {
                        revert.storage.iter().map(|(key, slot)| {
                            let value = match slot {
                                RevertToSlot::Some(value) => *value,
                                RevertToSlot::Destroyed => U256::ZERO,
                            };
                            (
                                BlockNumberAddress((number, *address)),
                                StorageEntry {
                                    key: B256::from(*key),
                                    value,
                                },
                            )
                        })
                    })
                    .collect(),
            );
            state.commit_source(&BundleSource(&output.state));
            archive.states.push(state.clone());
            let block = RecoveredBlock::new_unhashed(block, vec![TEMPO_SYSTEM_TX_SENDER]);
            parent = block.hash();
            archive.blocks.push(block);
        }
        archive
    }

    /// A block's published payload: its record, block payload and transaction payloads.
    struct Published {
        record: Record,
        bytes: Vec<u8>,
        cases: Vec<alloy_primitives::bytes::Bytes>,
    }

    /// Captures every block of a fresh archive and publishes it as a fill would.
    fn capture_archive() -> (ZoneChain, Vec<Published>) {
        let chain = chain();
        let l1 = MockL1Reader::default();
        let archive = archive(&chain, &l1);
        let source = ZoneSource {
            chain: chain.clone(),
            l1,
        };
        let consensus = ZoneConsensus::new(chain.chain_spec.clone());
        let published = archive
            .blocks
            .iter()
            .scan(0, |first_tx, block| {
                let captured = capture::capture(
                    &source,
                    &consensus,
                    &archive.changesets,
                    |at| Ok(archive.states[at as usize].clone()),
                    block,
                    *first_tx,
                )
                .unwrap();
                let input = &captured.input;
                assert!(
                    !input.l1.0.is_empty(),
                    "block {} recorded no L1 reads",
                    input.number
                );
                let bytes = store::encode(input).unwrap();
                let cases: Vec<_> = captured
                    .cases()
                    .unwrap()
                    .iter()
                    .map(|case| store::encode_case(case).unwrap())
                    .collect();
                let record = Record {
                    number: input.number,
                    parent: input.parent,
                    hash: input.block.hash,
                    bytes: bytes.len() + cases.iter().map(Vec::len).sum::<usize>(),
                    block_bytes: bytes.len(),
                    transactions: cases.len() as u64,
                    gas: captured.executed.gas,
                    first_tx: *first_tx,
                    cases: cases
                        .iter()
                        .enumerate()
                        .map(|(index, case)| CaseRecord {
                            index: index as u64,
                            bytes: case.len(),
                        })
                        .collect(),
                };
                *first_tx += record.transactions;
                Some(Published {
                    record,
                    bytes,
                    cases: cases.into_iter().map(Into::into).collect(),
                })
            })
            .collect();
        (chain, published)
    }

    #[test]
    fn captured_zone_blocks_replay_from_their_recorded_l1_reads() {
        let (chain, published) = capture_archive();
        // The replaying chain has no L1 reader: every L1 read is served from the record.
        let consensus = ZoneConsensus::new(chain.chain_spec.clone());
        for Published {
            record,
            bytes,
            cases,
        } in &published
        {
            let input = store::decode(bytes, record).unwrap();
            assert!(
                input.l1.0.keys().all(|read| read.block == record.number),
                "block {} read L1 state outside its Tempo block",
                record.number
            );
            replay::verify(&chain, &consensus, &input, cases, record).unwrap();
        }
    }

    #[test]
    fn unrecorded_l1_read_fails_replay() {
        let (chain, published) = capture_archive();
        let consensus = ZoneConsensus::new(chain.chain_spec.clone());
        let Published {
            record,
            bytes,
            cases,
        } = &published[0];
        let mut input = store::decode(bytes, record).unwrap();
        Arc::get_mut(&mut input).unwrap().l1.0.pop_first().unwrap();
        let err = replay::verify(&chain, &consensus, &input, cases, record).unwrap_err();
        assert!(format!("{err:#}").contains(UNRECORDED), "{err:#}");
    }

    #[test]
    fn corpus_commands_parse_without_l1_access() {
        let genesis = serde_json::to_string(chain().chain_spec.genesis()).unwrap();
        let corpus = "s3://bucket/zone";
        let l1 = "http://127.0.0.1:8545";
        for args in [
            &[
                "fill",
                "--chain",
                &genesis,
                "--corpus",
                corpus,
                "--l1.http-rpc-url",
                l1,
            ][..],
            &["replay", "--chain", &genesis, "--corpus", corpus],
            &["gc", "--corpus", corpus],
        ] {
            let parsed = ZoneCli::try_parse_from(["tempo-zone", "corpus"].iter().chain(args))
                .unwrap_or_else(|err| panic!("{args:?}: {err}"));
            // Fill reads L1 through its own URL; replay and gc read none.
            let ZoneCli::Node {
                cli,
                l1_access: CliL1Access::Unused,
            } = parsed
            else {
                panic!("{args:?} parsed as another command");
            };
            assert!(matches!(
                cli.command,
                Commands::Ext(ZoneSubcommand::Corpus(_))
            ));
        }
    }

    #[test]
    fn recorded_reader_serves_only_recorded_reads() {
        let account = Address::repeat_byte(1);
        let slot = B256::repeat_byte(2);
        let reads = L1Reads(
            [
                (l1_read(account, Some(slot), 7), [3; 32]),
                (l1_read(account, None, 7), [4; 32]),
            ]
            .into_iter()
            .collect(),
        );
        let reader = RecordedReader(Arc::new(reads));
        assert_eq!(
            reader.read_l1_storage(account, slot, 7).unwrap(),
            B256::repeat_byte(3)
        );
        assert_eq!(
            reader.read_l1_commitment(account, 7).unwrap(),
            B256::repeat_byte(4)
        );
        // The same slot at another L1 block was not recorded.
        assert!(matches!(
            reader.read_l1_storage(account, slot, 8),
            Err(L1StateError::StorageUnavailable { reason, .. }) if reason == UNRECORDED
        ));
        assert!(matches!(
            reader.read_l1_commitment(account, 8),
            Err(L1StateError::AccountUnavailable { reason, .. }) if reason == UNRECORDED
        ));
    }
}
