//! Proactive, durable collection of per-block Zone and Tempo state proofs.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use alloy_primitives::{Address, B256};
use alloy_provider::DynProvider;
use alloy_rpc_types_eth::BlockId;
use eyre::{Context as _, OptionExt as _, Result, bail, ensure};
use futures::StreamExt as _;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tempo_alloy::TempoNetwork;
use tempo_zone_contracts::ZonePortal;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};
use zone_rpc::{ZoneDebugApi, types::ZoneExecutionWitness};

use crate::ZoneSequencerProvider;

// Persisted files survive upgrades; reject incompatible witness formats explicitly.
const FORMAT_VERSION: u32 = 1;
const FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Load unsettled witnesses and return the proof collector handle and worker future.
pub async fn create_proof_collector<P: ZoneSequencerProvider>(
    config: ProofCollectorConfig,
    provider: P,
) -> Result<(
    ProofCollectorHandle,
    impl Future<Output = ()> + Send + 'static,
)> {
    let directory = config.directory.clone();
    let finalized_zone_height = config.finalized_zone_height().await?;
    let store = Arc::new(
        tokio::task::spawn_blocking(move || ProofStore::open(directory, finalized_zone_height))
            .await
            .context("proof store opening task panicked")??,
    );
    let (requests_tx, requests_rx) = mpsc::channel(16);
    let collector = ProofCollector {
        config,
        provider,
        store: store.clone(),
        requests: requests_rx,
    };
    let handle = ProofCollectorHandle {
        store,
        requests: requests_tx,
    };
    Ok((handle, collector.run()))
}

/// Collection and retained-witness access shared with block import and both prover modes.
#[derive(Clone, Debug)]
pub struct ProofCollectorHandle {
    store: Arc<ProofStore>,
    requests: mpsc::Sender<ProofRequest>,
}

impl ProofCollectorHandle {
    /// Collect one executed block before it becomes canonical.
    ///
    /// Returns `None` for blocks already covered by finalized settlement. Otherwise the
    /// returned witness's file and directory have both been synced.
    /// Each explicit request gets one collection attempt. Dropping the request
    /// does not cancel an in-flight write.
    pub async fn collect_and_persist(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<Option<Arc<StoredBlockProof>>> {
        let (response, result) = oneshot::channel();
        self.requests
            .send(ProofRequest::Collect {
                number,
                hash,
                response,
            })
            .await
            .context("proof collector stopped")?;
        result
            .await
            .context("proof collector stopped before persistence")?
    }

    /// Persist a received witness without recollecting it. The caller must bind its metadata
    /// to the imported block; this does not validate witness contents or completeness.
    pub async fn persist_received(&self, proof: StoredBlockProof) -> Result<()> {
        proof.validate()?;
        let (response, result) = oneshot::channel();
        self.requests
            .send(ProofRequest::Persist {
                proof: Box::new(proof),
                response,
            })
            .await
            .context("proof collector stopped")?;
        result
            .await
            .context("proof collector stopped before persistence")?
    }

    /// Whether an imported block still needs a durable witness for future settlement.
    pub fn requires_witness(&self, number: u64) -> bool {
        number > self.store.state.read().pruned_through
    }

    /// Fill any restart or upgrade gaps before allowing a proving node to advance.
    pub async fn collect_canonical_tail<P: ZoneSequencerProvider>(
        &self,
        provider: &P,
    ) -> Result<()> {
        let start = self.store.state.read().pruned_through.saturating_add(1);
        let head = provider.best_block_number()?;
        for number in start..=head {
            let hash = provider
                .block_hash(number)?
                .ok_or_eyre(format!("canonical Zone block {number} has no hash"))?;
            self.collect_and_persist(number, hash).await?;
        }
        Ok(())
    }

    /// Return a retained witness for this exact block without waiting for collection.
    pub fn get(&self, number: u64, hash: B256) -> Option<Arc<StoredBlockProof>> {
        let state = self.store.state.read();
        if number <= state.pruned_through {
            return None;
        }
        state
            .proofs
            .get(&number)
            .filter(|proof| proof.witness.block_hash == hash)
            .cloned()
    }
}

struct ProofCollector<P> {
    config: ProofCollectorConfig,
    provider: P,
    store: Arc<ProofStore>,
    requests: mpsc::Receiver<ProofRequest>,
}

impl<P: ZoneSequencerProvider> ProofCollector<P> {
    async fn run(mut self) {
        info!(
            target: "zone::sequencer::proofs",
            directory = %self.config.directory.display(),
            "Proof collector started"
        );
        let mut canonical = self.provider.canonical_state_stream();
        let mut fallback = tokio::time::interval(FALLBACK_POLL_INTERVAL);

        loop {
            tokio::select! {
                request = self.requests.recv() => {
                    let Some(request) = request else {
                        return;
                    };
                    match request {
                        ProofRequest::Collect { number, hash, response } => {
                            let result = self.collect_and_persist(number, hash).await;
                            let _ = response.send(result);
                        }
                        ProofRequest::Persist { proof, response } => {
                            let result = self.persist(*proof).await.map(|_| ());
                            let _ = response.send(result);
                        }
                    }
                    continue;
                }
                _ = fallback.tick() => {}
                notification = canonical.next() => {
                    if notification.is_none() {
                        return;
                    }
                }
            }

            if let Err(error) = self.prune_and_collect().await {
                error!(target: "zone::sequencer::proofs", error = ?error, "Proof collection failed; retrying");
            }
        }
    }

    async fn prune_and_collect(&self) -> Result<()> {
        let finalized_zone_height = self.config.finalized_zone_height().await?;
        let store = self.store.clone();
        let provider = self.provider.clone();
        let head = tokio::task::spawn_blocking(move || {
            store
                .prune_through(finalized_zone_height)
                .unwrap_or_else(|error| panic!("failed to prune block proofs: {error:#}"));
            Ok::<_, eyre::Report>(provider.best_block_number()?)
        })
        .await
        .expect("proof pruning task panicked")?;

        let start = self.store.state.read().pruned_through.saturating_add(1);
        for number in start..=head {
            let block_hash = self
                .provider
                .block_hash(number)?
                .ok_or_eyre(format!("canonical Zone block {number} has no hash"))?;
            if !self.store.contains(number, block_hash) {
                self.collect_and_persist(number, block_hash).await?;
            }
        }
        Ok(())
    }

    async fn collect_and_persist(
        &self,
        number: u64,
        block_hash: B256,
    ) -> Result<Option<Arc<StoredBlockProof>>> {
        {
            let state = self.store.state.read();
            if number <= state.pruned_through {
                return Ok(None);
            }
            if let Some(proof) = state
                .proofs
                .get(&number)
                .filter(|proof| proof.witness.block_hash == block_hash)
            {
                return Ok(Some(proof.clone()));
            }
        }
        let proof = self.collect_block(block_hash).await?;
        ensure!(
            proof.witness.block_number == number,
            "witness height does not match Zone block {number}"
        );
        self.persist(proof).await
    }

    async fn persist(&self, proof: StoredBlockProof) -> Result<Option<Arc<StoredBlockProof>>> {
        let number = proof.witness.block_number;
        let block_hash = proof.witness.block_hash;
        if number <= self.store.state.read().pruned_through {
            return Ok(None);
        }
        // Retrying an already persisted witness must not unlink its durable file first.
        if self.store.contains(number, block_hash) {
            return Ok(self.store.state.read().proofs.get(&number).cloned());
        }
        let store = self.store.clone();
        let proof = tokio::task::spawn_blocking(move || {
            store.remove_files(number..=number)?;
            store.insert(proof)?;
            Ok::<_, eyre::Report>(store.state.read().proofs[&number].clone())
        })
        .await
        .expect("proof persistence task panicked")
        .unwrap_or_else(|error| panic!("failed to persist block proof: {error:#}"));
        info!(
            target: "zone::sequencer::proofs",
            zone_block = number,
            %block_hash,
            "Collected and persisted block proofs"
        );
        Ok(Some(proof))
    }

    async fn collect_block(&self, block_hash: B256) -> Result<StoredBlockProof> {
        let witness = self
            .config
            .debug_api
            .zone_execution_witness(block_hash.into())
            .await
            .map_err(|error| eyre::eyre!(error.to_string()))
            .wrap_err_with(|| format!("collect witness for Zone block {block_hash}"))?;
        ensure!(
            witness.block_hash == block_hash,
            "collected witness does not match Zone block {block_hash}"
        );
        Ok(StoredBlockProof {
            format_version: FORMAT_VERSION,
            witness,
        })
    }
}

/// Configuration for the proactive proof collector.
#[derive(Clone)]
pub struct ProofCollectorConfig {
    /// Directory containing immutable per-block JSON proof files.
    pub directory: PathBuf,
    /// In-process API used to replay an executed block and collect its Zone and Tempo witness.
    pub debug_api: Arc<dyn ZoneDebugApi>,
    /// Portal whose finalized Zone height determines pruning.
    pub portal_address: Address,
    /// L1 provider used to read the finalized Zone height.
    pub l1_provider: DynProvider<TempoNetwork>,
}

impl ProofCollectorConfig {
    async fn finalized_zone_height(&self) -> Result<u64> {
        Ok(u64::try_from(
            ZonePortal::new(self.portal_address, &self.l1_provider)
                .zoneHeight()
                .block(BlockId::finalized())
                .call()
                .await?,
        )?)
    }
}

impl std::fmt::Debug for ProofCollectorConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProofCollectorConfig")
            .field("directory", &self.directory)
            .field("debug_api", &"<in-process>")
            .field("portal_address", &self.portal_address)
            .finish()
    }
}

/// Persisted witnesses with an in-memory index.
/// Mutations are serialized by the collector; the lock only coordinates cache readers.
#[derive(Debug)]
struct ProofStore {
    directory: PathBuf,
    state: RwLock<ProofStoreState>,
}

impl ProofStore {
    fn open(directory: PathBuf, pruned_through: u64) -> Result<Self> {
        fs::create_dir_all(&directory)
            .wrap_err_with(|| format!("create proof directory {}", directory.display()))?;

        let mut proofs = BTreeMap::new();
        for entry in fs::read_dir(&directory)
            .wrap_err_with(|| format!("read proof directory {}", directory.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let file = File::open(&path)
                .wrap_err_with(|| format!("open stored proof {}", path.display()))?;
            let proof: StoredBlockProof = serde_json::from_reader(BufReader::new(file))
                .wrap_err_with(|| format!("decode stored proof {}", path.display()))?;
            proof.validate()?;
            ensure!(
                path.file_name() == Some(proof.file_name().as_ref()),
                "stored proof filename does not match contents: {}",
                path.display()
            );
            if proof.witness.block_number <= pruned_through {
                fs::remove_file(&path)
                    .wrap_err_with(|| format!("remove settled proof {}", path.display()))?;
                continue;
            }
            if proofs
                .insert(proof.witness.block_number, Arc::new(proof))
                .is_some()
            {
                bail!("duplicate stored proof height in {}", directory.display());
            }
        }
        sync_directory(&directory)?;

        Ok(Self {
            directory,
            state: RwLock::new(ProofStoreState {
                pruned_through,
                proofs,
            }),
        })
    }

    fn insert(&self, proof: StoredBlockProof) -> Result<()> {
        proof.validate()?;
        {
            let state = self.state.read();
            if proof.witness.block_number <= state.pruned_through {
                bail!(
                    "cannot store proof for settled Zone block {}",
                    proof.witness.block_number
                );
            }
            if let Some(existing) = state.proofs.get(&proof.witness.block_number) {
                ensure!(
                    existing.witness.block_hash == proof.witness.block_hash,
                    "conflicting proof already stored at Zone block {}",
                    proof.witness.block_number
                );
                return Ok(());
            }
        }

        let path = self.directory.join(proof.file_name());
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)
            .wrap_err_with(|| format!("create temporary proof in {}", self.directory.display()))?;
        {
            let mut writer = BufWriter::new(temporary.as_file_mut());
            serde_json::to_writer(&mut writer, &proof).context("encode block proof as JSON")?;
            writer.flush().context("flush block proof JSON")?;
        }
        temporary
            .as_file()
            .sync_all()
            .context("sync temporary block proof")?;
        fs::rename(temporary.path(), &path)
            .wrap_err_with(|| format!("publish stored proof {}", path.display()))?;
        sync_directory(&self.directory)?;

        self.state
            .write()
            .proofs
            .insert(proof.witness.block_number, Arc::new(proof));
        Ok(())
    }

    fn contains(&self, number: u64, hash: B256) -> bool {
        let state = self.state.read();
        number > state.pruned_through
            && state
                .proofs
                .get(&number)
                .is_some_and(|proof| proof.witness.block_hash == hash)
    }

    #[cfg(test)]
    fn snapshot(&self, from: u64, to: u64) -> Result<Vec<Arc<StoredBlockProof>>> {
        ensure!(from <= to, "invalid proof range {from}..={to}");
        let state = self.state.read();
        ensure!(from > state.pruned_through, "proof range has been pruned");
        (from..=to)
            .map(|number| {
                state
                    .proofs
                    .get(&number)
                    .cloned()
                    .ok_or_eyre(format!("proof for Zone block {number} is not collected"))
            })
            .collect()
    }

    fn prune_through(&self, through: u64) -> Result<()> {
        let through = {
            let mut state = self.state.write();
            state.pruned_through = state.pruned_through.max(through);
            state.pruned_through
        };
        self.remove_files(..=through)
    }

    fn remove_files(&self, range: impl std::ops::RangeBounds<u64>) -> Result<()> {
        let numbers = self
            .state
            .read()
            .proofs
            .range(range)
            .map(|(number, _)| *number)
            .collect::<Vec<_>>();
        if numbers.is_empty() {
            return Ok(());
        }
        for number in numbers {
            let path = self
                .directory
                .join(self.state.read().proofs[&number].file_name());
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .wrap_err_with(|| format!("remove stored proof {}", path.display()));
                }
            }
            let removed = self.state.write().proofs.remove(&number);
            drop(removed);
        }
        sync_directory(&self.directory)
    }
}

#[derive(Debug)]
struct ProofStoreState {
    pruned_through: u64,
    proofs: BTreeMap<u64, Arc<StoredBlockProof>>,
}

/// Immutable proof material collected for one executed Zone block, possibly not yet canonical.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredBlockProof {
    pub format_version: u32,
    pub witness: ZoneExecutionWitness,
}

impl StoredBlockProof {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == FORMAT_VERSION,
            "unsupported proof format version {}",
            self.format_version
        );
        ensure!(
            self.witness.block_number > 0,
            "cannot store a genesis block proof"
        );
        Ok(())
    }

    fn file_name(&self) -> std::ffi::OsString {
        format!(
            "{}-{:x}.json",
            self.witness.block_number, self.witness.block_hash
        )
        .into()
    }
}

enum ProofRequest {
    Collect {
        number: u64,
        hash: B256,
        response: oneshot::Sender<Result<Option<Arc<StoredBlockProof>>>>,
    },
    Persist {
        proof: Box<StoredBlockProof>,
        response: oneshot::Sender<Result<()>>,
    },
}

fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .wrap_err_with(|| format!("open proof directory {}", directory.display()))?
        .sync_all()
        .wrap_err_with(|| format!("sync proof directory {}", directory.display()))
}

#[cfg(test)]
mod tests {

    use alloy_primitives::Bytes;

    use super::*;

    fn proof(number: u64, hash: B256) -> StoredBlockProof {
        let mut execution_witness = ZoneExecutionWitness::default().execution_witness;
        execution_witness.state = vec![Bytes::from_static(b"zone")];
        execution_witness.codes = vec![Bytes::from_static(b"code")];
        execution_witness.headers = vec![Bytes::from_static(b"ancestor")];
        StoredBlockProof {
            format_version: FORMAT_VERSION,
            witness: ZoneExecutionWitness {
                block_number: number,
                block_hash: hash,
                execution_witness,
                tempo_state: vec![Bytes::from_static(b"tempo")],
                ..Default::default()
            },
        }
    }

    struct StubDebugApi(ZoneExecutionWitness);

    #[jsonrpsee::core::async_trait]
    impl ZoneDebugApi for StubDebugApi {
        async fn zone_execution_witness(
            &self,
            block: alloy_eips::BlockId,
        ) -> jsonrpsee::core::RpcResult<ZoneExecutionWitness> {
            assert_eq!(block, self.0.block_hash.into());
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn collection_returns_durable_witness_and_skips_settled_backfill() {
        use alloy_provider::{Provider as _, ProviderBuilder};
        use alloy_transport::mock::Asserter;
        use reth_provider::test_utils::MockEthProvider;
        use tempo_primitives::TempoPrimitives;

        let directory = tempfile::tempdir().unwrap();
        let expected = proof(2, B256::repeat_byte(2));
        let store = Arc::new(ProofStore::open(directory.path().to_path_buf(), 1).unwrap());
        let (_, requests) = mpsc::channel(1);
        let collector = ProofCollector {
            config: ProofCollectorConfig {
                directory: directory.path().to_path_buf(),
                debug_api: Arc::new(StubDebugApi(expected.witness.clone())),
                portal_address: Address::ZERO,
                l1_provider: ProviderBuilder::new_with_network::<TempoNetwork>()
                    .connect_mocked_client(Asserter::new())
                    .erased(),
            },
            provider: MockEthProvider::<TempoPrimitives>::new(),
            store: store.clone(),
            requests,
        };
        // Historical state for settled backfill is deliberately unavailable from the stub.
        assert!(
            collector
                .collect_and_persist(1, B256::repeat_byte(1))
                .await
                .unwrap()
                .is_none()
        );
        // A hash resolving to an unexpected height must never enter the store.
        assert!(
            collector
                .collect_and_persist(3, expected.witness.block_hash)
                .await
                .is_err()
        );
        assert!(store.state.read().proofs.is_empty());
        let retained = collector
            .collect_and_persist(2, expected.witness.block_hash)
            .await
            .unwrap()
            .unwrap();
        let reopened = ProofStore::open(directory.path().to_path_buf(), 1).unwrap();
        assert_eq!(*retained, expected);
        assert_eq!(*reopened.snapshot(2, 2).unwrap()[0], expected);
        store.prune_through(2).unwrap();
        // The collection response owns the input even if pruning runs before the caller resumes.
        assert_eq!(*retained, expected);
    }

    #[test]
    fn persists_loads_and_prunes_json_proofs() {
        let directory = tempfile::tempdir().unwrap();
        let hash = B256::repeat_byte(1);
        let store = ProofStore::open(directory.path().to_path_buf(), 0).unwrap();
        store.insert(proof(1, hash)).unwrap();
        assert_eq!(store.snapshot(1, 1).unwrap()[0].witness.block_hash, hash);
        assert!(store.contains(1, hash));
        assert!(!store.contains(1, B256::ZERO));
        let json = fs::read_to_string(directory.path().join(proof(1, hash).file_name())).unwrap();
        let stored_json: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(stored_json["formatVersion"], FORMAT_VERSION);
        assert_eq!(
            stored_json["witness"],
            serde_json::to_value(proof(1, hash).witness).unwrap()
        );

        let reopened = ProofStore::open(directory.path().to_path_buf(), 0).unwrap();
        assert_eq!(*reopened.snapshot(1, 1).unwrap()[0], proof(1, hash));
        reopened.prune_through(1).unwrap();
        assert!(!reopened.contains(1, hash));
        assert!(reopened.snapshot(1, 1).is_err());
        assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
    }

    #[test]
    fn startup_finalized_zone_height_excludes_history_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProofStore::open(directory.path().to_path_buf(), 0).unwrap();
        for number in 1..=3 {
            store
                .insert(proof(number, B256::with_last_byte(number as u8)))
                .unwrap();
        }
        drop(store);

        let store = Arc::new(ProofStore::open(directory.path().to_path_buf(), 2).unwrap());
        assert_eq!(store.state.read().pruned_through, 2);
        assert!(store.snapshot(1, 2).is_err());
        assert!(store.snapshot(3, 3).is_ok());
        assert!(
            !directory
                .path()
                .join(proof(2, B256::with_last_byte(2)).file_name())
                .exists()
        );
        assert!(store.insert(proof(2, B256::with_last_byte(2))).is_err());
    }

    #[test]
    fn rejects_conflicting_proof_at_the_same_height() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProofStore::open(directory.path().to_path_buf(), 0).unwrap();
        store.insert(proof(1, B256::repeat_byte(1))).unwrap();

        let error = store.insert(proof(1, B256::repeat_byte(2))).unwrap_err();
        assert!(error.to_string().contains("conflicting proof"));
    }

    #[test]
    fn retries_pruning_after_file_deletion_fails() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProofStore::open(directory.path().to_path_buf(), 0).unwrap();
        let proof = proof(1, B256::repeat_byte(1));
        let path = directory.path().join(proof.file_name());
        store.insert(proof).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        let error = store.prune_through(1).unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(store.state.read().pruned_through, 1);
        assert!(store.snapshot(1, 1).is_err());
        assert!(!store.contains(1, B256::repeat_byte(1)));

        fs::remove_dir(&path).unwrap();
        store.prune_through(1).unwrap();
        assert_eq!(store.state.read().pruned_through, 1);
        assert!(store.state.read().proofs.is_empty());
    }

    #[test]
    fn restart_retains_pending_proof_until_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let staged_hash = B256::repeat_byte(2);
        let store = ProofStore::open(directory.path().to_path_buf(), 0).unwrap();
        store.insert(proof(2, staged_hash)).unwrap();
        drop(store);

        let store = ProofStore::open(directory.path().to_path_buf(), 1).unwrap();
        store.prune_through(1).unwrap();
        assert!(store.contains(2, staged_hash));
        let canonical_hash = B256::repeat_byte(3);
        assert!(!store.contains(2, canonical_hash));
        store.insert(proof(3, B256::repeat_byte(4))).unwrap();
        // Collection replaces only the conflicting proof, preserving newer witnesses.
        store.remove_files(2..=2).unwrap();
        store.insert(proof(2, canonical_hash)).unwrap();
        assert!(!store.contains(2, staged_hash));
        assert!(store.contains(2, canonical_hash));
        assert!(store.contains(3, B256::repeat_byte(4)));
        assert!(
            !directory
                .path()
                .join(proof(2, staged_hash).file_name())
                .exists()
        );
    }

    #[test]
    fn retries_removal_after_partial_deletion() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProofStore::open(directory.path().to_path_buf(), 0).unwrap();
        store.insert(proof(1, B256::repeat_byte(1))).unwrap();
        let second = proof(2, B256::repeat_byte(2));
        let path = directory.path().join(second.file_name());
        store.insert(second).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        let error = store.remove_files(1..).unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(!store.contains(1, B256::repeat_byte(1)));
        assert!(store.snapshot(1, 1).is_err());
        assert!(store.contains(2, B256::repeat_byte(2)));
        // Re-persisting the deleted proof must recreate its file.
        let first = proof(1, B256::repeat_byte(1));
        let first_path = directory.path().join(first.file_name());
        assert!(!first_path.exists());
        store.insert(first).unwrap();
        assert!(first_path.is_file());
        fs::remove_dir(&path).unwrap();
        store.remove_files(1..).unwrap();
        assert!(store.state.read().proofs.is_empty());
        assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
    }

    #[test]
    fn loaded_witness_survives_pruning_but_new_reads_miss() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(ProofStore::open(directory.path().to_path_buf(), 0).unwrap());
        let hash = B256::repeat_byte(1);
        store.insert(proof(1, hash)).unwrap();
        let (requests, _) = mpsc::channel(1);
        let handle = ProofCollectorHandle {
            store: store.clone(),
            requests,
        };
        assert!(handle.get(1, B256::repeat_byte(2)).is_none());
        let loaded = handle.get(1, hash).unwrap();
        store.prune_through(1).unwrap();
        assert!(handle.get(1, hash).is_none());
        assert_eq!(loaded.witness.block_hash, hash);
        assert!(!directory.path().join(loaded.file_name()).exists());
        store.prune_through(0).unwrap();
        assert_eq!(store.state.read().pruned_through, 1);
    }

    #[tokio::test]
    async fn collection_request_returns_its_result_or_worker_exit() {
        for outcome in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let store = Arc::new(ProofStore::open(directory.path().to_path_buf(), 0).unwrap());
            let (requests, mut receiver) = mpsc::channel::<ProofRequest>(1);
            let handle = ProofCollectorHandle { store, requests };
            let waiter = handle.collect_and_persist(1, B256::ZERO);
            tokio::pin!(waiter);
            let responder = async {
                let ProofRequest::Collect {
                    number,
                    hash,
                    response,
                } = receiver.recv().await.unwrap()
                else {
                    panic!("expected a collection request");
                };
                assert_eq!(number, 1);
                assert_eq!(hash, B256::ZERO);
                // Completion depends only on the response, not background readiness.
                match outcome {
                    0 => {
                        response
                            .send(Ok(Some(Arc::new(proof(1, B256::ZERO)))))
                            .unwrap();
                    }
                    1 => {
                        response
                            .send(Err(std::io::Error::from(
                                std::io::ErrorKind::PermissionDenied,
                            )
                            .into()))
                            .unwrap();
                    }
                    _ => {}
                }
            };
            let (result, ()) = tokio::join!(waiter, responder);
            match outcome {
                0 => assert_eq!(result.unwrap().unwrap().witness.block_number, 1),
                1 => assert_eq!(
                    result
                        .unwrap_err()
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .kind(),
                    std::io::ErrorKind::PermissionDenied,
                ),
                _ => assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("proof collector stopped")
                ),
            }
        }
    }
}
