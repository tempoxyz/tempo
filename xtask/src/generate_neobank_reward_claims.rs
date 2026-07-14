//! Deterministic Merkl reward-claim fixture generation for the neobank benchmark.

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    signers::{
        local::coins_bip39::{English, Mnemonic},
        utils::secret_key_to_address,
    },
    sol,
    sol_types::{SolCall, SolValue},
};
use coins_bip32::{BIP32_HARDEN, prelude::*};
use eyre::{Context as _, ensure};
use rayon::prelude::*;
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::{
    collections::HashSet,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

const DEFAULT_MNEMONIC: &str = "test test test test test test test test test test test junk";
const DEFAULT_CLAIM_COUNT: usize = 1 << 11;
const DEFAULT_CUMULATIVE_AMOUNT: u64 = 43_860;
const DEFAULT_ACCOUNT_POOL: &str = "reward_claimants";
const CLAIM_SIGNATURE: &str = "claim(address[],address[],uint256[],bytes32[][])";

sol! {
    interface Distributor {
        function claim(
            address[] calldata users,
            address[] calldata tokens,
            uint256[] calldata amounts,
            bytes32[][] calldata proofs
        ) external;
    }
}

/// Generate deterministic Merkl claim records for the neobank txgen preset.
#[derive(Debug, clap::Args)]
pub(crate) struct GenerateNeobankRewardClaims {
    /// Wrapper token used in every Merkl leaf.
    #[arg(long)]
    wrapper_token: Address,

    /// Number of usable claim records to emit. The tree is padded to a power of two.
    #[arg(long, default_value_t = DEFAULT_CLAIM_COUNT)]
    claims: usize,

    /// Cumulative reward amount in the wrapper token's smallest unit.
    #[arg(long, default_value_t = U256::from(DEFAULT_CUMULATIVE_AMOUNT))]
    cumulative_amount: U256,

    /// First BIP-44 account index used to construct claim leaves.
    #[arg(long, default_value_t = 0)]
    account_start: u32,

    /// Mnemonic backing the txgen account pool.
    #[arg(long, default_value = DEFAULT_MNEMONIC)]
    mnemonic: String,

    /// Account pool referenced by each generated record.
    #[arg(long, default_value = DEFAULT_ACCOUNT_POOL)]
    account_pool: String,

    /// JSON output containing the txgen records array.
    #[arg(short, long)]
    out: PathBuf,

    /// Metadata output. Defaults to `<out stem>.meta.json`.
    #[arg(long)]
    metadata_out: Option<PathBuf>,

    /// Verify that both existing outputs exactly match freshly generated content.
    #[arg(long)]
    check: bool,
}

impl GenerateNeobankRewardClaims {
    pub(crate) fn run(self) -> eyre::Result<()> {
        let metadata_out = self
            .metadata_out
            .clone()
            .unwrap_or_else(|| self.out.with_extension("meta.json"));
        ensure!(
            self.out != metadata_out,
            "record and metadata outputs must differ"
        );

        let fixture = Fixture::build(
            &self.mnemonic,
            self.account_start,
            self.claims,
            self.wrapper_token,
            self.cumulative_amount,
            &self.account_pool,
        )?;

        let records_bytes = if self.check {
            check_records(&self.out, &fixture)?
        } else {
            write_records_file(&self.out, &fixture)?
        };
        let metadata = fixture.metadata(records_bytes)?;

        if self.check {
            check_json(&metadata_out, &metadata)?;
            println!("Neobank reward-claim fixtures are reproducible:");
        } else {
            write_json_file(&metadata_out, &metadata)?;
            println!("Generated neobank reward-claim fixtures:");
        }
        println!("  Records: {}", self.out.display());
        println!("  Metadata: {}", metadata_out.display());
        println!("  Merkle root: {}", metadata.merkle_root);
        println!("  Claim records: {}", metadata.claim_count);
        println!("  Dummy leaves: {}", metadata.dummy_leaf_count);
        println!("  Proof depth: {}", metadata.proof_depth);
        println!(
            "  Records size: {} bytes ({:.2} MiB)",
            records_bytes,
            records_bytes as f64 / (1024.0 * 1024.0)
        );
        println!(
            "  Calldata per record: {} bytes",
            metadata.calldata_bytes_per_record
        );

        Ok(())
    }
}

#[derive(Debug)]
struct Fixture {
    account_start: u32,
    account_pool: String,
    wrapper_token: Address,
    cumulative_amount: U256,
    users: Vec<Address>,
    layers: Vec<Vec<B256>>,
}

impl Fixture {
    fn build(
        mnemonic: &str,
        account_start: u32,
        claim_count: usize,
        wrapper_token: Address,
        cumulative_amount: U256,
        account_pool: &str,
    ) -> eyre::Result<Self> {
        ensure!(claim_count > 0, "claim count must be greater than zero");
        ensure!(
            !account_pool.trim().is_empty(),
            "account pool must not be empty"
        );
        ensure!(
            wrapper_token != Address::ZERO,
            "wrapper token must not be the zero address"
        );
        ensure!(
            cumulative_amount > U256::ZERO,
            "cumulative amount must be greater than zero"
        );

        let tree_leaf_count = claim_count
            .checked_next_power_of_two()
            .ok_or_else(|| eyre::eyre!("claim count is too large"))?;
        let last_offset = u32::try_from(tree_leaf_count - 1)
            .wrap_err("tree contains more leaves than BIP-44 indices")?;
        let last_account_index = account_start
            .checked_add(last_offset)
            .ok_or_else(|| eyre::eyre!("tree leaf account indices overflow u32"))?;
        ensure!(
            last_account_index < BIP32_HARDEN,
            "tree leaf account indices must remain below the hardened BIP-32 range"
        );

        let parent_key = Arc::new(derive_parent_key(mnemonic)?);
        let derived: Vec<(Address, B256)> = (0..tree_leaf_count)
            .into_par_iter()
            .map(|offset| -> eyre::Result<_> {
                let offset = u32::try_from(offset).expect("leaf count was bounded to u32");
                let account_index = account_start
                    .checked_add(offset)
                    .expect("account range was validated");
                let user = derive_address(&parent_key, account_index)?;
                Ok((user, merkl_leaf(user, wrapper_token, cumulative_amount)))
            })
            .collect::<eyre::Result<_>>()?;
        ensure!(
            derived
                .iter()
                .map(|(_, leaf)| leaf)
                .collect::<HashSet<_>>()
                .len()
                == tree_leaf_count,
            "derived Merkl leaves are not unique"
        );

        let users = derived
            .iter()
            .take(claim_count)
            .map(|(user, _)| *user)
            .collect();
        let leaves = derived.into_iter().map(|(_, leaf)| leaf).collect();
        let layers = merkle_layers(leaves);

        Ok(Self {
            account_start,
            account_pool: account_pool.to_owned(),
            wrapper_token,
            cumulative_amount,
            users,
            layers,
        })
    }

    fn claim_count(&self) -> usize {
        self.users.len()
    }

    fn tree_leaf_count(&self) -> usize {
        self.layers[0].len()
    }

    fn proof_depth(&self) -> usize {
        self.layers.len() - 1
    }

    fn root(&self) -> B256 {
        self.layers.last().expect("tree has a root layer")[0]
    }

    fn proof(&self, leaf_index: usize) -> Vec<B256> {
        debug_assert!(leaf_index < self.tree_leaf_count());
        let mut index = leaf_index;
        let mut proof = Vec::with_capacity(self.proof_depth());
        for layer in &self.layers[..self.proof_depth()] {
            proof.push(layer[index ^ 1]);
            index /= 2;
        }
        proof
    }

    fn calldata(&self, claim_index: usize) -> Vec<u8> {
        Distributor::claimCall {
            users: vec![self.users[claim_index]],
            tokens: vec![self.wrapper_token],
            amounts: vec![self.cumulative_amount],
            proofs: vec![self.proof(claim_index)],
        }
        .abi_encode()
    }

    fn metadata(&self, records_bytes: u64) -> eyre::Result<Metadata> {
        let claim_count_u64 = u64::try_from(self.claim_count())?;
        let total_funding = self
            .cumulative_amount
            .checked_mul(U256::from(claim_count_u64))
            .ok_or_else(|| eyre::eyre!("total claim funding overflows uint256"))?;
        let account_end = u64::from(self.account_start) + claim_count_u64;
        let padding_account_end =
            u64::from(self.account_start) + u64::try_from(self.tree_leaf_count())?;

        Ok(Metadata {
            format_version: 1,
            merkle_root: format!("{:#x}", self.root()),
            wrapper_token: format!("{:#x}", self.wrapper_token),
            cumulative_amount: self.cumulative_amount.to_string(),
            total_claim_funding: total_funding.to_string(),
            claim_function: CLAIM_SIGNATURE,
            account_pool: self.account_pool.clone(),
            mnemonic_derivation_path: "m/44'/60'/0'/0/{index}",
            account_start: self.account_start,
            account_end,
            padding_account_end,
            claim_count: self.claim_count(),
            tree_leaf_count: self.tree_leaf_count(),
            dummy_leaf_count: self.tree_leaf_count() - self.claim_count(),
            proof_depth: self.proof_depth(),
            calldata_bytes_per_record: self.calldata(0).len(),
            records_bytes,
        })
    }
}

#[derive(Debug, Serialize)]
struct Metadata {
    format_version: u8,
    merkle_root: String,
    wrapper_token: String,
    cumulative_amount: String,
    total_claim_funding: String,
    claim_function: &'static str,
    account_pool: String,
    mnemonic_derivation_path: &'static str,
    account_start: u32,
    account_end: u64,
    padding_account_end: u64,
    claim_count: usize,
    tree_leaf_count: usize,
    dummy_leaf_count: usize,
    proof_depth: usize,
    calldata_bytes_per_record: usize,
    records_bytes: u64,
}

struct Records<'a>(&'a Fixture);

impl Serialize for Records<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let fixture = self.0;
        let mut seq = serializer.serialize_seq(Some(fixture.claim_count()))?;
        for index in 0..fixture.claim_count() {
            let input = format!("0x{}", const_hex::encode(fixture.calldata(index)));
            seq.serialize_element(&Record {
                from: RecordAccount {
                    pool: &fixture.account_pool,
                    select: RecordSelection { index },
                },
                input,
            })?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct Record<'a> {
    from: RecordAccount<'a>,
    input: String,
}

#[derive(Serialize)]
struct RecordAccount<'a> {
    pool: &'a str,
    select: RecordSelection,
}

#[derive(Serialize)]
struct RecordSelection {
    index: usize,
}

fn derive_parent_key(mnemonic_phrase: &str) -> eyre::Result<XPriv> {
    let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_phrase)
        .map_err(|err| eyre::eyre!("invalid mnemonic: {err}"))?;
    mnemonic
        .derive_key("m/44'/60'/0'/0", None)
        .map_err(|err| eyre::eyre!("key derivation failed: {err}"))
}

fn derive_address(parent_key: &XPriv, index: u32) -> eyre::Result<Address> {
    let child = parent_key
        .derive_child(index)
        .map_err(|err| eyre::eyre!("failed to derive account {index}: {err}"))?;
    let key: &coins_bip32::prelude::SigningKey = child.as_ref();
    Ok(secret_key_to_address(key))
}

fn merkl_leaf(user: Address, wrapper_token: Address, cumulative_amount: U256) -> B256 {
    keccak256((user, wrapper_token, cumulative_amount).abi_encode())
}

fn merkle_layers(leaves: Vec<B256>) -> Vec<Vec<B256>> {
    debug_assert!(leaves.len().is_power_of_two());
    let mut layers = vec![leaves];
    while layers.last().expect("at least one layer").len() > 1 {
        let next = layers
            .last()
            .expect("at least one layer")
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash_sorted_pair(pair[0], pair[1]))
            .collect();
        layers.push(next);
    }
    layers
}

fn hash_sorted_pair(a: B256, b: B256) -> B256 {
    let (first, second) = if a < b { (a, b) } else { (b, a) };
    keccak256((first, second).abi_encode())
}

#[cfg(test)]
fn verify_proof(leaf: B256, proof: &[B256], root: B256) -> bool {
    proof
        .iter()
        .fold(leaf, |hash, sibling| hash_sorted_pair(hash, *sibling))
        == root
}

fn write_records_file(path: &Path, fixture: &Fixture) -> eyre::Result<u64> {
    ensure_parent_exists(path)?;
    let file = File::create(path)
        .wrap_err_with(|| format!("failed to create record output {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let bytes = {
        let mut counter = CountingWriter::new(&mut writer);
        serde_json::to_writer(&mut counter, &Records(fixture))?;
        counter.write_all(b"\n")?;
        counter.bytes_written
    };
    writer.flush()?;
    Ok(bytes)
}

fn write_json_file(path: &Path, value: &impl Serialize) -> eyre::Result<()> {
    ensure_parent_exists(path)?;
    let file = File::create(path)
        .wrap_err_with(|| format!("failed to create metadata output {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn ensure_parent_exists(path: &Path) -> eyre::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create output directory {}", parent.display()))?;
    }
    Ok(())
}

fn check_records(path: &Path, fixture: &Fixture) -> eyre::Result<u64> {
    let file = File::open(path)
        .wrap_err_with(|| format!("failed to open record fixture {}", path.display()))?;
    let mut writer = BufWriter::new(ExactFileWriter::new(file));
    serde_json::to_writer(&mut writer, &Records(fixture))?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer
        .into_inner()
        .map_err(|err| err.into_error())?
        .finish(path)
}

fn check_json(path: &Path, value: &impl Serialize) -> eyre::Result<()> {
    let file = File::open(path)
        .wrap_err_with(|| format!("failed to open metadata fixture {}", path.display()))?;
    let mut writer = BufWriter::new(ExactFileWriter::new(file));
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer
        .into_inner()
        .map_err(|err| err.into_error())?
        .finish(path)?;
    Ok(())
}

struct CountingWriter<W> {
    inner: W,
    bytes_written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.bytes_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct ExactFileWriter {
    expected: BufReader<File>,
    compared: u64,
}

impl ExactFileWriter {
    fn new(file: File) -> Self {
        Self {
            expected: BufReader::new(file),
            compared: 0,
        }
    }

    fn finish(mut self, path: &Path) -> eyre::Result<u64> {
        let mut trailing = [0u8; 1];
        ensure!(
            self.expected.read(&mut trailing)? == 0,
            "{} differs from generated fixture at byte {} (existing file has trailing data)",
            path.display(),
            self.compared
        );
        Ok(self.compared)
    }
}

impl Write for ExactFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut expected = vec![0u8; buf.len()];
        let mut read = 0;
        while read < expected.len() {
            let count = self.expected.read(&mut expected[read..])?;
            if count == 0 {
                return Err(std::io::Error::other(format!(
                    "existing fixture ended at byte {}",
                    self.compared + read as u64
                )));
            }
            read += count;
        }
        if let Some(offset) = expected
            .iter()
            .zip(buf)
            .position(|(expected, generated)| expected != generated)
        {
            return Err(std::io::Error::other(format!(
                "fixture differs at byte {}",
                self.compared + offset as u64
            )));
        }
        self.compared += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const WRAPPER: Address = Address::repeat_byte(0x11);

    #[test]
    fn derives_txgen_accounts_and_exact_solidity_leaf() {
        let parent = derive_parent_key(DEFAULT_MNEMONIC).unwrap();
        let user = derive_address(&parent, 0).unwrap();
        assert_eq!(
            user,
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
                .parse::<Address>()
                .unwrap()
        );

        let amount = U256::from(DEFAULT_CUMULATIVE_AMOUNT);
        let mut abi_encoded = [0u8; 96];
        abi_encoded[12..32].copy_from_slice(user.as_slice());
        abi_encoded[44..64].copy_from_slice(WRAPPER.as_slice());
        abi_encoded[64..].copy_from_slice(&amount.to_be_bytes::<32>());
        assert_eq!(merkl_leaf(user, WRAPPER, amount), keccak256(abi_encoded));
    }

    #[test]
    fn pads_with_unique_derived_leaves_and_builds_valid_proofs() {
        let fixture = Fixture::build(
            DEFAULT_MNEMONIC,
            0,
            3,
            WRAPPER,
            U256::from(DEFAULT_CUMULATIVE_AMOUNT),
            DEFAULT_ACCOUNT_POOL,
        )
        .unwrap();

        assert_eq!(fixture.claim_count(), 3);
        assert_eq!(fixture.tree_leaf_count(), 4);
        assert_eq!(fixture.proof_depth(), 2);
        assert_eq!(fixture.layers[0].iter().collect::<HashSet<_>>().len(), 4);
        for index in 0..fixture.claim_count() {
            assert!(verify_proof(
                fixture.layers[0][index],
                &fixture.proof(index),
                fixture.root()
            ));
        }
    }

    #[test]
    fn emits_txgen_records_with_distributor_claim_calldata() {
        let fixture = Fixture::build(
            DEFAULT_MNEMONIC,
            0,
            2,
            WRAPPER,
            U256::from(DEFAULT_CUMULATIVE_AMOUNT),
            DEFAULT_ACCOUNT_POOL,
        )
        .unwrap();
        let calldata = fixture.calldata(1);
        assert_eq!(&calldata[..4], &[0x71, 0xee, 0x95, 0xc0]);
        let decoded = Distributor::claimCall::abi_decode(&calldata).unwrap();
        assert_eq!(decoded.users, vec![fixture.users[1]]);
        assert_eq!(decoded.tokens, vec![WRAPPER]);
        assert_eq!(decoded.amounts, vec![U256::from(DEFAULT_CUMULATIVE_AMOUNT)]);
        assert_eq!(decoded.proofs, vec![fixture.proof(1)]);

        let first = serde_json::to_vec(&Records(&fixture)).unwrap();
        let second = serde_json::to_vec(&Records(&fixture)).unwrap();
        assert_eq!(first, second);
        let json: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(json[1]["from"]["pool"], DEFAULT_ACCOUNT_POOL);
        assert_eq!(json[1]["from"]["select"]["index"], 1);
        assert_eq!(
            json[1]["input"].as_str().unwrap(),
            format!("0x{}", const_hex::encode(calldata))
        );
    }

    #[test]
    fn sorted_pair_proof_does_not_depend_on_sibling_order() {
        let a = keccak256(b"a");
        let b = keccak256(b"b");
        assert_eq!(hash_sorted_pair(a, b), hash_sorted_pair(b, a));
    }

    #[test]
    fn rejects_hardened_final_account_component() {
        let result = Fixture::build(
            DEFAULT_MNEMONIC,
            BIP32_HARDEN,
            1,
            WRAPPER,
            U256::from(DEFAULT_CUMULATIVE_AMOUNT),
            DEFAULT_ACCOUNT_POOL,
        );
        assert!(result.is_err());
    }

    #[test]
    fn committed_fixture_and_preset_are_stable() {
        let parent = derive_parent_key(DEFAULT_MNEMONIC).unwrap();
        let reward_admin = derive_address(&parent, 100_001).unwrap();
        assert_eq!(
            reward_admin,
            "0xd7932ce865275be97001a0574441d79b143820ec"
                .parse::<Address>()
                .unwrap()
        );

        let wrapper = "0x878e9282ca9a0fadd5832c2bf933c197f60e4165"
            .parse::<Address>()
            .unwrap();
        assert_eq!(reward_admin.create(4), wrapper);

        let fixture = Fixture::build(
            DEFAULT_MNEMONIC,
            0,
            DEFAULT_CLAIM_COUNT,
            wrapper,
            U256::from(DEFAULT_CUMULATIVE_AMOUNT),
            DEFAULT_ACCOUNT_POOL,
        )
        .unwrap();

        assert_eq!(fixture.proof_depth(), 11);
        assert_eq!(fixture.calldata(0).len(), 772);
        let root = "0xd5e22956036f00808b0b02c3ef5f41d8b308e8ff4683429f7ca239e900a4ac72";
        assert_eq!(fixture.root(), root.parse::<B256>().unwrap());

        let claim_preset = include_str!("../../contrib/bench/txgen/presets/neobank-claim.yml");
        assert!(claim_preset.contains(root.trim_start_matches("0x")));
        assert!(claim_preset.contains("\"1000000000000\""));
        assert!(claim_preset.contains("artifact: MerklBenchmarkDistributor"));

        let base_preset = include_str!("../../contrib/bench/txgen/presets/neobank-swap.yml");
        let directswap_seed = base_preset
            .split_once("- id: directswap_seed_token0")
            .unwrap()
            .1
            .split("\n    - id:")
            .next()
            .unwrap();
        assert!(directswap_seed.contains("pool: users"));
        assert!(directswap_seed.contains("function: mint"));
        assert!(directswap_seed.contains("{ var: setup.directswap.address }"));
        assert!(directswap_seed.contains("\"1000000000000000000\""));

        let deployment_ids = [
            "- id: reward_access_control",
            "- id: reward_distributor_implementation",
            "- id: reward_distributor\n",
            "- id: reward_distribution_creator",
            "- id: reward_wrapper",
        ];
        let positions: Vec<_> = deployment_ids
            .iter()
            .map(|id| {
                claim_preset
                    .find(id)
                    .expect("reward deployment must remain in preset")
            })
            .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
