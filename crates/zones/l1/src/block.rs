use super::*;
use rayon::prelude::*;
use std::collections::{BTreeMap, btree_map::Entry};

/// Avoid blocking and Rayon scheduling overhead for small deposit batches.
const MIN_PARALLEL_DEPOSITS: usize = 10;

/// An L1 block's header paired with the deposits found in that block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct L1BlockDeposits {
    /// The sealed L1 block header (caches the block hash).
    pub header: SealedHeader<TempoHeader>,
    /// Portal events extracted from this block.
    pub events: L1PortalEvents,
}

impl L1BlockDeposits {
    /// Prepare portal work accumulated across checkpoint-only blocks for one full import.
    pub async fn prepare_many(
        blocks: Vec<Self>,
        encryption_keys: &EncryptionKeyRing,
        portal_address: Address,
    ) -> eyre::Result<PreparedL1Block> {
        let follows_checkpoint_blocks = blocks.len() > 1;
        let mut blocks = blocks.into_iter();
        let first = blocks
            .next()
            .ok_or_else(|| eyre::eyre!("cannot prepare an empty L1 range"))?;
        let mut prepared = first.prepare(encryption_keys, portal_address).await?;
        for block in blocks {
            let next = block.prepare(encryption_keys, portal_address).await?;
            prepared.header = next.header;
            prepared.queued_deposits.extend(next.queued_deposits);
            prepared.decryptions.extend(next.decryptions);
            prepared.enabled_tokens.extend(next.enabled_tokens);
        }
        eyre::ensure!(
            prepared.queued_deposits.len() <= zone_primitives::constants::MAX_UNPROCESSED_DEPOSITS,
            "outstanding deposit suffix exceeds protocol capacity"
        );
        eyre::ensure!(
            prepared.enabled_tokens.len()
                <= zone_primitives::constants::MAX_UNPROCESSED_TOKEN_ENABLEMENTS,
            "outstanding token-enablement suffix exceeds protocol capacity"
        );
        prepared.follows_checkpoint_blocks = follows_checkpoint_blocks;
        Ok(prepared)
    }

    /// Prepare all deposits for the payload builder.
    ///
    /// Decrypts ordinary deposits and proves ECDH for forced requests without interpreting
    /// their plaintext. Preserves the complete mixed queue for `advanceTempo`.
    /// Mint-recipient policy is enforced by upstream TIP-20 after the L1 state is anchored.
    /// The resulting [`PreparedL1Block`] is ready to be passed via payload attributes to the
    /// builder.
    pub async fn prepare(
        self,
        encryption_keys: &EncryptionKeyRing,
        portal_address: Address,
    ) -> eyre::Result<PreparedL1Block> {
        let start = std::time::Instant::now();
        let l1_block_number = self.header.inner.number;
        let (total_deposits, deposits) = (self.events.deposits.len(), self.events.deposits);

        // Resolve keys in deposit order before parallel work so missing-key errors remain stable.
        let mut keys: BTreeMap<U256, k256::SecretKey> = BTreeMap::new();
        let mut encrypted_deposits = 0;
        for deposit in &deposits {
            let key_index = match deposit {
                L1Deposit::Deposit(d) => d.key_index,
                L1Deposit::ForcedExit(d) => d.entry.keyIndex,
                L1Deposit::WithdrawalBounceBack(_) => continue,
            };
            encrypted_deposits += 1;
            if let Entry::Vacant(entry) = keys.entry(key_index) {
                entry.insert(encryption_keys.key(key_index)?);
            }
        }

        let prepared = if encrypted_deposits < MIN_PARALLEL_DEPOSITS {
            deposits
                .iter()
                .map(|deposit| prepare_deposit(deposit, &keys, portal_address, l1_block_number))
                .collect::<Vec<_>>()
        } else {
            tokio::task::spawn_blocking(move || {
                deposits
                    .par_iter()
                    .map(|deposit| prepare_deposit(deposit, &keys, portal_address, l1_block_number))
                    .collect::<Vec<_>>()
            })
            .await?
        };

        let mut queued_deposits: Vec<abi::QueuedDeposit> = Vec::with_capacity(prepared.len());
        let mut decryptions: Vec<abi::DecryptionData> = Vec::with_capacity(encrypted_deposits);
        for result in prepared {
            let (queued, decryption) = result?;
            queued_deposits.push(queued);
            decryptions.extend(decryption);
        }

        let enabled_tokens: Vec<_> = self
            .events
            .enabled_tokens
            .iter()
            .map(|t| t.to_abi())
            .collect();

        let elapsed = start.elapsed();
        info!(
            target: "zone::engine",
            l1_block = l1_block_number,
            total_deposits,
            encrypted = decryptions.len(),
            enabled_tokens = enabled_tokens.len(),
            ?elapsed,
            "Prepared L1 block deposits"
        );

        Ok(PreparedL1Block {
            header: self.header,
            queued_deposits,
            decryptions,
            enabled_tokens,
            follows_checkpoint_blocks: false,
        })
    }
}

/// An L1 block with deposits fully prepared for the payload builder.
///
/// Ordinary deposits are decrypted; forced requests carry ECDH proofs and remain encrypted.
/// The builder only needs to RLP-encode the header and assemble the `advanceTempo` calldata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreparedL1Block {
    /// The sealed L1 block header.
    pub header: SealedHeader<TempoHeader>,
    /// ABI-encoded deposits, forced requests, and internal withdrawal bounce-backs.
    #[serde(skip)]
    pub queued_deposits: Vec<abi::QueuedDeposit>,
    /// Decryption data for every encrypted queue entry, in order.
    #[serde(skip)]
    pub decryptions: Vec<abi::DecryptionData>,
    /// Tokens newly enabled for bridging in this block.
    #[serde(skip)]
    pub enabled_tokens: Vec<abi::EnabledToken>,
    /// Whether this is the first full import following checkpoint-only Zone blocks.
    /// Such a block closes the settlement batch containing that prefix, and signals a batch boundary.
    #[serde(skip)]
    pub follows_checkpoint_blocks: bool,
}

/// ABI-encode a single queue entry and, for user deposits, derive the decryption data the on-chain
/// verification expects.
fn prepare_deposit(
    deposit: &L1Deposit,
    keys: &BTreeMap<U256, k256::SecretKey>,
    portal_address: Address,
    l1_block_number: u64,
) -> eyre::Result<(abi::QueuedDeposit, Option<abi::DecryptionData>)> {
    use crate::precompiles::ecies;

    let queued = deposit.to_abi_queued_deposit();
    if let L1Deposit::ForcedExit(d) = deposit {
        let key = keys
            .get(&d.entry.keyIndex)
            .expect("every forced request key is resolved before preparation");
        let encrypted = &d.entry.encrypted;
        let proof = ecies::compute_ecdh_proof(
            key,
            &encrypted.ephemeralPubkeyX,
            encrypted.ephemeralPubkeyYParity,
        )
        .ok_or_else(|| {
            eyre::eyre!(
                "cannot prepare ECDH proof for forced request {} at deposit {}",
                d.entry.requestId,
                d.deposit_number,
            )
        })?;
        return Ok((
            queued,
            Some(abi::DecryptionData {
                sharedSecret: proof.shared_secret,
                sharedSecretYParity: proof.shared_secret_y_parity,
                cpProof: proof.cp_proof,
            }),
        ));
    }
    let L1Deposit::Deposit(d) = deposit else {
        return Ok((queued, None));
    };
    let decryption_key = keys
        .get(&d.key_index)
        .expect("every deposit's key index is resolved before decryption");

    // Attempt full ECIES decryption.
    let dec = ecies::decrypt_deposit(
        decryption_key,
        &d.ephemeral_pubkey_x,
        d.ephemeral_pubkey_y_parity,
        &d.ciphertext,
        &d.nonce,
        &d.tag,
        portal_address,
        d.key_index,
        d.sender,
    );

    if let Some(dec) = dec {
        debug!(
            target: "zone::engine",
            l1_block = l1_block_number,
            sender = %d.sender,
            recipient = %dec.to,
            token = %d.token,
            amount = %d.amount,
            "Decrypted deposit"
        );

        return Ok((
            queued,
            Some(abi::DecryptionData {
                sharedSecret: dec.proof.shared_secret,
                sharedSecretYParity: dec.proof.shared_secret_y_parity,
                cpProof: dec.proof.cp_proof,
            }),
        ));
    }

    // Full decryption failed — try ECDH proof for on-chain refund.
    let proof = ecies::compute_ecdh_proof(
        decryption_key,
        &d.ephemeral_pubkey_x,
        d.ephemeral_pubkey_y_parity,
    );

    if let Some(proof) = proof {
        warn!(
            target: "zone::payload",
            sender = %d.sender,
            amount = %d.amount,
            "Encrypted deposit decryption failed, providing valid proof for on-chain refund"
        );
        return Ok((
            queued,
            Some(abi::DecryptionData {
                sharedSecret: proof.shared_secret,
                sharedSecretYParity: proof.shared_secret_y_parity,
                cpProof: proof.cp_proof,
            }),
        ));
    }

    warn!(
        target: "zone::payload",
        sender = %d.sender,
        amount = %d.amount,
        "Encrypted deposit has invalid ephemeral pubkey, using zeroed DecryptionData"
    );
    Ok((
        queued,
        Some(abi::DecryptionData {
            sharedSecret: B256::ZERO,
            sharedSecretYParity: 0x02,
            cpProof: abi::ChaumPedersenProof {
                s: B256::ZERO,
                c: B256::ZERO,
            },
        }),
    ))
}
