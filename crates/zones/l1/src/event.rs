use super::*;

/// Events extracted from the ZonePortal in a single L1 block.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct L1PortalEvents {
    /// User deposits and internal withdrawal bounce-backs.
    pub deposits: Vec<L1Deposit>,
    /// Tokens newly enabled for bridging in this block, with metadata.
    pub enabled_tokens: Vec<EnabledToken>,
    /// Encryption-key registrations in canonical log order.
    #[serde(default)]
    pub encryption_key_rotations: Vec<EncryptionKeyRotation>,
    /// Leadership transitions in this block, in canonical log order.
    ///
    /// The portal allows at most one distinct transition per Tempo block.
    #[serde(default)]
    pub leader_transitions: Vec<LeaderTransition>,
    /// Portal-wide pause state left by this block's `PortalPaused`/`PortalResumed` events, if any.
    ///
    /// Automatic expiry emits no event, so this is only a lower bound on transitions; the
    /// finalized Portal state poller observes expiry.
    #[serde(default)]
    pub portal_pause: Option<bool>,
}

/// A finalized `SequencerEncryptionKeyUpdated` Portal event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EncryptionKeyRotation {
    /// Compressed public-key X coordinate.
    pub x: B256,
    /// Compressed public-key prefix (`0x02` or `0x03`).
    pub y_parity: u8,
    /// Address derived from the compressed public key.
    pub pubkey: Address,
    /// Index assigned by the Portal's append-only key history.
    pub key_index: U256,
    /// L1 block at which this key became current.
    pub activation_block: u64,
}

/// Derive the address for a compressed secp256k1 encryption public key.
pub fn encryption_key_address(x: B256, y_parity: u8) -> eyre::Result<Address> {
    let mut compressed = [0; 33];
    compressed[0] = y_parity;
    compressed[1..].copy_from_slice(x.as_slice());
    let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&compressed)
        .map_err(|err| eyre::eyre!("invalid compressed encryption public key: {err}"))?;
    Ok(Address::from_public_key(&verifying_key))
}

/// A decoded `LeaderUpdated` portal event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeaderTransition {
    /// The leader being replaced (`Address::ZERO` at initialization).
    pub previous_leader: Address,
    /// Individual sequencer address of the new block-production leader.
    pub new_leader: Address,
    /// New monotonic leadership epoch.
    pub epoch: u64,
    /// Tempo block that recorded the transition — the first anchor for the new leader.
    pub activation_tempo_block: u64,
}

/// A token newly enabled for bridging, with metadata for L2 creation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnabledToken {
    /// The L1 token address (TIP-20 with 0x20C0 prefix).
    pub token: Address,
    /// Token name.
    pub name: String,
    /// Token symbol.
    pub symbol: String,
    /// Token currency (e.g. "USD", "EUR").
    pub currency: String,
}

impl EnabledToken {
    /// Convert to the ABI type used in `advanceTempo` calldata.
    pub fn to_abi(&self) -> abi::EnabledToken {
        abi::EnabledToken {
            token: self.token,
            name: self.name.clone(),
            symbol: self.symbol.clone(),
            currency: self.currency.clone(),
        }
    }
}

impl L1PortalEvents {
    /// Event signature hashes that this container knows how to decode.
    const SIGNATURE_HASHES: [B256; 7] = [
        DepositMade::SIGNATURE_HASH,
        WithdrawalBounceBack::SIGNATURE_HASH,
        TokenEnabled::SIGNATURE_HASH,
        SequencerEncryptionKeyUpdated::SIGNATURE_HASH,
        LeaderUpdated::SIGNATURE_HASH,
        PortalPaused::SIGNATURE_HASH,
        PortalResumed::SIGNATURE_HASH,
    ];

    /// Create portal events from deposits only.
    pub fn from_deposits(deposits: Vec<L1Deposit>) -> Self {
        Self {
            deposits,
            ..Default::default()
        }
    }

    /// Append only events consumed by `advanceTempo`.
    ///
    /// Key rotations and leadership transitions are applied during L1 ingestion and must not be
    /// retained for a later operational import.
    pub(crate) fn extend_operational(&mut self, mut other: Self) {
        self.deposits.append(&mut other.deposits);
        self.enabled_tokens.append(&mut other.enabled_tokens);
    }

    /// Validate that `advanceTempo` processes every deposit and token enable observed in this
    /// block's verified L1 receipts, in canonical log order.
    ///
    /// The sequencer-controlled `rejected` flag is deliberately excluded from deposit identity.
    pub fn validate_advance_tempo_inputs(
        &self,
        deposits: &[abi::QueuedDeposit],
        enabled_tokens: &[abi::EnabledToken],
    ) -> eyre::Result<()> {
        eyre::ensure!(
            deposits.len() == self.deposits.len(),
            "advanceTempo deposit count does not match observed L1 events: expected {}, got {}",
            self.deposits.len(),
            deposits.len()
        );

        for (index, (expected, actual)) in self.deposits.iter().zip(deposits).enumerate() {
            let expected = expected.to_abi_queued_deposit();
            eyre::ensure!(
                actual.depositType == expected.depositType
                    && actual.depositData == expected.depositData,
                "advanceTempo deposit {index} does not match the observed L1 event"
            );
        }

        let expected_tokens: Vec<_> = self
            .enabled_tokens
            .iter()
            .map(EnabledToken::to_abi)
            .collect();
        eyre::ensure!(
            enabled_tokens == expected_tokens,
            "advanceTempo token enables do not match observed L1 events"
        );
        Ok(())
    }

    /// Decode a portal log and add the event to this container.
    ///
    /// Logs whose topic0 does not match a known portal event are skipped.
    /// Known events that fail to decode return an error.
    pub fn push_log(&mut self, log: &Log, block_number: u64) -> eyre::Result<()> {
        if !Self::is_known_event(log) {
            debug!(
                l1_block = block_number,
                topic0 = ?log.topic0(),
                "Skipping unknown portal event"
            );
            return Ok(());
        }
        match ZonePortalEvents::decode_log(&log.inner)?.data {
            ZonePortalEvents::DepositMade(event) => {
                info!(
                    l1_block = block_number,
                    token = %event.token,
                    sender = %event.sender,
                    amount = %event.netAmount,
                    "🔒 Deposit from L1"
                );
                self.deposits
                    .push(L1Deposit::Deposit(Deposit::from_event(event)));
            }
            ZonePortalEvents::WithdrawalBounceBack(event) => {
                info!(
                    l1_block = block_number,
                    token = %event.token,
                    fallback_nonce = event.fallbackNonce,
                    amount = %event.amount,
                    "↩️ Bounce-back deposit from L1"
                );
                self.deposits.push(L1Deposit::WithdrawalBounceBack(
                    WithdrawalBounceBackDeposit::from_bounce_back(event),
                ));
            }
            ZonePortalEvents::TokenEnabled(event) => {
                info!(
                    l1_block = block_number,
                    token = %event.token,
                    name = %event.name,
                    symbol = %event.symbol,
                    currency = %event.currency,
                    "🪙 Token enabled on L1"
                );
                self.enabled_tokens.push(EnabledToken {
                    token: event.token,
                    name: event.name,
                    symbol: event.symbol,
                    currency: event.currency,
                });
            }
            ZonePortalEvents::SequencerEncryptionKeyUpdated(event) => {
                info!(
                    l1_block = block_number,
                    pubkey = %event.pubkey,
                    key_index = %event.keyIndex,
                    activation_block = event.activationBlock,
                    "Sequencer encryption key rotated on L1"
                );
                self.encryption_key_rotations.push(EncryptionKeyRotation {
                    x: event.x,
                    y_parity: event.yParity,
                    pubkey: event.pubkey,
                    key_index: event.keyIndex,
                    activation_block: event.activationBlock,
                });
            }
            ZonePortalEvents::LeaderUpdated(event) => {
                info!(
                    l1_block = block_number,
                    previous_leader = %event.previousLeader,
                    new_leader = %event.newLeader,
                    epoch = event.epoch,
                    activation_tempo_block = event.activationTempoBlock,
                    "Leadership transition on L1"
                );
                self.leader_transitions.push(LeaderTransition {
                    previous_leader: event.previousLeader,
                    new_leader: event.newLeader,
                    epoch: event.epoch,
                    activation_tempo_block: event.activationTempoBlock,
                });
            }
            ZonePortalEvents::PortalPaused(event) => {
                info!(l1_block = block_number, account = %event.account, "Portal-wide pause on L1");
                self.portal_pause = Some(true);
            }
            ZonePortalEvents::PortalResumed(event) => {
                info!(l1_block = block_number, account = %event.account, "Portal-wide resume on L1");
                self.portal_pause = Some(false);
            }
            _ => {}
        }
        Ok(())
    }

    /// Return the leadership transition in this block, if any.
    pub fn final_leader_transition(&self) -> eyre::Result<Option<&LeaderTransition>> {
        eyre::ensure!(
            self.leader_transitions.len() <= 1,
            "L1 block contains {} leadership transitions; the portal permits at most one",
            self.leader_transitions.len()
        );
        Ok(self.leader_transitions.first())
    }

    fn is_known_event(log: &Log) -> bool {
        log.topic0()
            .is_some_and(|t| Self::SIGNATURE_HASHES.contains(t))
    }
}
