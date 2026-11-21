use super::*;

/// An internal withdrawal bounce-back extracted from L1.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WithdrawalBounceBackDeposit {
    /// TIP-20 token being returned to the zone.
    pub token: Address,
    /// Recipient on the zone.
    pub to: Address,
    /// Net amount deposited (fee already deducted on L1).
    pub amount: u128,
    /// Fee paid on L1 (always zero for a bounce-back).
    pub fee: u128,
}

impl WithdrawalBounceBackDeposit {
    /// Create a bounce-back deposit from an event.
    pub fn from_bounce_back(event: WithdrawalBounceBack) -> Self {
        Self {
            token: event.token,
            to: Address::left_padding_from(&event.fallbackNonce.to_be_bytes()),
            amount: event.amount,
            fee: 0,
        }
    }
}

/// A user deposit extracted from L1.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Deposit {
    /// TIP-20 token being deposited.
    pub token: Address,
    /// Sender on L1.
    pub sender: Address,
    /// Net amount deposited (fee already deducted on L1).
    pub amount: u128,
    /// Fee paid on L1.
    pub fee: u128,
    /// Tempo recipient for a failed-deposit refund.
    pub tempo_refund_recipient: Address,
    /// Index of the encryption key used.
    pub key_index: U256,
    /// Ephemeral public key X coordinate.
    pub ephemeral_pubkey_x: B256,
    /// Ephemeral public key Y parity (0x02 or 0x03).
    pub ephemeral_pubkey_y_parity: u8,
    /// AES-256-GCM ciphertext.
    pub ciphertext: Vec<u8>,
    /// GCM nonce (12 bytes).
    pub nonce: [u8; 12],
    /// GCM authentication tag (16 bytes).
    pub tag: [u8; 16],
}

impl Deposit {
    /// Create a new deposit from an event.
    pub fn from_event(event: DepositMade) -> Self {
        Self {
            token: event.token,
            sender: event.sender,
            amount: event.netAmount,
            fee: event.fee,
            tempo_refund_recipient: event.tempoRefundRecipient,
            key_index: event.keyIndex,
            ephemeral_pubkey_x: event.ephemeralPubkeyX,
            ephemeral_pubkey_y_parity: event.ephemeralPubkeyYParity,
            ciphertext: event.ciphertext.to_vec(),
            nonce: event.nonce.0,
            tag: event.tag.0,
        }
    }
}

/// A TIP-1094 transfer to a zone deposit address, extracted from L1.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VirtualDeposit {
    /// TIP-20 token that was transferred.
    pub token: Address,
    /// Debited Tempo account; a failed deposit refunds it.
    pub originator: Address,
    /// Net amount queued (fee already deducted on L1).
    pub amount: u128,
    /// Fee paid on L1.
    pub fee: u128,
    /// The zone deposit address the transfer was sent to.
    pub destination: Address,
    /// Whether the transfer entrypoint carried a memo.
    pub has_memo: bool,
    /// Public memo; zero when [`Self::has_memo`] is false.
    pub memo: B256,
}

impl VirtualDeposit {
    /// Create a virtual deposit from its portal event.
    pub fn from_event(event: VirtualDepositMade) -> Self {
        Self {
            token: event.token,
            originator: event.originator,
            amount: event.netAmount,
            fee: event.fee,
            destination: event.destination,
            has_memo: event.hasMemo,
            memo: event.memo,
        }
    }

    fn to_abi(&self) -> abi::VirtualDeposit {
        abi::VirtualDeposit {
            token: self.token,
            originator: self.originator,
            amount: self.amount,
            destination: self.destination,
            hasMemo: self.has_memo,
            memo: self.memo,
        }
    }
}

/// A queue entry from L1: an internal withdrawal bounce-back, an encrypted user deposit, or a
/// TIP-1094 virtual deposit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum L1Deposit {
    /// An internal withdrawal bounce-back.
    WithdrawalBounceBack(WithdrawalBounceBackDeposit),
    /// A user deposit whose recipient and memo are encrypted.
    Deposit(Deposit),
    /// A transfer to a zone deposit address. It needs no sequencer decryption.
    ZoneVirtual(VirtualDeposit),
}

impl L1Deposit {
    /// Convert the L1 event payload into its canonical `advanceTempo` queue encoding.
    pub fn to_abi_queued_deposit(&self) -> abi::QueuedDeposit {
        match self {
            Self::WithdrawalBounceBack(d) => abi::QueuedDeposit {
                depositType: abi::DepositType::WithdrawalBounceBack,
                rejected: false,
                depositData: abi::WithdrawalBounceBackDeposit {
                    token: d.token,
                    to: d.to,
                    amount: d.amount,
                }
                .abi_encode()
                .into(),
            },
            Self::Deposit(d) => abi::QueuedDeposit {
                depositType: abi::DepositType::Deposit,
                rejected: false,
                depositData: AbiDeposit {
                    token: d.token,
                    sender: d.sender,
                    amount: d.amount,
                    tempoRefundRecipient: d.tempo_refund_recipient,
                    keyIndex: d.key_index,
                    encrypted: AbiDepositPayload {
                        ephemeralPubkeyX: d.ephemeral_pubkey_x,
                        ephemeralPubkeyYParity: d.ephemeral_pubkey_y_parity,
                        ciphertext: d.ciphertext.clone().into(),
                        nonce: d.nonce.into(),
                        tag: d.tag.into(),
                    },
                }
                .abi_encode()
                .into(),
            },
            Self::ZoneVirtual(d) => abi::QueuedDeposit {
                depositType: abi::DepositType::ZoneVirtual,
                rejected: false,
                depositData: d.to_abi().abi_encode().into(),
            },
        }
    }

    /// Compute the next hash chain value: `keccak256(abi.encode(deposit, prevHash))`.
    pub fn hash_chain(&self, prev_hash: B256) -> B256 {
        match self {
            Self::WithdrawalBounceBack(d) => keccak256(
                (
                    abi::DepositType::WithdrawalBounceBack,
                    abi::WithdrawalBounceBackDeposit {
                        token: d.token,
                        to: d.to,
                        amount: d.amount,
                    },
                    prev_hash,
                )
                    .abi_encode_params(),
            ),
            Self::Deposit(d) => keccak256(
                (
                    abi::DepositType::Deposit,
                    AbiDeposit {
                        token: d.token,
                        sender: d.sender,
                        amount: d.amount,
                        tempoRefundRecipient: d.tempo_refund_recipient,
                        keyIndex: d.key_index,
                        encrypted: AbiDepositPayload {
                            ephemeralPubkeyX: d.ephemeral_pubkey_x,
                            ephemeralPubkeyYParity: d.ephemeral_pubkey_y_parity,
                            ciphertext: d.ciphertext.clone().into(),
                            nonce: d.nonce.into(),
                            tag: d.tag.into(),
                        },
                    },
                    prev_hash,
                )
                    .abi_encode_params(),
            ),
            Self::ZoneVirtual(d) => keccak256(
                (abi::DepositType::ZoneVirtual, d.to_abi(), prev_hash).abi_encode_params(),
            ),
        }
    }
}
