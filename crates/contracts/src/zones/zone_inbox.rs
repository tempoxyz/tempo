//! `IZoneInbox` — Zone L2 system contract interface (0x1c00...0001).

pub use IZoneInbox::{
    ChaumPedersenProof, DecryptionData, DepositType, EnabledToken,
    IZoneInboxErrors as ZoneInboxError, IZoneInboxEvents as ZoneInboxEvent, QueuedDeposit,
    TempoAdvanced_0 as LegacyTempoAdvanced, TempoAdvanced_1 as TempoAdvanced,
    WithdrawalBounceBackDeposit,
};

use alloy_primitives::{Address, B256, keccak256};
use alloy_sol_types::SolValue;

crate::sol! {
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    contract IZoneInbox {
        // -- Shared types --

        struct WithdrawalBounceBackDeposit {
            address token;
            address to;
            uint128 amount;
        }

        /// A TIP-20 token enabled on L1 for bridging to the zone.
        struct EnabledToken {
            address token;
            string name;
            string symbol;
            string currency;
        }

        /// Entry types for the unified deposit queue.
        enum DepositType {
            /// Internal withdrawal bounce-back entry.
            WithdrawalBounceBack,
            /// User deposit with an encrypted recipient and memo.
            Deposit,
        }

        /// A user deposit or internal withdrawal bounce-back passed to `advanceTempo`.
        struct QueuedDeposit {
            DepositType depositType;
            bytes depositData;
            bool rejected;
        }

        /// Chaum-Pedersen proof for ECDH shared secret derivation.
        struct ChaumPedersenProof {
            bytes32 s;
            bytes32 c;
        }

        /// Decryption data provided by the sequencer for user deposits.
        struct DecryptionData {
            bytes32 sharedSecret;
            uint8 sharedSecretYParity;
            ChaumPedersenProof cpProof;
        }

        // -- Events --

        event TempoAdvanced(
            bytes32 indexed tempoBlockHash,
            uint64 indexed tempoBlockNumber,
            uint256 depositsProcessed,
            bytes32 newProcessedDepositQueueHash,
            uint64 lastProcessedDepositNumber
        );

        /// T13 Tempo advancement event with the processed enabled-token cursor.
        event TempoAdvanced(
            bytes32 indexed tempoBlockHash,
            uint64 indexed tempoBlockNumber,
            uint256 depositsProcessed,
            bytes32 newProcessedDepositQueueHash,
            uint64 lastProcessedDepositNumber,
            uint64 lastProcessedEnabledTokenCount
        );

        event DepositProcessed(
            bytes32 indexed depositHash,
            address indexed sender,
            address indexed to,
            address token,
            uint128 amount,
            bytes32 memo
        );

        event DepositFailed(
            bytes32 indexed depositHash,
            address indexed sender,
            address token,
            uint128 amount
        );

        event DepositRejected(
            bytes32 indexed depositHash,
            address indexed sender,
            DepositType depositType,
            address token,
            uint128 amount,
            address tempoRefundRecipient
        );

        event WithdrawalBounceBackProcessed(address indexed zoneFallbackRecipient, address token, uint128 amount);

        event WithdrawalBounceBackPending(address indexed zoneFallbackRecipient, address token, uint128 amount);

        event RefundClaimed(address indexed recipient, address indexed token, uint128 amount);

        /// Emitted when a TIP-20 token is enabled on the zone via advanceTempo.
        event TokenEnabled(address indexed token, string name, string symbol, string currency);

        error OnlySequencer();
        error InvalidDepositQueueHash();
        error InvalidWithdrawalBounceBack();
        error InvalidTokenEnablementHash();
        error MissingDecryptionData();
        error ExtraDecryptionData();
        error InvalidSharedSecretProof();
        error Unauthorized();

        function processedDepositQueueHash() external view returns (bytes32);
        function processedDepositNumber() external view returns (uint64);
        function processedTokenEnablementHash() external view returns (bytes32);
        /// Get the number of enabled tokens processed by the Zone Inbox. Active from T13.
        function processedEnabledTokenCount() external view returns (uint64);
        function tempoPortal() external view returns (address);
        function tempoState() external view returns (address);
        function refunds(address token, address owner) external view returns (uint128);
        function claimRefund(address token) external returns (uint128 amount);

        function advanceTempo(
            bytes calldata header,
            QueuedDeposit[] calldata deposits,
            DecryptionData[] calldata decryptions,
            EnabledToken[] calldata enabledTokens
        ) external;
        /// Advance only the authenticated Tempo checkpoint. A block opened by this call may not
        /// contain any other transaction.
        function advanceTempoHeaders(bytes[] calldata headers) external;
    }
}

/// IZoneInbox entries retired by the T13 hardfork.
mod pre_t13_retired {
    crate::sol! {
        #[sol(abi)]
        contract IZoneInboxPreT13Retired {
            event TempoAdvanced(
                bytes32 indexed tempoBlockHash,
                uint64 indexed tempoBlockNumber,
                uint256 depositsProcessed,
                bytes32 newProcessedDepositQueueHash,
                uint64 lastProcessedDepositNumber
            );
        }
    }
}

#[doc(hidden)]
pub use pre_t13_retired::IZoneInboxPreT13Retired;

impl EnabledToken {
    /// Hash this token enablement as the next link in the portal commitment.
    pub fn hash_with_previous(&self, previous_hash: B256) -> B256 {
        keccak256(
            (
                previous_hash,
                self.token,
                self.name.as_str(),
                self.symbol.as_str(),
                self.currency.as_str(),
            )
                .abi_encode_params(),
        )
    }

    /// Build the event emitted after enabling this token on the zone.
    pub fn enabled_event(self) -> ZoneInboxEvent {
        ZoneInboxEvent::token_enabled(self.token, self.name, self.symbol, self.currency)
    }
}

impl WithdrawalBounceBackDeposit {
    /// Build the event emitted after processing a withdrawal bounce-back.
    pub fn withdrawal_bounce_back_processed_event(
        &self,
        fallback_recipient: Address,
    ) -> ZoneInboxEvent {
        ZoneInboxEvent::withdrawal_bounce_back_processed(
            fallback_recipient,
            self.token,
            self.amount,
        )
    }

    /// Build the event emitted after parking a failed withdrawal bounce-back.
    pub fn withdrawal_bounce_back_pending_event(
        &self,
        fallback_recipient: Address,
    ) -> ZoneInboxEvent {
        ZoneInboxEvent::withdrawal_bounce_back_pending(fallback_recipient, self.token, self.amount)
    }
}
