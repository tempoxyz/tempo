#![allow(clippy::too_many_arguments)]

pub use IBridge::IBridgeErrors as BridgeError;

crate::sol! {
    /// Bridge precompile interface for cross-chain stablecoin bridging.
    ///
    /// This precompile manages deposits from origin chains (mint TIP-20) and
    /// burns on Tempo (unlock on origin). Uses 2/3 validator threshold signatures.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IBridge {
        /// Deposit request status
        enum DepositStatus { None, Registered, Finalized }

        /// Burn request status
        enum BurnStatus { None, Initiated, Finalized }

        /// Deposit request info
        struct DepositRequest {
            uint64 originChainId;
            address originEscrow;
            address originToken;
            bytes32 originTxHash;
            uint32 originLogIndex;
            address tempoRecipient;
            uint64 amount;  // 6 decimals
            uint64 originBlockNumber;
            address tempoTip20;
            uint64 votingPowerSigned;
            DepositStatus status;
        }

        /// Burn request info
        struct BurnRequest {
            uint64 originChainId;
            address originToken;
            address originRecipient;
            uint64 amount;
            uint64 nonce;
            BurnStatus status;
            uint64 tempoBlockNumber;
        }

        /// Token mapping info
        struct TokenMapping {
            uint64 originChainId;
            address originToken;
            address tempoTip20;
            bool active;
        }

        // --- Configuration ---
        function owner() external view returns (address);
        function changeOwner(address newOwner) external;

        /// Returns true if the contract is paused
        function paused() external view returns (bool);

        /// Pause the contract (owner only)
        function pause() external;

        /// Unpause the contract (owner only)
        function unpause() external;

        /// Register a token mapping (owner only)
        function registerTokenMapping(
            uint64 originChainId,
            address originToken,
            address tempoTip20
        ) external;

        /// Get TIP-20 address for origin token
        function getTip20ForOriginToken(uint64 originChainId, address originToken)
            external view returns (address);

        /// Get token mapping
        function getTokenMapping(uint64 originChainId, address originToken)
            external view returns (TokenMapping memory);

        // --- Inbound: Origin -> Tempo (Mint) ---

        /// Register a deposit from origin chain (anyone can call)
        /// Returns the unique requestId
        function registerDeposit(
            uint64 originChainId,
            address originEscrow,
            address originToken,
            bytes32 originTxHash,
            uint32 originLogIndex,
            address tempoRecipient,
            uint64 amount,
            uint64 originBlockNumber
        ) external returns (bytes32 requestId);

        /// Submit validator vote for a deposit
        ///
        /// Security model: The validator's vote is authenticated by the transaction sender address.
        /// No separate signature is required because submitting this transaction from a registered
        /// validator address already proves the validator's intent to vote for this deposit.
        /// Only callable by active validators registered in ValidatorConfig.
        function submitDepositVote(bytes32 requestId) external;

        /// Finalize deposit and mint TIP-20 (anyone can call once threshold reached)
        function finalizeDeposit(bytes32 requestId) external;

        /// Register and finalize a deposit in one call with bundled validator signatures.
        ///
        /// This is the preferred method for validators to attest to deposits. Instead of
        /// each validator submitting a separate transaction (paying gas), validators sign
        /// attestations off-chain and a single caller (block producer or relayer) submits
        /// all signatures in one transaction.
        ///
        /// The caller does NOT need to be a validator - they are just relaying signatures.
        /// Each signature is verified via ecrecover against active validators.
        ///
        /// @param originChainId Origin chain ID
        /// @param originEscrow Escrow contract address on origin chain
        /// @param originToken Token address on origin chain
        /// @param originTxHash Transaction hash of the deposit on origin chain
        /// @param originLogIndex Log index of the deposit event
        /// @param tempoRecipient Recipient address on Tempo
        /// @param amount Amount deposited (6 decimals)
        /// @param originBlockNumber Block number of the deposit on origin chain
        /// @param signatures Array of validator signatures (each 65 bytes: r, s, v)
        function registerAndFinalizeWithSignatures(
            uint64 originChainId,
            address originEscrow,
            address originToken,
            bytes32 originTxHash,
            uint32 originLogIndex,
            address tempoRecipient,
            uint64 amount,
            uint64 originBlockNumber,
            bytes[] calldata signatures
        ) external returns (bytes32 requestId);

        /// Get deposit request info
        function getDeposit(bytes32 requestId) external view returns (DepositRequest memory);

        /// Check if validator has signed a deposit
        function hasValidatorSignedDeposit(bytes32 requestId, address validator)
            external view returns (bool);

        // --- Outbound: Tempo -> Origin (Burn/Unlock) ---

        /// Burn TIP-20 to unlock on origin chain
        /// Emits BurnInitiated event that origin chain verifies
        function burnForUnlock(
            uint64 originChainId,
            address originToken,
            address originRecipient,
            uint64 amount,
            uint64 nonce
        ) external returns (bytes32 burnId);

        /// Get burn request info
        function getBurn(bytes32 burnId) external view returns (BurnRequest memory);

        // --- Events ---

        event DepositRegistered(
            bytes32 indexed requestId,
            uint64 originChainId,
            address originToken,
            bytes32 originTxHash,
            address tempoRecipient,
            uint64 amount
        );

        event DepositVoteSubmitted(
            bytes32 indexed requestId,
            address indexed validator,
            uint64 votingPowerSigned
        );

        event DepositFinalized(
            bytes32 indexed requestId,
            address tempoTip20,
            address recipient,
            uint64 amount
        );

        event BurnInitiated(
            bytes32 indexed burnId,
            uint64 indexed originChainId,
            address originToken,
            address originRecipient,
            uint64 amount,
            uint64 nonce,
            uint64 tempoBlockNumber
        );

        event TokenMappingRegistered(
            uint64 indexed originChainId,
            address indexed originToken,
            address indexed tempoTip20
        );

        event Paused(address indexed account);
        event Unpaused(address indexed account);

        // --- Errors ---
        error Unauthorized();
        error InvalidToken();
        error TokenMappingNotFound();
        error TokenMappingExists();
        error DepositAlreadyExists();
        error DepositNotFound();
        error DepositAlreadyFinalized();
        error ThresholdNotReached();
        error ValidatorNotActive();
        error AlreadySigned();
        error InvalidSignature();
        error BurnAlreadyExists();
        error InsufficientBalance();
        error ZeroAmount();
        error InvalidRecipient();
        error ContractPaused();
    }
}

impl BridgeError {
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(IBridge::Unauthorized {})
    }

    pub const fn invalid_token() -> Self {
        Self::InvalidToken(IBridge::InvalidToken {})
    }

    pub const fn token_mapping_not_found() -> Self {
        Self::TokenMappingNotFound(IBridge::TokenMappingNotFound {})
    }

    pub const fn token_mapping_exists() -> Self {
        Self::TokenMappingExists(IBridge::TokenMappingExists {})
    }

    pub const fn deposit_already_exists() -> Self {
        Self::DepositAlreadyExists(IBridge::DepositAlreadyExists {})
    }

    pub const fn deposit_not_found() -> Self {
        Self::DepositNotFound(IBridge::DepositNotFound {})
    }

    pub const fn deposit_already_finalized() -> Self {
        Self::DepositAlreadyFinalized(IBridge::DepositAlreadyFinalized {})
    }

    pub const fn threshold_not_reached() -> Self {
        Self::ThresholdNotReached(IBridge::ThresholdNotReached {})
    }

    pub const fn validator_not_active() -> Self {
        Self::ValidatorNotActive(IBridge::ValidatorNotActive {})
    }

    pub const fn already_signed() -> Self {
        Self::AlreadySigned(IBridge::AlreadySigned {})
    }

    pub const fn invalid_signature() -> Self {
        Self::InvalidSignature(IBridge::InvalidSignature {})
    }

    pub const fn burn_already_exists() -> Self {
        Self::BurnAlreadyExists(IBridge::BurnAlreadyExists {})
    }

    pub const fn insufficient_balance() -> Self {
        Self::InsufficientBalance(IBridge::InsufficientBalance {})
    }

    pub const fn zero_amount() -> Self {
        Self::ZeroAmount(IBridge::ZeroAmount {})
    }

    pub const fn invalid_recipient() -> Self {
        Self::InvalidRecipient(IBridge::InvalidRecipient {})
    }

    pub const fn contract_paused() -> Self {
        Self::ContractPaused(IBridge::ContractPaused {})
    }
}
