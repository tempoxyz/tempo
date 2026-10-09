//! `TempoState` — Zone L2 predeploy (0x1c00...0000).

pub use TempoState::{
    TempoStateErrors as TempoStateError, TempoStateEvents as TempoStateEvent,
    finalizeTempo_0Call as legacyFinalizeTempoCall, finalizeTempo_1Call as finalizeTempoCall,
};

crate::sol! {
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    contract TempoState {
        event TempoBlockFinalized(bytes32 indexed blockHash, uint64 indexed blockNumber, bytes32 stateRoot);

        error InvalidParentHash();
        error InvalidBlockNumber();
        error InvalidTimestamp();
        error InvalidRlpData();
        error OnlyZoneInbox();

        function tempoBlockHash() external view returns (bytes32);
        function tempoBlockNumber() external view returns (uint64);

        /// Finalize one Tempo header. Active before T13.
        function finalizeTempo(bytes calldata header) external;

        /// Finalize consecutive Tempo headers. Active from T13.
        function finalizeTempo(bytes[] calldata headers) external;
    }
}

/// TempoState entries retired by the T13 hardfork.
mod pre_t13_retired {
    crate::sol! {
        #[sol(abi)]
        contract TempoStatePreT13Retired {
            function finalizeTempo(bytes header) external;
        }
    }
}

#[doc(hidden)]
pub use pre_t13_retired::TempoStatePreT13Retired;
