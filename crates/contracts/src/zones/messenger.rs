//! Shared withdrawal callback sender deployed on Tempo L1.

pub use ZoneMessenger as IZoneMessenger;

crate::sol! {
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    contract ZoneMessenger {
        error UnauthorizedPortal();
        error TransferFailed();
        error CallbackRejected();
        error InvalidCallbackTarget();
        error ReentrantRelay();

        function zoneFactory() external view returns (address);

        function relayMessage(
            uint32 zoneId,
            address token,
            bytes32 senderTag,
            address target,
            uint128 amount,
            uint64 gasLimit,
            bytes calldata data
        ) external;
    }
}
