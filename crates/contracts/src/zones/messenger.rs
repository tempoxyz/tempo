crate::sol! {
    contract ZoneMessenger {
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
