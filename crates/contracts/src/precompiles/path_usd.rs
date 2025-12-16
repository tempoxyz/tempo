use alloy_sol_types::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface IPathUSD {
        function TRANSFER_ROLE() external view returns (bytes32);
        function RECEIVE_WITH_MEMO_ROLE() external view returns (bytes32);
    }
}
