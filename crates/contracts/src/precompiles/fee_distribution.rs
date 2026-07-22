pub use IFeeDistribution::{
    IFeeDistributionCalls, IFeeDistributionErrors as FeeDistributionError,
    IFeeDistributionEvents as FeeDistributionEvent,
};

crate::sol! {
    /// Narrow interface for direct fee accrual and distribution.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IFeeDistribution {
        event FeesDistributed(
            address indexed beneficiary,
            address indexed token,
            uint256 amount
        );

        function collectedFees(
            address beneficiary,
            address token
        ) external view returns (uint256);

        function distributeFees(address beneficiary, address token) external;

        error Unauthorized();
    }
}
