pub use ITipAccountRegistrar::ITipAccountRegistrarErrors as TipAccountRegistrarError;
use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITipAccountRegistrar {
        function delegateToDefault(bytes32 hash, bytes signature) external returns (address authority);
        function getDelegationMessage() external pure returns (string memory);

        // Errors
        error InvalidSignature();
        error CodeNotEmpty();
        error NonceNotZero();
    }
}
