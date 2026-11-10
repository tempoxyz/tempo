pub use IReservations::{
    IReservationsErrors as ReservationsError, IReservationsEvents as ReservationsEvent,
};
use alloy_primitives::{Address, address};

/// Account reservations precompile address (ASCII "RESV").
pub const RESERVATIONS_ADDRESS: Address = address!("0x5245535600000000000000000000000000000000");

crate::sol! {
    /// Account reservations precompile: native holds on TIP-20 balances, capped debt and linked
    /// refunds. Hold ids are scoped per owner.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IReservations {
        /// A hold on `amount` of the owner's `token` balance in favor of `payee`.
        struct Hold {
            address token;
            address payee;
            uint128 amount;
            uint64 expiresAt;
        }

        /// Reserves `amount` of the caller's `token` balance for `payee` until `expiresAt`.
        function hold(address token, bytes32 id, uint128 amount, uint64 expiresAt, address payee) external;
        /// Sets the hold's reserved total to `amount`; an increase needs available balance.
        function adjust(bytes32 id, uint128 amount) external;
        /// Pays `amount` to the hold's payee and releases the rest of the hold.
        function capture(bytes32 id, uint128 amount) external;
        /// Pays `amount`, at most the held amount, of `owner`'s live hold to its payee (the caller)
        /// and releases the rest. Settles holds whose placing key was revoked or rotated.
        function captureFor(address owner, bytes32 id, uint128 amount) external;
        /// Pays `amount` to `payee` without a hold, from available balance and then capped debt.
        function charge(address token, bytes32 id, uint128 amount, address payee) external;
        /// Releases the caller's hold.
        function release(bytes32 id) external;
        /// Sets how much debt in `token` the caller accepts towards `creditor`. Root key only.
        function setDebtCap(address creditor, address token, uint128 cap) external;
        /// Releases an expired hold of `owner`. Callable by anyone.
        function releaseExpired(address owner, bytes32 id) external;
        /// Moves `amount` from the payee (caller) back to `owner`, up to the captured total.
        function refund(address owner, bytes32 id, uint128 amount) external;

        function getHold(address owner, bytes32 id) external view returns (Hold memory);
        function reserved(address owner, address token) external view returns (uint128);
        function available(address owner, address token) external view returns (uint128);
        function debtOf(address owner, address token) external view returns (address creditor, uint128 amount);
        function debtCap(address owner, address creditor, address token) external view returns (uint128);
        function captured(address owner, bytes32 id) external view returns (uint128 captured, uint128 refunded);

        event HoldPlaced(address indexed owner, bytes32 indexed id, address indexed token, address payee, uint128 amount, uint64 expiresAt);
        event HoldAdjusted(address indexed owner, bytes32 indexed id, address indexed token, uint128 amount);
        event HoldReleased(address indexed owner, bytes32 indexed id, address indexed token);
        event HoldCaptured(address indexed owner, bytes32 indexed id, address indexed token, uint128 amount, uint128 debt);
        event Charged(address indexed owner, bytes32 indexed id, address indexed token, address payee, uint128 amount, uint128 debt);
        event Refunded(address indexed owner, bytes32 indexed id, uint128 amount);
        event DebtRepaid(address indexed owner, address indexed token, address indexed creditor, uint128 amount);

        error HoldExists();
        error HoldNotFound();
        error HoldNotExpired();
        error InsufficientAvailable();
        error RefundExceedsCapture();
        error DebtCapExceeded();
        error PolicyForbids();
        error Unauthorized();
        error InvalidAmount();
    }
}
