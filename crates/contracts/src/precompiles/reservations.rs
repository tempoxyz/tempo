pub use IReservationCore::{
    IReservationCoreErrors as ReservationsError, IReservationCoreEvents as ReservationsEvent,
};
use alloy_primitives::{Address, address};

/// Reservation core precompile address (ASCII "RESV").
pub const RESERVATIONS_ADDRESS: Address = address!("0x5245535600000000000000000000000000000000");

crate::sol! {
    /// Reservation core (TIP-1153): holds, captures, refunds, capped debt and liens on TIP-20
    /// balances. Hold ids are scoped per owner, lien ids per authority.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IReservationCore {
        /// A hold to place on the owner's balance.
        struct HoldRequest {
            address token;
            bytes32 id;
            /// Amount to reserve; for a stand-in, the amount approved offline.
            uint128 amount;
            /// Must satisfy `now < expiresAt <= now + 31 days`.
            uint64 expiresAt;
            address payee;
            bool standIn;
        }

        /// The record of one hold or charge of an owner.
        struct HoldRecord {
            address token;
            /// The owner for a direct hold, else the holder contract that placed it.
            address placer;
            address payee;
            /// Amount still reserved.
            uint128 held;
            /// The capture cap before tolerance: the first amount, or the offline approval.
            uint128 approved;
            uint128 captured;
            uint128 refunded;
            uint64 expiresAt;
            bool standIn;
            /// A final capture, a release or a charge ended it.
            bool settled;
        }

        /// Caps what `holder` may have outstanding in holds on the caller's `token`. Zero revokes:
        /// no new holds, while existing ones still capture, release and refund. Root key only.
        function approveHolder(address holder, address token, uint128 allowance) external;
        /// Sets the debt the caller accepts owing `creditor` in `token`. Root key only.
        function setDebtCap(address creditor, address token, uint128 cap) external;
        /// Sets how far captures for `payee` in `token` may exceed a hold's approval, in basis
        /// points. Root key only.
        function setCaptureTolerance(address payee, address token, uint32 toleranceBps) external;
        /// Sets the debt stand-in holds and charges for `payee` in `token` may create. Root key only.
        function setOfflineCap(address payee, address token, uint128 cap) external;

        /// Places a hold on the caller's own balance.
        function hold(HoldRequest calldata request) external;
        /// Places a hold on `owner`'s balance as a holder `owner` approved for the token.
        function holdFrom(address owner, HoldRequest calldata request) external;
        /// Sets what a live hold still reserves. Placer only.
        function adjust(address owner, bytes32 id, uint128 amount) external;
        /// Pays `amount` of a live hold to its payee; a final capture releases the rest. Placer or payee.
        function capture(address owner, bytes32 id, uint128 amount, bool isFinal) external;
        /// Ends a live hold, returning what it reserves. Placer or payee.
        function release(address owner, bytes32 id) external;
        /// Ends a hold past its expiry. Anyone.
        function releaseExpired(address owner, bytes32 id) external;
        /// Pays `amount` of what a record captured back to its owner. Payee only.
        function refund(address owner, bytes32 id, uint128 amount) external;
        /// Pays `payee` without a hold and records a settled id. Owner or approved holder.
        function charge(address owner, address token, bytes32 id, uint128 amount, address payee, bool standIn) external;

        /// Liens `amount` of `owner`'s available balance. Needs the token's `LIEN_ROLE` and the
        /// caller's root key; `expiresAt` zero means no expiry.
        function lien(address owner, address token, bytes32 id, uint128 amount, uint64 expiresAt) external;
        /// Liens the caller's own available balance for `authority` until `expiresAt`. Root key only.
        function pledge(address authority, address token, bytes32 id, uint128 amount, uint64 expiresAt) external;
        /// Ends the caller's lien `id`.
        function releaseLien(bytes32 id) external;
        /// Lowers the caller's lien `id` by `amount`, ending it at or above its amount.
        function reduceLien(bytes32 id, uint128 amount) external;
        /// Pays `amount` of the caller's lien `id` to the caller.
        function seizeLien(bytes32 id, uint128 amount) external;
        /// Ends `authority`'s lien `id` past its expiry. Anyone.
        function releaseExpiredLien(address authority, bytes32 id) external;

        function getHold(address owner, bytes32 id) external view returns (HoldRecord memory);
        function reserved(address owner, address token) external view returns (uint128);
        function available(address owner, address token) external view returns (uint128);
        function allowance(address owner, address holder, address token) external view returns (uint128 allowance, uint128 outstanding);
        function debtOf(address owner, address token) external view returns (address creditor, uint128 amount);
        function debtCap(address owner, address creditor, address token) external view returns (uint128);
        function captureTolerance(address owner, address payee, address token) external view returns (uint32);
        function offlineCap(address owner, address payee, address token) external view returns (uint128);
        function lienOf(address authority, bytes32 id) external view returns (address owner, address token, uint128 amount, uint64 expiresAt, bool pledged);
        function liened(address owner, address token) external view returns (uint128);

        event HolderApproved(address indexed owner, address indexed holder, address indexed token, uint128 allowance);
        event HoldPlaced(address indexed owner, bytes32 indexed id, address indexed token, address placer, address payee, uint128 amount, uint128 held, uint64 expiresAt, bool standIn);
        event HoldAdjusted(address indexed owner, bytes32 indexed id, address indexed token, uint128 held);
        event HoldCaptured(address indexed owner, bytes32 indexed id, address indexed token, address payee, uint128 amount, uint128 debt, bool isFinal);
        event HoldReleased(address indexed owner, bytes32 indexed id, address indexed token, uint128 amount, bool expired);
        event Charged(address indexed owner, bytes32 indexed id, address indexed token, address payee, uint128 amount, uint128 debt);
        event Refunded(address indexed owner, bytes32 indexed id, address indexed token, address payee, uint128 amount);
        event DebtRepaid(address indexed owner, address indexed token, address indexed creditor, uint128 amount);
        event Liened(address indexed owner, address indexed authority, address indexed token, bytes32 id, uint128 amount, uint64 expiresAt, bool pledged);
        event LienReleased(address indexed owner, address indexed authority, address indexed token, bytes32 id, uint128 amount, bool expired);
        event LienReduced(address indexed owner, address indexed authority, address indexed token, bytes32 id, uint128 remaining);
        event LienSeized(address indexed owner, address indexed authority, address indexed token, bytes32 id, uint128 amount, uint128 remaining);

        error HoldExists();
        error HoldNotFound();
        error HoldExpired();
        error HoldNotExpired();
        error HoldSettled();
        error InsufficientAvailable();
        error AllowanceExceeded();
        error ToleranceExceeded();
        error RefundExceedsCapture();
        error DebtCapExceeded();
        error PolicyForbids();
        error Unauthorized();
        error InvalidAmount();
        error InvalidExpiry();
        error LienExists();
        error LienNotFound();
        error LienNotExpired();
    }
}
