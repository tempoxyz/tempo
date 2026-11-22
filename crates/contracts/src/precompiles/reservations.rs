pub use IReservationCore::{
    IReservationCoreErrors as ReservationsError, IReservationCoreEvents as ReservationsEvent,
};
use alloy_primitives::{Address, address};

/// Reservation core precompile address (ASCII "RESV").
pub const RESERVATIONS_ADDRESS: Address = address!("0x5245535600000000000000000000000000000000");

crate::sol! {
    /// Reservation core (TIP-1153): holds, captures, charges, refunds, pledges and liens inside
    /// TIP-20 balances, with holders the owner gives a spend budget.
    ///
    /// Every reservation is a record keyed by `(owner, placer, id)`: each placer's ids are its own
    /// namespace, and calls from the payee's side name the placer. A record is deleted when it
    /// settles, after which its id may be used again.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IReservationCore {
        /// A hold to place on the owner's balance.
        struct HoldRequest {
            address token;
            bytes32 id;
            /// Amount to reserve; it must be available.
            uint128 amount;
            /// Must satisfy `now < expiresAt <= now + 31 days`.
            uint64 expiresAt;
            address payee;
        }

        /// A live record. Every field is zero once it settles or if it never existed.
        struct HoldRecord {
            address token;
            /// Who captures it: the payee of a hold, the authority of a pledge or lien.
            address payee;
            /// Amount still reserved.
            uint128 held;
            /// What captures may still pay in total, tolerance included.
            uint128 captureLimit;
            /// Zero for a lien without expiry.
            uint64 expiresAt;
            /// 0: none, 1: hold, 2: pledge, 3: lien.
            uint8 kind;
        }

        /// A holder's spend budget on one owner's balance of one token.
        struct Budget {
            /// Most `spent + outstanding` may reach; zero revokes.
            uint128 limit;
            /// What captures, charges and seizures paid this period; never returned.
            uint128 spent;
            /// What the holder's live holds and pledges still reserve.
            uint128 outstanding;
            /// Seconds after which `spent` resets; zero for a lifetime budget.
            uint32 period;
            /// Start of the current period.
            uint64 periodStart;
        }

        /// Sets `holder`'s spend budget on the caller's `token`: `limit` (saturated to 2^64 - 1)
        /// bounds what it spends per `period` plus what it holds. A zero limit revokes: no new
        /// holds, charges or pledges, while existing holds still settle. Root key only.
        function approveHolder(address holder, address token, uint128 limit, uint32 period) external;
        /// Sets how far captures of the caller's new holds to `payee` in `token` may exceed the
        /// held amount, in basis points. Root key only.
        function setCaptureTolerance(address payee, address token, uint16 toleranceBps) external;

        /// Places a hold on the caller's own balance.
        function hold(HoldRequest calldata request) external;
        /// Places a hold on `owner`'s balance as a holder within its budget.
        function holdFrom(address owner, HoldRequest calldata request) external;
        /// Pledges the caller's available balance to `authority` until `expiresAt`, at most 400
        /// days away. Root key only.
        function pledge(address authority, address token, bytes32 id, uint128 amount, uint64 expiresAt) external;
        /// Pledges `owner`'s available balance to the caller, a holder within its budget, until
        /// `expiresAt`, at most 400 days away.
        function pledgeFrom(address owner, address token, bytes32 id, uint128 amount, uint64 expiresAt) external;
        /// Liens `owner`'s available balance for the caller. Needs the token's `LIEN_ROLE` and the
        /// caller's root key; `expiresAt` zero means no expiry.
        function lien(address owner, address token, bytes32 id, uint128 amount, uint64 expiresAt) external;

        /// Sets what a live hold reserves. The placer of a hold; the payee of a pledge or lien,
        /// only downward.
        function adjust(address owner, address placer, bytes32 id, uint128 amount) external;
        /// Pays `amount` of a live hold to its payee; a final capture releases the rest. The
        /// placer or payee of a hold; the payee of a pledge or lien.
        function capture(address owner, address placer, bytes32 id, uint128 amount, bool isFinal) external;
        /// Ends a live hold, returning what it reserves. The placer or payee of a hold; the payee
        /// of a pledge or lien.
        function release(address owner, address placer, bytes32 id) external;
        /// Ends a hold past its expiry. Anyone.
        function releaseExpired(address owner, address placer, bytes32 id) external;
        /// Pays `payee` from `owner`'s available balance without a hold. The owner or a holder
        /// within its budget.
        function charge(address owner, address token, bytes32 id, uint128 amount, address payee) external;
        /// Pays `amount` of the caller's available balance back to `owner` for `placer`'s hold
        /// `id`.
        function refund(address owner, address token, address placer, bytes32 id, uint128 amount) external;

        function getHold(address owner, address placer, bytes32 id) external view returns (HoldRecord memory);
        function reserved(address owner, address token) external view returns (uint128);
        function available(address owner, address token) external view returns (uint128);
        function budget(address owner, address holder, address token) external view returns (Budget memory);
        function captureTolerance(address owner, address payee, address token) external view returns (uint16);

        event HolderApproved(address indexed owner, address indexed holder, address indexed token, uint128 limit, uint32 period);
        event CaptureToleranceSet(address indexed owner, address indexed payee, address indexed token, uint16 toleranceBps);
        event HoldPlaced(address indexed owner, address indexed placer, address indexed token, bytes32 id, uint8 kind, address payee, uint128 amount, uint128 captureLimit, uint64 expiresAt);
        event HoldAdjusted(address indexed owner, address indexed placer, address indexed token, bytes32 id, uint128 held, uint128 captureLimit);
        event HoldCaptured(address indexed owner, address indexed placer, address indexed token, bytes32 id, address payee, uint128 amount, bool isFinal);
        event HoldReleased(address indexed owner, address indexed placer, address indexed token, bytes32 id, uint128 amount, bool expired);
        event Charged(address indexed owner, address indexed charger, address indexed token, bytes32 id, address payee, uint128 amount);
        event Refunded(address indexed owner, address indexed payee, address indexed token, address placer, bytes32 id, uint128 amount);

        error HoldExists();
        error HoldNotFound();
        error HoldExpired();
        error HoldNotExpired();
        error InsufficientAvailable();
        error BudgetExceeded();
        error CaptureLimitExceeded();
        error PolicyForbids();
        error Unauthorized();
        error InvalidAmount();
        error InvalidExpiry();
    }
}
