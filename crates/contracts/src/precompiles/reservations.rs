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
        /// Sets what the hold still reserves, after any non-final captures, to `amount`; an increase
        /// needs available balance.
        function adjust(bytes32 id, uint128 amount) external;
        /// Pays `amount` to the hold's payee and releases the rest of the hold.
        function capture(bytes32 id, uint128 amount) external;
        /// Pays `amount`, at most the held amount, of `owner`'s live hold to its payee (the caller)
        /// and releases the rest. Settles holds whose placing key was revoked or rotated.
        function captureFor(address owner, bytes32 id, uint128 amount) external;
        /// Pays `amount` of the caller's live hold to its payee. A non-final capture takes at most
        /// the held amount and keeps the rest held; a final one settles the hold as `capture`.
        function capturePart(bytes32 id, uint128 amount, bool isFinal) external;
        /// Pays `amount`, at most the held amount, of `owner`'s live hold to its payee (the caller).
        /// A non-final capture keeps the rest held; a final one settles the hold as `captureFor`.
        function captureForPart(address owner, bytes32 id, uint128 amount, bool isFinal) external;
        /// Pays `amount` to `payee` without a hold, from available balance and then capped debt.
        function charge(address token, bytes32 id, uint128 amount, address payee) external;
        /// Records an approval the payee made in stand-in: reserves what is available of `amount`
        /// and marks the hold, so that its final capture may leave the rest as debt up to the
        /// larger of the debt cap and the offline cap.
        function holdStandIn(address token, bytes32 id, uint128 amount, uint64 expiresAt, address payee) external;
        /// `hold` through the caller's card `card` issued by `issuer` (its `ICards` payee, which may
        /// differ from the hold's `payee`, such as a savings facility paying the issuer; TIP-1169):
        /// reverts `UnknownCard`, `CardInactive`, `TokenNotAllowed` or `CardLimitExceeded` from
        /// `ICards` unless the card may hold `amount` of `token` now, and records the card's line.
        function holdCard(address token, bytes32 id, uint128 amount, uint64 expiresAt, address payee, address issuer, bytes32 card) external;
        /// `charge` for an approval the payee made in stand-in: the shortfall may become debt up to
        /// the larger of the debt cap and the offline cap.
        function chargeStandIn(address token, bytes32 id, uint128 amount, address payee) external;
        /// Releases the caller's hold.
        function release(bytes32 id) external;
        /// Sets how much debt in `token` the caller accepts towards `creditor`. Root key only.
        function setDebtCap(address creditor, address token, uint128 cap) external;
        /// Bounds the caller's final captures in `token` for `payee` when `bounded`: one taking the
        /// hold's captured total past its authorized total by more than `toleranceBps` basis points
        /// reverts `ToleranceExceeded`. Unbounded by default and when `bounded` is false, which
        /// needs a zero `toleranceBps`. Root key only.
        function setCaptureTolerance(address payee, address token, bool bounded, uint32 toleranceBps) external;
        /// Sets how much debt in `token` the caller accepts towards `payee` from its stand-in holds
        /// and charges, when above the debt cap. Root key only.
        function setOfflineCap(address payee, address token, uint128 cap) external;
        /// Releases an expired hold of `owner`. Callable by anyone.
        function releaseExpired(address owner, bytes32 id) external;
        /// Moves `amount` from the payee (caller) back to `owner`, up to the captured total. The
        /// part a credit line paid repays the line first.
        function refund(address owner, bytes32 id, uint128 amount) external;
        /// Opens credit line `line` lending the caller's `token`; the caller is its lender.
        function openLine(bytes32 line, address token) external;
        /// Offers `owner` credit on the caller's line `line`, paid to `payee`, up to `limit`; zero
        /// withdraws the offer. A granted limit above `limit` drops to it at once. Root key only.
        function offerCredit(bytes32 line, address owner, address payee, uint128 limit) external;
        /// Accepts credit on `lender`'s line `line` paid to `payee`, up to `limit`, within the
        /// lender's offer, and reserves the lender's balance for the undrawn limit. Root key only.
        function grantCredit(bytes32 line, address lender, address payee, uint128 limit) external;
        /// Reserves `amount` for `payee` until `expiresAt` as `hold` does, with `linePart` of it on
        /// `lender`'s line `line` instead of the caller's balance.
        function holdWithLine(address token, bytes32 id, uint128 amount, uint128 linePart, bytes32 line, address lender, uint64 expiresAt, address payee) external;
        /// `holdWithLine` through the caller's card `card` issued by `issuer`: runs `holdCard`'s
        /// card checks on the whole `amount`, line part included, then places the line hold and
        /// records the card's line, so freezing the card stops holds funded by the line too.
        function holdCardWithLine(address token, bytes32 id, uint128 amount, uint128 linePart, bytes32 line, address lender, uint64 expiresAt, address payee, address issuer, bytes32 card) external;
        /// Repays up to `amount` of what the caller owes on `lender`'s line `line` from its
        /// available balance.
        function repayCredit(address lender, bytes32 line, uint128 amount) external;

        function getHold(address owner, bytes32 id) external view returns (Hold memory);
        function reserved(address owner, address token) external view returns (uint128);
        function available(address owner, address token) external view returns (uint128);
        function debtOf(address owner, address token) external view returns (address creditor, uint128 amount);
        function debtCap(address owner, address creditor, address token) external view returns (uint128);
        function captureTolerance(address owner, address payee, address token) external view returns (bool bounded, uint32 toleranceBps);
        function captured(address owner, bytes32 id) external view returns (uint128 captured, uint128 refunded);
        function offlineCap(address owner, address payee, address token) external view returns (uint128);
        /// What `owner` may borrow on `lender`'s line, owes on it, and has reserved on it in live holds.
        function creditOf(address owner, address lender, bytes32 line) external view returns (uint128 limit, uint128 owed, uint128 held);
        /// The line's token, zero when it is not open, and how much of the lender's balance it reserves.
        function getLine(address lender, bytes32 line) external view returns (address token, uint128 lien);
        /// The lender's standing offer to `owner` on the line; a zero limit when there is none.
        function creditOffer(address lender, bytes32 line, address owner) external view returns (address payee, uint128 limit);

        event HoldPlaced(address indexed owner, bytes32 indexed id, address indexed token, address payee, uint128 amount, uint64 expiresAt);
        event CardHoldPlaced(address indexed owner, bytes32 indexed id, bytes32 indexed card, uint64 line);
        event StandInHoldPlaced(address indexed owner, bytes32 indexed id, address indexed token, uint128 approved);
        event HoldAdjusted(address indexed owner, bytes32 indexed id, address indexed token, uint128 amount);
        event HoldReleased(address indexed owner, bytes32 indexed id, address indexed token);
        event HoldCaptured(address indexed owner, bytes32 indexed id, address indexed token, uint128 amount, uint128 debt);
        event HoldPartCaptured(address indexed owner, bytes32 indexed id, address indexed token, uint128 amount, uint128 debt);
        event Charged(address indexed owner, bytes32 indexed id, address indexed token, address payee, uint128 amount, uint128 debt);
        event Refunded(address indexed owner, bytes32 indexed id, uint128 amount);
        event DebtRepaid(address indexed owner, address indexed token, address indexed creditor, uint128 amount);
        event LineOpened(address indexed lender, bytes32 indexed line, address indexed token);
        /// The lender's balance the line reserves, emitted whenever it changes.
        event LineReserved(address indexed lender, bytes32 indexed line, address indexed token, uint128 lien);
        event CreditOffered(address indexed lender, bytes32 indexed line, address indexed owner, address payee, uint128 limit);
        event CreditGranted(address indexed owner, address indexed lender, bytes32 indexed line, address payee, uint128 limit);
        /// Follows `HoldPlaced` or `HoldAdjusted` with the part of the hold now on the line.
        event CreditHeld(address indexed owner, bytes32 indexed id, address indexed lender, bytes32 line, uint128 amount);
        event CreditDrawn(address indexed owner, bytes32 indexed id, address indexed lender, bytes32 line, uint128 amount);
        event CreditRepaid(address indexed owner, address indexed lender, bytes32 line, uint128 amount);

        error HoldExists();
        error HoldNotFound();
        error HoldNotExpired();
        error InsufficientAvailable();
        error RefundExceedsCapture();
        error DebtCapExceeded();
        error PolicyForbids();
        error Unauthorized();
        error InvalidAmount();
        error ToleranceExceeded();
        error LineExists();
        error LineNotFound();
        error CreditNotOffered();
    }
}
