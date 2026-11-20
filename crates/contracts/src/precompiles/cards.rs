pub use ICards::{ICardsErrors as CardsError, ICardsEvents as CardsEvent};
use alloy_primitives::{Address, address};

/// Card records precompile address (ASCII "CARD").
pub const CARDS_ADDRESS: Address = address!("0x4341524400000000000000000000000000000000");

crate::sol! {
    /// Card records precompile: cards an issuer's settlement account (the payee) issues on an
    /// owner's account, with status, limit, expiry, replacement and network token hashes that
    /// card-scoped holds check. Cards are keyed by payee then card id. Each owner also has an
    /// account record (status and agent) that every hold checks, which closure and estates set.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ICards {
        /// A card's lifecycle state.
        enum Status { Inactive, Active, Frozen, Closed }
        /// A card's program type; every type runs on the same holds.
        enum Program { Debit, Prepaid, Credit, Corporate, Virtual }
        /// An account's lifecycle state; holds need Active.
        enum AccountStatus { Active, Dormant, Estate, Closed }
        /// A role an authority holds in the registry the admin keeps.
        enum Role { Escheat, Estate }

        /// A card as `getCard` reads it: its line's fields, seen through one credential.
        struct Card {
            address owner;
            address payee;
            Status status;
            Program program;
            uint64 expiresAt;
            uint96 limit;
            uint96 committed;
            bytes32 holder;
            bytes32 current;
            bytes32 replacedBy;
            bytes32 tokenHash;
            uint64 line;
        }

        /// An owner's account record. `agent` is the executor in Estate and the payout address
        /// once Closed.
        struct Account {
            AccountStatus status;
            uint64 lastActive;
            address agent;
        }

        /// Issues `card` under the caller (the payee) on `owner`'s account. A `limit` of
        /// `type(uint96).max` is no limit; an `expiresAt` of zero never expires.
        function issueCard(address owner, bytes32 card, Status status, uint96 limit, uint64 expiresAt, Program program, bytes32 holder) external;
        /// Sets every issuer field of the caller's current card `card`.
        function updateCard(bytes32 card, Status status, uint96 limit, uint64 expiresAt, Program program, bytes32 holder) external;
        /// Maps the new credential `next` to `card`'s line, closes `card` and activates the line.
        function replaceCard(bytes32 card, bytes32 next) external;
        /// Sets the hash of the network token reference of the caller's current card `card`;
        /// zero removes it.
        function setTokenHash(bytes32 card, bytes32 tokenHash) external;
        /// Lists the tokens the caller's cards may hold; an empty list allows every token.
        function setProgramTokens(address[] calldata tokens) external;
        /// The owner, with its root key, freezes, unfreezes or closes its card.
        function setCardStatus(address payee, bytes32 card, Status status) external;
        /// The owner, with its root key, lowers its card's limit.
        function lowerCardLimit(address payee, bytes32 card, uint96 limit) external;

        /// The owner, with its root key, closes its account (from Active or Dormant) and sweeps
        /// `token` to `payoutTo`; a later call may change `payoutTo`. Returns what it paid out.
        function closeAccount(address token, address payoutTo) external returns (uint128 paid);
        /// Repays a closed account's debt in `token` from its available balance and pays the rest
        /// to its payout address. Anyone may call it.
        function sweep(address owner, address token) external returns (uint128 paid);
        /// A listed Escheat authority marks an Active owner dormant once it has been idle for the
        /// authority's dormancy period: new holds stop until the owner reactivates.
        function markDormant(address owner) external;
        /// The owner, with its root key, returns its dormant account to Active.
        function reactivate() external;
        /// The owner, with its root key, records activity on its Active account.
        function touch() external;
        /// A listed Escheat authority takes a dormant account's `token`, after debts, once it has been
        /// idle for the authority's escheat period: paid to the authority's payout address, or into
        /// `via` (such as a savings facility) for that address. Returns what it paid.
        function escheat(address owner, address token, address via) external returns (uint128 paid);
        /// What sweeps of `owner`'s `token` paid into `via` so far, and who it is for.
        function payoutOf(address owner, address token, address via) external view returns (address to, uint128 amount);
        /// An Estate authority records an owner's death: holds stop, cards read Frozen, and only
        /// `executor` can settle the estate.
        function setEstate(address owner, address executor) external;
        /// The executor sweeps `token` to `to` once no hold in it is open, then closes the
        /// account with `to` as its payout address.
        function settleEstate(address owner, address token, address to) external returns (uint128 paid);
        /// The admin lists or delists an authority in a role, with an Escheat authority's payout
        /// address and periods in seconds.
        function setAuthority(address authority, Role role, bool listed, address payout, uint32 dormancy, uint32 escheatAfter) external;

        /// The owner, with its root key, sets its calendar-month spend window for `issuer`'s card
        /// holds: `limit` on what they commit in a period, whose current one ends at `firstEnd` and
        /// each later one a calendar month after (UTC). A `firstEnd` of zero removes the window.
        function setSpendWindow(address issuer, uint32 firstEnd, uint96 limit) external;
        /// The owner, with its root key, sets whether `merchant` (an opaque reference the issuer
        /// supplies) may hold through `issuer`'s cards, and its limit in each spend window period.
        function setMerchantMandate(address issuer, bytes32 merchant, bool revoked, uint96 limit) external;
        /// The owner, with its root key, sets its daily limits for `issuer`'s card holds: `limit` on
        /// what they commit in a day, whose current one ends at `firstEnd` and each later one 24 hours
        /// after, and `perPurchase` on what one hold commits. A `firstEnd` of zero removes both.
        function setDailyLimits(address issuer, uint32 firstEnd, uint64 limit, uint64 perPurchase) external;
        /// Reads an owner's daily limits for an issuer, as of now; a zero `periodEnd` is none.
        function dailyLimits(address owner, address issuer) external view returns (uint32 periodEnd, uint64 limit, uint64 perPurchase, uint64 committed);
        /// Reads an owner's spend window for an issuer, as of now; a zero `periodEnd` is no window.
        function spendWindow(address owner, address issuer) external view returns (uint32 periodEnd, uint96 limit, uint96 committed);
        /// Reads an owner's mandate for a merchant under an issuer, as of now.
        function merchantMandate(address owner, address issuer, bytes32 merchant) external view returns (bool revoked, uint96 limit, uint96 committed);

        /// Reads an owner's account record; an owner never recorded reads Active.
        function getAccount(address owner) external view returns (Account memory);
        /// Reads an authority's registry entry in a role.
        function authorityOf(address authority, Role role) external view returns (bool listed, address payout, uint32 dormancy, uint32 escheatAfter);
        /// Reads a card; an unknown card reads with a zero owner.
        function getCard(address payee, bytes32 card) external view returns (Card memory);
        /// The current card of the line a token hash belongs to; zero when unknown.
        function cardByToken(address payee, bytes32 tokenHash) external view returns (bytes32 card);
        /// Whether `payee`'s cards may hold `token`.
        function programAllows(address payee, address token) external view returns (bool);
        /// Records that the caller (an attester) checked `owner` for `claim` under `jurisdiction`,
        /// keeping only the hash of its record, until `expiresAt`; replaces the caller's earlier
        /// attestation of the claim, and an `expiresAt` of zero revokes it.
        function attest(address owner, bytes32 claim, bytes32 jurisdiction, bytes32 record, uint64 expiresAt) external;
        /// Sets the caller's (a payee's) identity policy: holds paid to it, or through its cards,
        /// need a live attestation of `claim` under `jurisdiction` from one of `attesters`. No
        /// attesters clears the policy.
        function setIdentityPolicy(bytes32 claim, bytes32 jurisdiction, address[] calldata attesters) external;
        function attestationOf(address owner, address attester, bytes32 claim) external view returns (bytes32 jurisdiction, bytes32 record, uint64 expiresAt);
        function identityPolicy(address payee) external view returns (bytes32 claim, bytes32 jurisdiction, address[] memory attesters);

        event CardIssued(address indexed payee, bytes32 indexed card, address indexed owner, uint64 line);
        event CardUpdated(address indexed payee, bytes32 indexed card, Status status, uint96 limit, uint64 expiresAt, Program program);
        event CardReplaced(address indexed payee, bytes32 indexed card, bytes32 indexed next);
        event CardTokenSet(address indexed payee, bytes32 indexed card, bytes32 tokenHash);
        event ProgramTokensSet(address indexed payee, address[] tokens);
        event AccountStatusSet(address indexed owner, AccountStatus status, address agent);
        event PayoutRecorded(address indexed owner, address indexed token, address indexed via, address to, uint128 amount);
        event AccountSwept(address indexed owner, address indexed token, address indexed to, uint128 debtRepaid, uint128 paid);
        event SpendWindowSet(address indexed owner, address indexed issuer, uint32 periodEnd, uint96 limit);
        event DailyLimitsSet(address indexed owner, address indexed issuer, uint32 periodEnd, uint64 limit, uint64 perPurchase);
        event MerchantMandateSet(address indexed owner, address indexed issuer, bytes32 indexed merchant, bool revoked, uint96 limit);
        event Attested(address indexed owner, address indexed attester, bytes32 indexed claim, bytes32 jurisdiction, bytes32 record, uint64 expiresAt);
        event IdentityPolicySet(address indexed payee, bytes32 claim, bytes32 jurisdiction, address[] attesters);
        event AuthoritySet(address indexed authority, Role role, bool listed, address payout, uint32 dormancy, uint32 escheatAfter);

        error CardExists();
        error UnknownCard();
        error CardInactive();
        error CardClosed();
        error CardLimitExceeded();
        error TokenNotAllowed();
        error InvalidCard();
        error Unauthorized();
        error AccountInactive();
        error AccountStateInvalid();
        error HoldsOpen();
        error MerchantRevoked();
        error WindowLimitExceeded();
        error IdentityRequired();
        error TooManyAttesters();
    }
}
