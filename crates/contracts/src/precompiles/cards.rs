pub use ICards::{ICardsErrors as CardsError, ICardsEvents as CardsEvent};
use alloy_primitives::{Address, address};

/// Card records precompile address (ASCII "CARD").
pub const CARDS_ADDRESS: Address = address!("0x4341524400000000000000000000000000000000");

crate::sol! {
    /// Card records precompile: cards an issuer's settlement account (the payee) issues on an
    /// owner's account, with status, limit, expiry, replacement and network token hashes that
    /// card-scoped holds check. Cards are keyed by payee then card id.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ICards {
        /// A card's lifecycle state.
        enum Status { Inactive, Active, Frozen, Closed }
        /// A card's program type; every type runs on the same holds.
        enum Program { Debit, Prepaid, Credit, Corporate, Virtual }

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

        /// Reads a card; an unknown card reads with a zero owner.
        function getCard(address payee, bytes32 card) external view returns (Card memory);
        /// The current card of the line a token hash belongs to; zero when unknown.
        function cardByToken(address payee, bytes32 tokenHash) external view returns (bytes32 card);
        /// Whether `payee`'s cards may hold `token`.
        function programAllows(address payee, address token) external view returns (bool);

        event CardIssued(address indexed payee, bytes32 indexed card, address indexed owner, uint64 line);
        event CardUpdated(address indexed payee, bytes32 indexed card, Status status, uint96 limit, uint64 expiresAt, Program program);
        event CardReplaced(address indexed payee, bytes32 indexed card, bytes32 indexed next);
        event CardTokenSet(address indexed payee, bytes32 indexed card, bytes32 tokenHash);
        event ProgramTokensSet(address indexed payee, address[] tokens);

        error CardExists();
        error UnknownCard();
        error CardInactive();
        error CardClosed();
        error CardLimitExceeded();
        error TokenNotAllowed();
        error InvalidCard();
        error Unauthorized();
    }
}
