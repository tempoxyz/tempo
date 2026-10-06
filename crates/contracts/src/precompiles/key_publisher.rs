pub use IKeyPublisher::{
    IKeyPublisherErrors as KeyPublisherError, IKeyPublisherEvents as KeyPublisherEvent,
};

crate::sol! {
    /// [TIP-1132] Key Publisher interface.
    ///
    /// Publishers list the identity-provider keys that ZK signatures may use. Anyone can create
    /// a publisher. Only its owner can change its keys or owner.
    ///
    /// [TIP-1132]: <https://docs.tempo.xyz/protocol/tips/tip-1132>
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IKeyPublisher {
        /// An issuer and its key hashes, used to list a new publisher's first keys.
        struct IssuerKeys {
            bytes32 issuer;
            bytes32[] keyHashes;
        }

        // Publishers
        function createPublisher(bytes32 salt, address owner, IssuerKeys[] calldata initialKeys) external returns (bytes32 publisherId);
        function computePublisherId(address creator, bytes32 salt) external pure returns (bytes32);
        function transferOwnership(bytes32 publisherId, address newOwner) external;

        // Keys
        function setKeys(bytes32 publisherId, bytes32 issuer, bytes32[] calldata keyHashes) external;
        function revokeKey(bytes32 publisherId, bytes32 issuer, bytes32 keyHash) external;

        // View functions
        function owner(bytes32 publisherId) external view returns (address);
        function activeKeys(bytes32 publisherId, bytes32 issuer) external view returns (bytes32[] memory);
        function keyValidUntil(bytes32 publisherId, bytes32 issuer, bytes32 keyHash) external view returns (uint64);
        function isKeyActive(bytes32 publisherId, bytes32 issuer, bytes32 keyHash) external view returns (bool);

        // Events
        event PublisherCreated(bytes32 indexed publisherId, address indexed creator, address indexed owner);
        event OwnershipTransferred(bytes32 indexed publisherId, address indexed previousOwner, address indexed newOwner);
        event KeysSet(bytes32 indexed publisherId, bytes32 indexed issuer, bytes32[] keyHashes, uint64 graceUntil);
        event KeyRevoked(bytes32 indexed publisherId, bytes32 indexed issuer, bytes32 indexed keyHash);

        // Errors
        error PublisherExists();
        error UnknownPublisher();
        error Unauthorized();
        error ZeroAddress();
        error InvalidFieldElement();
        error KeysNotSorted();
        error IssuersNotSorted();
        error TooManyKeys();
    }
}
