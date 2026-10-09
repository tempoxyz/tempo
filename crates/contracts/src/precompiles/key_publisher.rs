pub use IKeyPublisher::IKeyPublisherErrors as KeyPublisherError;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IKeyPublisher {
        struct IssuerKeys {
            bytes32 issuer;
            bytes32[] keyHashes;
        }

        event PublisherCreated(bytes32 indexed publisherId, address indexed creator, address indexed owner);
        event OwnershipTransferred(bytes32 indexed publisherId, address indexed previousOwner, address indexed newOwner);
        event KeysSet(bytes32 indexed publisherId, bytes32 indexed issuer, bytes32[] keyHashes, uint64 graceUntil);
        event KeyRevoked(bytes32 indexed publisherId, bytes32 indexed issuer, bytes32 indexed keyHash);

        error PublisherExists();
        error UnknownPublisher();
        error Unauthorized();
        error ZeroAddress();
        error InvalidFieldElement();
        error KeysNotSorted();
        error IssuersNotSorted();
        error TooManyKeys();
        error DelegateCallNotAllowed();

        function createPublisher(bytes32 salt, address owner, IssuerKeys[] calldata initialKeys) external returns (bytes32 publisherId);
        function computePublisherId(address creator, bytes32 salt) external pure returns (bytes32 publisherId);
        function transferOwnership(bytes32 publisherId, address newOwner) external;
        function setKeys(bytes32 publisherId, bytes32 issuer, bytes32[] calldata keyHashes) external;
        function revokeKey(bytes32 publisherId, bytes32 issuer, bytes32 keyHash) external;
        function owner(bytes32 publisherId) external view returns (address);
        function activeKeys(bytes32 publisherId, bytes32 issuer) external view returns (bytes32[] memory);
        function keyValidUntil(bytes32 publisherId, bytes32 issuer, bytes32 keyHash) external view returns (uint64);
        function isKeyActive(bytes32 publisherId, bytes32 issuer, bytes32 keyHash) external view returns (bool);
    }
}
