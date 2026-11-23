pub use IPaymentCallRegistry::{
    IPaymentCallRegistryErrors as PaymentCallRegistryError,
    IPaymentCallRegistryEvents as PaymentCallRegistryEvent,
};
use alloy_primitives::{Address, address};

/// Payment call registry precompile address (TIP-1180).
pub const PAYMENT_CALL_REGISTRY_ADDRESS: Address =
    address!("0x1180000000000000000000000000000000000000");

crate::sol! {
    /// Payment call registry (TIP-1180): contract calls the payment lane admits beside TIP-1045
    /// payment calls.
    ///
    /// Governance registers a *template*: the keccak256 hash of a contract's runtime code with
    /// some byte ranges (its immutables) zeroed, the ranges themselves, and the selectors that
    /// count as payments, each with an exact calldata length and a gas cap. Anyone may then
    /// register an *instance*: a deployed contract whose code, with the template's ranges
    /// zeroed, hashes to the template's hash.
    ///
    /// Additions take effect at a later block and removals at the next block, so a change made
    /// in a block never changes how that block's transactions are classified.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IPaymentCallRegistry {
        /// A byte range of a template's runtime code that differs between instances, such as an
        /// immutable. It must lie inside PUSH immediate data.
        struct CodeRange {
            uint32 offset;
            uint32 length;
        }

        /// A selector whose calls count as registered payment calls.
        struct PaymentSelector {
            bytes4 selector;
            /// Exact calldata length, selector included: 4 plus 32 per static argument.
            uint32 calldataLength;
            /// Gas a call with this selector may add to the transaction gas limit.
            uint64 gasCap;
        }

        struct Template {
            /// keccak256 of the runtime code with every range zeroed.
            bytes32 maskedCodeHash;
            uint32 codeLength;
            /// Timestamp of the proposal; activation is allowed `templateTimelock()` later.
            uint64 proposedAt;
            /// First block whose transactions the template classifies; zero until activated.
            uint64 activationBlock;
            /// First block at which the template no longer classifies; zero unless removed.
            uint64 removedAtBlock;
            CodeRange[] ranges;
            PaymentSelector[] selectors;
        }

        struct Instance {
            /// Zero for an unregistered address.
            uint64 templateId;
            uint64 activationBlock;
            uint64 removedAtBlock;
        }

        // Governance
        function proposeTemplate(bytes calldata code, CodeRange[] calldata ranges, PaymentSelector[] calldata selectors) external returns (uint64 templateId);
        function activateTemplate(uint64 templateId) external;
        function removeTemplate(uint64 templateId) external;
        function removeInstance(address instance) external;

        // Permissionless
        function registerInstance(address instance) external returns (uint64 templateId);

        // Views
        function governance() external view returns (address);
        function version() external view returns (uint64);
        function templateCount() external view returns (uint64);
        function templateTimelock() external view returns (uint64);
        function instanceActivationDelay() external view returns (uint64);
        function getTemplate(uint64 templateId) external view returns (Template memory);
        function getInstance(address instance) external view returns (Instance memory);
        function paymentCallGasCap(address target, bytes calldata input) external view returns (uint64);
        function maskedCodeHash(bytes calldata code, CodeRange[] calldata ranges) external view returns (bytes32);

        // Events
        event TemplateProposed(uint64 indexed templateId, bytes32 maskedCodeHash, uint64 activatableAt);
        event TemplateActivated(uint64 indexed templateId, uint64 activationBlock);
        event TemplateRemoved(uint64 indexed templateId, uint64 removedAtBlock);
        event InstanceRegistered(address indexed instance, uint64 indexed templateId, uint64 activationBlock);
        event InstanceRemoved(address indexed instance, uint64 removedAtBlock);

        // Errors
        error Unauthorized();
        error UnknownTemplate(uint64 templateId);
        error TemplateAlreadyActivated(uint64 templateId);
        error TemplateRemovedAlready(uint64 templateId);
        error TimelockNotElapsed(uint64 activatableAt);
        error InvalidCode();
        error InvalidCodeRange(uint32 offset, uint32 length);
        error ForbiddenOpcode(uint32 offset, uint8 opcode);
        error InvalidPaymentSelector(bytes4 selector);
        error InstanceAlreadyRegistered(address instance);
        error InstanceRemovedAlready(address instance);
        error UnknownInstance(address instance);
        error NoMatchingTemplate(address instance);
        error InstanceCreatedInTransaction(address instance);
    }
}
