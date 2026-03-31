pub use IAddressRegistry::{
    IAddressRegistryErrors as AddrRegistryError, IAddressRegistryEvents as AddrRegistryEvent,
};
use alloy_primitives::Address;

crate::sol! {
    /// [TIP-1022] virtual address registry interface.
    ///
    /// Allows EOAs and contracts to register as virtual-address masters via a
    /// 32-bit proof-of-work and provides resolution of virtual addresses back to
    /// their registered master.
    ///
    /// [TIP-1022]: <https://docs.tempo.xyz/protocol/tip1022>
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IAddressRegistry {
        // Registration
        function registerVirtualMaster(bytes32 salt) external returns (bytes4 masterId);

        // View functions
        function getMaster(bytes4 masterId) external view returns (address);
        function resolveRecipient(address to) external view returns (address effectiveRecipient);
        function resolveVirtualAddress(address virtualAddr) external view returns (address master);

        // Pure functions
        function isVirtualAddress(address addr) external pure returns (bool);
        function decodeVirtualAddress(address addr) external pure returns (bool isVirtual, bytes4 masterId, bytes6 userTag);

        // Events
        event MasterRegistered(bytes4 indexed masterId, address indexed masterAddress);

        // Errors
        error MasterIdCollision(address master);
        error InvalidMasterAddress();
        error ProofOfWorkFailed();
        error VirtualAddressUnregistered();
    }
}

impl AddrRegistryError {
    /// The computed `masterId` is already registered to the given `master` address.
    pub const fn master_id_collision(master: Address) -> Self {
        Self::MasterIdCollision(IAddressRegistry::MasterIdCollision { master })
    }

    /// The caller address is not eligible to be a virtual-address master.
    pub const fn invalid_master_address() -> Self {
        Self::InvalidMasterAddress(IAddressRegistry::InvalidMasterAddress {})
    }

    /// The registration hash does not satisfy the 32-bit proof-of-work requirement.
    pub const fn proof_of_work_failed() -> Self {
        Self::ProofOfWorkFailed(IAddressRegistry::ProofOfWorkFailed {})
    }

    /// The virtual address has a valid format but its `masterId` is not registered.
    pub const fn virtual_address_unregistered() -> Self {
        Self::VirtualAddressUnregistered(IAddressRegistry::VirtualAddressUnregistered {})
    }
}
