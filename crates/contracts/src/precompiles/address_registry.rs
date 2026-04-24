pub use IAddressRegistry::{
    IAddressRegistryErrors as AddrRegistryError, IAddressRegistryEvents as AddrRegistryEvent,
};

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
