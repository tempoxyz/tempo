crate::sol! {
    /// Epoch-scoped temporary key-value storage as per [TIP-1040].
    ///
    /// Values are stored per `msg.sender` and expire automatically: data written in a
    /// given epoch is readable during that epoch and the next, then becomes inaccessible.
    ///
    /// [TIP-1040]: <https://docs.tempo.xyz/protocol/tip1040>
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITemporaryStorage {
        /// Stores `value` for the caller under `key` in the current epoch.
        /// @param key Caller-chosen 32-byte key
        /// @param value The value to store
        function temporaryStore(bytes32 key, bytes32 value) external;

        /// Loads the caller's value for `key`, checking the current epoch first and
        /// falling back to the previous epoch.
        /// @param key Caller-chosen 32-byte key
        /// @return value The stored value, or zero if not found in either epoch
        function temporaryLoad(bytes32 key) external view returns (bytes32 value);
    }
}
