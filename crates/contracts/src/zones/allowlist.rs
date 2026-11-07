//! `IZoneAllowlist` — Zone L2 deposit allowlist precompile interface (0x1c00...0003).

pub use IZoneAllowlist::{
    IZoneAllowlistErrors as ZoneAllowlistError, IZoneAllowlistEvents as ZoneAllowlistEvent,
};

crate::sol! {
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    contract IZoneAllowlist {
        /// Emitted when the allowlist admin changes.
        event AdminChanged(address indexed previousAdmin, address indexed newAdmin);
        /// Emitted when enforcement is switched on or off.
        event EnabledChanged(bool enabled);
        /// Emitted after every `setAllowed` batch with the resulting member count. Member
        /// addresses are never emitted, to keep the list private.
        event AllowlistChanged(uint256 count);

        /// The caller may not perform this call.
        error Unauthorized();
        /// A `setAllowed` batch exceeds the per-call limit.
        error BatchTooLarge(uint256 length, uint256 max);
        /// Adding the batch would exceed the total list size limit.
        error AllowlistFull(uint256 max);

        /// Returns the account allowed to change the list and toggle enforcement.
        function admin() external view returns (address);
        /// Returns whether deposits are restricted to listed senders.
        function enabled() external view returns (bool);
        /// Returns the number of listed accounts. Readable by the admin and portal sequencers.
        function count() external view returns (uint256);
        /// Returns whether `account` may deposit: true when enforcement is disabled or the account
        /// is listed. Readable by `account` itself, the admin and portal sequencers.
        function isAllowed(address account) external view returns (bool);
        /// Returns up to `limit` listed accounts starting at `offset`. Readable by the admin and
        /// portal sequencers.
        function accounts(uint256 offset, uint256 limit) external view returns (address[] memory);
        /// Replaces the admin. Callable by the current admin or a ZonePortal sequencer on Tempo.
        function setAdmin(address newAdmin) external;
        /// Switches enforcement on or off. Admin only.
        function setEnabled(bool enabled) external;
        /// Adds (`allowed = true`) or removes accounts in one batch. Admin only.
        function setAllowed(address[] calldata accounts, bool allowed) external;
    }
}
