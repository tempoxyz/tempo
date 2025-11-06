use alloy::sol;

sol! {
    /// LinkingUSD interface providing system-level initialization functionality.
    ///
    /// This interface extends TIP20 functionality with a special case initialization function
    /// that can only be called by the zero address for genesis or testing flows.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface ILinkingUSD {
        /// System-level initialization function that sets the admin directly.
        /// This function can only be called by the zero address (msg.sender == 0x0).
        /// It's intended for genesis-style flows where the admin must be seeded
        /// before normal flows are possible.
        ///
        /// @param admin The address to set as the admin
        /// @return True if initialization was successful
        function systemTxInitialize(address admin) external;
    }
}
