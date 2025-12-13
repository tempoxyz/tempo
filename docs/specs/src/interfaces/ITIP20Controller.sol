// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title ITIP20Controller
/// @notice Interface for the TIP20Controller contract which manages minting rate limits and
/// allowances for stablecoins backed by a reserve ledger token
/// @dev Adapted from TokenAuthority for TIP20 tokens - uses ReserveStore instead of wrap/unwrap
interface ITIP20Controller {

    /*//////////////////////////////////////////////////////////////////////////
                                    Errors
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Thrown when a mint operation would exceed the per-transaction mint limit
    error MintTxnLimitExceeded();

    /// @notice Thrown when a mint operation would exceed the minter's allowance
    error MinterAllowanceExceeded();

    /// @notice Thrown when attempting to perform an operation with an amount of zero
    error AmountCannotBeZero();

    /// @notice Thrown when a mint operation would exceed the absolute maximum amount
    error AmountExceedsAbsoluteMax();

    /// @notice Thrown when no reserve store is configured for a stablecoin
    error ReserveStoreNotConfigured();

    /// @notice Thrown when a transfer operation fails
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////////////////
                                    Events
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the per-transaction mint limit is updated for a stablecoin
    /// @param sender The address that set the limit
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param mintTxnLimit The new per-transaction mint limit
    event TxnMintLimitSet(
        address indexed sender, address indexed stablecoinContract, uint256 mintTxnLimit
    );

    /// @notice Emitted when a minter's allowance is set for a stablecoin
    /// @param sender The address that set the allowance
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param minter The address of the minter whose allowance is being set
    /// @param minterAllowance The new allowance for the minter
    event MinterAllowanceSet(
        address indexed sender,
        address indexed stablecoinContract,
        address indexed minter,
        uint256 minterAllowance
    );

    /// @notice Emitted when tokens are minted to a recipient
    /// @param sender The address that initiated the mint operation
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param to The address receiving the minted tokens
    /// @param amount The amount of tokens minted
    event Mint(
        address indexed sender,
        address indexed stablecoinContract,
        address indexed to,
        uint256 amount
    );

    /// @notice Emitted when tokens are burned
    /// @param sender The address that initiated the burn operation
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param amount The amount of tokens burned
    event Burn(address indexed sender, address indexed stablecoinContract, uint256 amount);

    /// @notice Emitted when a reserve store is set for a stablecoin
    /// @param sender The address that set the reserve store
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param reserveStore The address of the reserve store
    event ReserveStoreSet(
        address indexed sender, address indexed stablecoinContract, address indexed reserveStore
    );

    /// @notice Emitted when reserve tokens are wrapped into stablecoins
    /// @param sender The address that initiated the wrap
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param to The address receiving the stablecoins
    /// @param amount The amount wrapped
    event Wrap(
        address indexed sender,
        address indexed stablecoinContract,
        address indexed to,
        uint256 amount
    );

    /// @notice Emitted when stablecoins are unwrapped back to reserve tokens
    /// @param sender The address that initiated the unwrap
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param amount The amount unwrapped
    event Unwrap(address indexed sender, address indexed stablecoinContract, uint256 amount);

    /*//////////////////////////////////////////////////////////////////////////
                                    Functions
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Mints stablecoins to a recipient address
    /// @param stablecoinContract The address of the stablecoin contract to mint from
    /// @param to The address to receive the minted tokens
    /// @param amount The amount of tokens to mint
    function mint(address stablecoinContract, address to, uint256 amount) external;

    /// @notice Mints stablecoins to a specified address for bridge ecosystem contracts
    /// @param stablecoinContract The address of the stablecoin contract to mint from
    /// @param to The recipient address that will receive the minted tokens
    /// @param amount The amount of tokens to mint
    function mintBridgeEcosystem(address stablecoinContract, address to, uint256 amount) external;

    /// @notice Burns tokens from the sender's balance for a given stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param amount The amount of tokens to burn
    function burn(address stablecoinContract, uint256 amount) external;

    /// @notice Wraps reserve ledger tokens into stablecoins
    /// @dev Transfers reserve tokens from sender to ReserveStore, mints stablecoins to recipient
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param to The address to receive the stablecoins
    /// @param amount The amount to wrap
    function wrap(address stablecoinContract, address to, uint256 amount) external;

    /// @notice Unwraps stablecoins back to reserve ledger tokens
    /// @dev Burns stablecoins from sender, transfers reserve tokens from ReserveStore to sender
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param amount The amount to unwrap
    function unwrap(address stablecoinContract, uint256 amount) external;

    /// @notice Sets the per-transaction mint limit for a stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param mintTxnLimit The per-transaction mint limit to set
    function setTxnMintLimit(address stablecoinContract, uint256 mintTxnLimit) external;

    /// @notice Sets the mint allowance for a specific minter on a stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param minter The address of the minter
    /// @param minterAllowance The allowance amount to set for the minter
    function setMinterAllowance(address stablecoinContract, address minter, uint256 minterAllowance)
        external;

    /// @notice Sets the reserve store for a stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param reserveStore The address of the reserve store
    function setReserveStore(address stablecoinContract, address reserveStore) external;

    /// @notice Gets the mint allowance for a specific minter on a stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param minter The address of the minter
    /// @return minterAllowance The remaining allowance for the minter
    function getMinterAllowance(address stablecoinContract, address minter)
        external
        view
        returns (uint256 minterAllowance);

    /// @notice Gets the per-transaction mint limit for a specific stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @return mintTxnLimit The per-transaction mint limit
    function getStablecoinTxnMintLimit(address stablecoinContract)
        external
        view
        returns (uint256 mintTxnLimit);

    /// @notice Gets the reserve store for a specific stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @return reserveStore The address of the reserve store
    function getReserveStore(address stablecoinContract)
        external
        view
        returns (address reserveStore);

}
