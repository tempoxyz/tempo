// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20RolesAuth } from "./abstracts/TIP20RolesAuth.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";
import { ITIP20Controller } from "./interfaces/ITIP20Controller.sol";

/// @title TIP20Controller
/// @notice A singleton controller contract that manages minting rate limits and allowances for
/// multiple TIP20 stablecoins backed by a single reserve ledger token
/// @dev Adapted from TokenAuthority - uses ReserveStore contracts instead of wrap/unwrap
///      for TIP20 compatibility. Each stablecoin has its own ReserveStore to keep ledger
///      tokens separate for reconciliation purposes.
contract TIP20Controller is ITIP20Controller, TIP20RolesAuth {

    /*//////////////////////////////////////////////////////////////////////////
                                Immutable Variables
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice The reserve ledger token used to back all stablecoins
    address public immutable RESERVE_LEDGER_TOKEN;

    /// @notice Absolute maximum amount for any single operation (1 billion with 6 decimals)
    uint256 public constant ABSOLUTE_MAX = 1_000_000_000 * 10e6;

    /*//////////////////////////////////////////////////////////////////////////
                                Role Constants
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Role required to set mint rate limits and minter allowances
    bytes32 public constant MINT_RATE_LIMIT_SETTER_ROLE = keccak256("MINT_RATE_LIMIT_SETTER_ROLE");

    /// @notice Role required to burn tokens
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    /// @notice Role required to unwrap stablecoins back to reserve tokens
    bytes32 public constant UNWRAPPER_ROLE = keccak256("UNWRAPPER_ROLE");

    /// @notice Role for bridge ecosystem contracts that bypass rate limits
    bytes32 public constant BRIDGE_ECOSYSTEM_CONTRACT_ROLE =
        keccak256("BRIDGE_ECOSYSTEM_CONTRACT_ROLE");

    /*//////////////////////////////////////////////////////////////////////////
                                State Variables
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Maps stablecoin contract address and user address to minter allowance
    /// @dev minterAllowances[stablecoinContract][user] = remaining tokens that can be minted
    mapping(address stablecoinContract => mapping(address user => uint256 minterAllowance)) public
        minterAllowances;

    /// @notice Maps stablecoin contract address to per-transaction mint limit
    mapping(address stablecoinContract => uint256 mintTxnLimit) public mintTxnLimits;

    /// @notice Maps stablecoin contract address to its ReserveStore address
    mapping(address stablecoinContract => address reserveStore) public reserveStores;

    /*//////////////////////////////////////////////////////////////////////////
                                    Constructor
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Constructs the TIP20Controller contract
    /// @param _reserveLedgerToken The address of the reserve ledger token
    /// @param _admin The address to be granted admin role
    constructor(address _reserveLedgerToken, address _admin) {
        RESERVE_LEDGER_TOKEN = _reserveLedgerToken;
        hasRole[_admin][DEFAULT_ADMIN_ROLE] = true;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                        Mint
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Mints stablecoins to a recipient address
    /// @dev Checks and decrements transaction limit and minter allowance before minting.
    ///      Caller must have pre-approved this contract to spend their reserve ledger tokens.
    /// @param stablecoinContract The address of the stablecoin contract to mint from
    /// @param to The address to receive the minted tokens
    /// @param amount The amount of tokens to mint
    function mint(address stablecoinContract, address to, uint256 amount) external {
        if (amount == 0) revert AmountCannotBeZero();

        uint256 mintTxnLimit = mintTxnLimits[stablecoinContract];
        uint256 minterAllowance = minterAllowances[stablecoinContract][msg.sender];
        if (minterAllowance < amount) revert MinterAllowanceExceeded();
        if (mintTxnLimit < amount) revert MintTxnLimitExceeded();

        minterAllowances[stablecoinContract][msg.sender] -= amount;

        _mint(stablecoinContract, to, amount);
    }

    /// @notice Mints stablecoins to a specified address for bridge ecosystem contracts
    /// @dev Callable only by contracts with BRIDGE_ECOSYSTEM_CONTRACT_ROLE.
    ///      Does not enforce minter allowance or per-transaction mint limits.
    /// @param stablecoinContract The address of the stablecoin contract to mint from
    /// @param to The recipient address that will receive the minted tokens
    /// @param amount The amount of tokens to mint
    function mintBridgeEcosystem(address stablecoinContract, address to, uint256 amount)
        external
        onlyRole(BRIDGE_ECOSYSTEM_CONTRACT_ROLE)
    {
        _mint(stablecoinContract, to, amount);
    }

    /// @notice Burns tokens from the sender's balance for a given stablecoin contract
    /// @dev Transfers stablecoin from sender, burns it, and returns reserve ledger tokens
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param amount The amount of tokens to burn
    function burn(address stablecoinContract, uint256 amount) external onlyRole(BURNER_ROLE) {
        if (stablecoinContract == RESERVE_LEDGER_TOKEN) {
            if (!ITIP20(RESERVE_LEDGER_TOKEN).transferFrom(msg.sender, address(this), amount)) {
                revert TransferFailed();
            }
            ITIP20(RESERVE_LEDGER_TOKEN).burn(amount);
        } else {
            address reserveStore = reserveStores[stablecoinContract];
            if (reserveStore == address(0)) revert ReserveStoreNotConfigured();

            if (!ITIP20(stablecoinContract).transferFrom(msg.sender, address(this), amount)) {
                revert TransferFailed();
            }
            ITIP20(stablecoinContract).burn(amount);

            if (!ITIP20(RESERVE_LEDGER_TOKEN).transferFrom(reserveStore, msg.sender, amount)) {
                revert TransferFailed();
            }
        }

        emit Burn(msg.sender, stablecoinContract, amount);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    Wrap/Unwrap
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Wraps reserve ledger tokens into stablecoins
    /// @dev Transfers reserve tokens from sender to ReserveStore, mints stablecoins to recipient.
    ///      Unlike mint(), this does not require minter allowance or respect rate limits.
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param to The address to receive the stablecoins
    /// @param amount The amount to wrap
    function wrap(address stablecoinContract, address to, uint256 amount) external {
        if (amount == 0) revert AmountCannotBeZero();
        if (amount > ABSOLUTE_MAX) revert AmountExceedsAbsoluteMax();

        address reserveStore = reserveStores[stablecoinContract];
        if (reserveStore == address(0)) revert ReserveStoreNotConfigured();

        if (!ITIP20(RESERVE_LEDGER_TOKEN).transferFrom(msg.sender, reserveStore, amount)) {
            revert TransferFailed();
        }
        ITIP20(stablecoinContract).mint(to, amount);

        emit Wrap(msg.sender, stablecoinContract, to, amount);
    }

    /// @notice Unwraps stablecoins back to reserve ledger tokens
    /// @dev Burns stablecoins from sender, transfers reserve tokens from ReserveStore to sender.
    ///      Unlike burn(), this returns the reserve tokens instead of destroying them.
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param amount The amount to unwrap
    function unwrap(address stablecoinContract, uint256 amount) external onlyRole(UNWRAPPER_ROLE) {
        if (amount == 0) revert AmountCannotBeZero();

        address reserveStore = reserveStores[stablecoinContract];
        if (reserveStore == address(0)) revert ReserveStoreNotConfigured();

        if (!ITIP20(stablecoinContract).transferFrom(msg.sender, address(this), amount)) {
            revert TransferFailed();
        }
        ITIP20(stablecoinContract).burn(amount);

        if (!ITIP20(RESERVE_LEDGER_TOKEN).transferFrom(reserveStore, msg.sender, amount)) {
            revert TransferFailed();
        }

        emit Unwrap(msg.sender, stablecoinContract, amount);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                Mint Rate Setters
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Sets the per-transaction mint limit for a stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param mintTxnLimit The per-transaction mint limit to set
    function setTxnMintLimit(address stablecoinContract, uint256 mintTxnLimit)
        external
        onlyRole(MINT_RATE_LIMIT_SETTER_ROLE)
    {
        if (mintTxnLimit >= type(uint256).max / 2) revert AmountExceedsAbsoluteMax();
        mintTxnLimits[stablecoinContract] = mintTxnLimit;

        emit TxnMintLimitSet(msg.sender, stablecoinContract, mintTxnLimit);
    }

    /// @notice Sets the mint allowance for a specific minter on a stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param minter The address of the minter
    /// @param minterAllowance The allowance amount to set for the minter
    function setMinterAllowance(address stablecoinContract, address minter, uint256 minterAllowance)
        external
        onlyRole(MINT_RATE_LIMIT_SETTER_ROLE)
    {
        if (minterAllowance >= type(uint256).max / 2) revert AmountExceedsAbsoluteMax();
        minterAllowances[stablecoinContract][minter] = minterAllowance;

        emit MinterAllowanceSet(msg.sender, stablecoinContract, minter, minterAllowance);
    }

    /// @notice Sets the reserve store for a stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param reserveStore The address of the reserve store
    function setReserveStore(address stablecoinContract, address reserveStore)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        reserveStores[stablecoinContract] = reserveStore;

        emit ReserveStoreSet(msg.sender, stablecoinContract, reserveStore);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                Getters
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Gets the mint allowance for a specific minter on a stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @param minter The address of the minter
    /// @return minterAllowance The remaining allowance for the minter
    function getMinterAllowance(address stablecoinContract, address minter)
        external
        view
        returns (uint256 minterAllowance)
    {
        return minterAllowances[stablecoinContract][minter];
    }

    /// @notice Gets the per-transaction mint limit for a specific stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @return mintTxnLimit The per-transaction mint limit
    function getStablecoinTxnMintLimit(address stablecoinContract)
        external
        view
        returns (uint256 mintTxnLimit)
    {
        return mintTxnLimits[stablecoinContract];
    }

    /// @notice Gets the reserve store for a specific stablecoin contract
    /// @param stablecoinContract The address of the stablecoin contract
    /// @return reserveStore The address of the reserve store
    function getReserveStore(address stablecoinContract)
        external
        view
        returns (address reserveStore)
    {
        return reserveStores[stablecoinContract];
    }

    /*//////////////////////////////////////////////////////////////////////////
                                Internal Functions
    //////////////////////////////////////////////////////////////////////////*/

    function _mint(address stablecoinContract, address to, uint256 amount) internal {
        if (amount > ABSOLUTE_MAX) revert AmountExceedsAbsoluteMax();

        if (stablecoinContract == RESERVE_LEDGER_TOKEN) {
            if (!ITIP20(RESERVE_LEDGER_TOKEN).transferFrom(msg.sender, address(this), amount)) {
                revert TransferFailed();
            }
            ITIP20(RESERVE_LEDGER_TOKEN).transfer(to, amount);
        } else {
            address reserveStore = reserveStores[stablecoinContract];
            if (reserveStore == address(0)) revert ReserveStoreNotConfigured();

            if (!ITIP20(RESERVE_LEDGER_TOKEN).transferFrom(msg.sender, reserveStore, amount)) {
                revert TransferFailed();
            }
            ITIP20(stablecoinContract).mint(to, amount);
        }

        emit Mint(msg.sender, stablecoinContract, to, amount);
    }

}
