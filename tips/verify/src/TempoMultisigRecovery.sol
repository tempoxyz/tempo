// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.34;

/// @notice CREATE2 factory for native multisig recovery wallets on non-Tempo EVM chains.
contract TempoMultisigRecoveryFactory {

    error DeploymentFailed();

    event RecoveryWalletDeployed(bytes32 indexed accountSalt, address indexed wallet);

    bytes32 public constant WALLET_INIT_CODE_HASH =
        keccak256(type(TempoMultisigRecoveryWallet).creationCode);

    function walletAddress(bytes32 accountSalt) public view returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), accountSalt, WALLET_INIT_CODE_HASH)
        );
        return address(uint160(uint256(digest)));
    }

    function deploy(bytes32 accountSalt) public returns (address wallet) {
        wallet = walletAddress(accountSalt);
        if (wallet.code.length != 0) {
            return wallet;
        }

        bytes memory creationCode = type(TempoMultisigRecoveryWallet).creationCode;
        assembly {
            wallet := create2(0, add(creationCode, 0x20), mload(creationCode), accountSalt)
        }
        if (wallet == address(0)) {
            revert DeploymentFailed();
        }
        // Bind the freshly deployed wallet to the config committed to by `accountSalt`. Only this
        // factory can CREATE2 a wallet at this address, and it always initializes in the same
        // transaction, so `recover` can trust the stored salt as the wallet's true config.
        TempoMultisigRecoveryWallet(payable(wallet)).initialize(accountSalt);
        emit RecoveryWalletDeployed(accountSalt, wallet);
    }

}

/// @notice Minimal recovery wallet for assets sent to a native multisig address on EVM chains.
contract TempoMultisigRecoveryWallet {

    struct Owner {
        address owner;
        uint8 weight;
    }

    struct InitMultisig {
        bytes32 salt;
        uint8 threshold;
        Owner[] owners;
    }

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    error InvalidConfig();
    error InvalidSignature();
    error InvalidThreshold();
    error InvalidOwner();
    error UnauthorizedFactory();
    error CallFailed(uint256 index, bytes returndata);
    error AlreadyInitialized();
    error UnsupportedCall(uint256 index);

    // Standard token transfer selectors. Recovery is limited to these (plus native-value sweeps)
    // so a compromised or malicious initial owner set cannot use the cross-chain address for
    // governance, bridging, approvals, or any other arbitrary call — only asset recovery.
    bytes4 internal constant ERC20_TRANSFER = 0xa9059cbb; // transfer(address,uint256)
    bytes4 internal constant ERC721_TRANSFER_FROM = 0x23b872dd; // transferFrom(a,a,u256)
    bytes4 internal constant ERC721_SAFE_TRANSFER_FROM = 0x42842e0e; // safeTransferFrom(a,a,u256)
    bytes4 internal constant ERC721_SAFE_TRANSFER_FROM_DATA = 0xb88d4fde; // safeTransferFrom(a,a,u,b)
    bytes4 internal constant ERC1155_SAFE_TRANSFER_FROM = 0xf242432a; // safeTransferFrom(a,a,u,u,b)
    bytes4 internal constant ERC1155_SAFE_BATCH_TRANSFER_FROM = 0x2eb2c2d6; // safeBatchTransferFrom

    uint256 public nonce;

    address private immutable FACTORY = msg.sender;

    /// @notice CREATE2 salt committing to the immutable initial config this wallet recovers for.
    /// @dev Set once by the factory in the same transaction as deployment. `recover` requires the
    /// supplied config to re-derive this salt, so a caller cannot recover with an arbitrary config.
    bytes32 public accountSalt;
    bool private initialized;

    bytes internal constant ACCOUNT_DOMAIN = "tempo:multisig:account";
    bytes internal constant RECOVERY_DOMAIN = "tempo:multisig:recovery";
    uint256 internal constant MAX_OWNERS = 48;
    uint256 internal constant MAX_SIGNATURES = 8;
    uint256 internal constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    receive() external payable { }

    /// @notice Accepts safe ERC-721 transfers and mints before and after recovery deployment.
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    )
        external
        pure
        returns (bytes4)
    {
        return this.onERC721Received.selector;
    }

    /// @notice Accepts safe ERC-1155 single-token transfers and mints.
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    )
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    /// @notice Accepts safe ERC-1155 batch transfers and mints.
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    )
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    /// @notice Reports the receiver interfaces implemented by the recovery wallet.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 // ERC-165
            || interfaceId == 0x150b7a02 // ERC-721 receiver
            || interfaceId == 0x4e2312e0; // ERC-1155 receiver
    }

    /// @notice Binds this wallet to the config committed to by `salt`. Callable once.
    /// @dev Permissionless but safe: only the factory can CREATE2 a wallet at this address, and it
    /// always calls this in the same transaction as deployment, so the wallet is never observable
    /// in a deployed-but-uninitialized state.
    function initialize(bytes32 salt) external {
        if (msg.sender != FACTORY) {
            revert UnauthorizedFactory();
        }
        if (initialized) {
            revert AlreadyInitialized();
        }
        accountSalt = salt;
        initialized = true;
    }

    function recover(
        InitMultisig calldata init,
        bytes[] calldata signatures,
        Call[] calldata calls
    )
        external
        payable
    {
        if (!initialized) {
            revert InvalidConfig();
        }
        // Bind the supplied config to the one this wallet was deployed for. Without this check any
        // caller could pass their own owner set + signatures and drain the wallet.
        if (deriveAccountSalt(init) != accountSalt) {
            revert InvalidConfig();
        }
        bytes32 digest = recoveryDigest(accountSalt, calls);
        verifyOwnerSignatures(init, digest, signatures);
        unchecked {
            ++nonce;
        }

        for (uint256 i = 0; i < calls.length; ++i) {
            if (!_isAllowedRecoveryCall(calls[i])) {
                revert UnsupportedCall(i);
            }
            (bool ok, bytes memory returndata) =
                calls[i].target.call{ value: calls[i].value }(calls[i].data);
            if (!ok) {
                revert CallFailed(i, returndata);
            }
            if (calls[i].data.length >= 4) {
                bytes4 selector = bytes4(calls[i].data[:4]);
                // ERC-20 transfer and the selector shared by ERC-20/ERC-721 transferFrom use the
                // optional-return convention. Standard ERC-721 transferFrom returns no data.
                if (selector == ERC20_TRANSFER || selector == ERC721_TRANSFER_FROM) {
                    if (
                        returndata.length != 0
                            && (returndata.length != 32 || !abi.decode(returndata, (bool)))
                    ) {
                        revert CallFailed(i, returndata);
                    }
                }
            }
        }
    }

    /// @notice Restricts recovery to native-value sweeps and standard ERC-20/721/1155 transfers.
    /// @dev A data-carrying call must target a standard transfer selector and send no value; an
    /// empty-calldata call is a native-value sweep and may invoke recipient code. Other calldata
    /// (including approvals) is rejected.
    function _isAllowedRecoveryCall(Call calldata call_) internal view returns (bool) {
        if (call_.data.length == 0) {
            return call_.value != 0;
        }
        if (call_.value != 0 || call_.data.length < 4 || call_.target.code.length == 0) {
            return false;
        }
        bytes4 selector = bytes4(call_.data[:4]);
        if (selector == ERC20_TRANSFER) {
            return call_.data.length == 4 + 32 * 2;
        }
        if (selector == ERC721_TRANSFER_FROM || selector == ERC721_SAFE_TRANSFER_FROM) {
            (address from, address to, uint256 tokenId) =
                abi.decode(call_.data[4:], (address, address, uint256));
            return from == address(this)
                && keccak256(call_.data)
                    == keccak256(abi.encodeWithSelector(selector, from, to, tokenId));
        }
        if (selector == ERC721_SAFE_TRANSFER_FROM_DATA) {
            (address from, address to, uint256 tokenId, bytes memory data) =
                abi.decode(call_.data[4:], (address, address, uint256, bytes));
            return from == address(this)
                && keccak256(call_.data)
                    == keccak256(abi.encodeWithSelector(selector, from, to, tokenId, data));
        }
        if (selector == ERC1155_SAFE_TRANSFER_FROM) {
            (address from, address to, uint256 id, uint256 amount, bytes memory data) =
                abi.decode(call_.data[4:], (address, address, uint256, uint256, bytes));
            return from == address(this)
                && keccak256(call_.data)
                    == keccak256(abi.encodeWithSelector(selector, from, to, id, amount, data));
        }
        if (selector == ERC1155_SAFE_BATCH_TRANSFER_FROM) {
            (
                address from,
                address to,
                uint256[] memory ids,
                uint256[] memory amounts,
                bytes memory data
            ) = abi.decode(call_.data[4:], (address, address, uint256[], uint256[], bytes));
            return from == address(this) && ids.length == amounts.length
                && keccak256(call_.data)
                    == keccak256(abi.encodeWithSelector(selector, from, to, ids, amounts, data));
        }
        return false;
    }

    function deriveAccountSalt(InitMultisig calldata init) public view returns (bytes32) {
        validateConfig(init);

        bytes memory input =
            abi.encodePacked(ACCOUNT_DOMAIN, init.salt, init.threshold, uint8(init.owners.length));
        for (uint256 i = 0; i < init.owners.length; ++i) {
            input = abi.encodePacked(input, init.owners[i].owner, init.owners[i].weight);
        }

        return keccak256(input);
    }

    function recoveryDigest(
        bytes32 boundAccountSalt,
        Call[] calldata calls
    )
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                RECOVERY_DOMAIN,
                block.chainid,
                address(this),
                boundAccountSalt,
                nonce,
                hashCalls(calls)
            )
        );
    }

    function hashCalls(Call[] calldata calls) public pure returns (bytes32) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            callHashes[i] =
                keccak256(abi.encode(calls[i].target, calls[i].value, keccak256(calls[i].data)));
        }
        return keccak256(abi.encodePacked(callHashes));
    }

    function validateConfig(InitMultisig calldata init) internal view {
        if (init.threshold == 0 || init.owners.length == 0 || init.owners.length > MAX_OWNERS) {
            revert InvalidThreshold();
        }

        uint256 totalWeight;
        address previousOwner;
        for (uint256 i = 0; i < init.owners.length; ++i) {
            Owner calldata owner = init.owners[i];
            if (
                owner.owner == address(0) || owner.owner == address(this)
                    || owner.owner <= previousOwner || owner.weight == 0
            ) {
                revert InvalidOwner();
            }
            previousOwner = owner.owner;
            totalWeight += owner.weight;
        }
        if (totalWeight > type(uint8).max || init.threshold > _maxReachableWeight(init.owners)) {
            revert InvalidThreshold();
        }
    }

    function _maxReachableWeight(Owner[] calldata owners) internal pure returns (uint256 total) {
        uint8[MAX_SIGNATURES] memory highest;
        for (uint256 i = 0; i < owners.length; ++i) {
            uint8 weight = owners[i].weight;
            for (uint256 j = 0; j < MAX_SIGNATURES; ++j) {
                if (weight > highest[j]) {
                    for (uint256 k = MAX_SIGNATURES - 1; k > j; --k) {
                        highest[k] = highest[k - 1];
                    }
                    highest[j] = weight;
                    break;
                }
            }
        }
        for (uint256 i = 0; i < MAX_SIGNATURES; ++i) {
            total += highest[i];
        }
    }

    function verifyOwnerSignatures(
        InitMultisig calldata init,
        bytes32 digest,
        bytes[] calldata signatures
    )
        internal
        pure
    {
        if (signatures.length == 0 || signatures.length > MAX_SIGNATURES) {
            revert InvalidSignature();
        }

        uint256 recoveredWeight;
        address previousSigner;
        for (uint256 i = 0; i < signatures.length; ++i) {
            address signer = recoverSigner(digest, signatures[i]);
            if (signer <= previousSigner) {
                revert InvalidSignature();
            }
            previousSigner = signer;

            uint256 ownerIndex = findOwner(init.owners, signer);
            recoveredWeight += init.owners[ownerIndex].weight;
            if (recoveredWeight >= init.threshold && i + 1 != signatures.length) {
                revert InvalidSignature();
            }
        }

        if (recoveredWeight < init.threshold) {
            revert InvalidThreshold();
        }
    }

    function findOwner(Owner[] calldata owners, address signer) internal pure returns (uint256) {
        for (uint256 i = 0; i < owners.length; ++i) {
            if (owners[i].owner == signer) {
                return i;
            }
        }
        revert InvalidOwner();
    }

    function recoverSigner(
        bytes32 digest,
        bytes calldata signature
    )
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) {
            revert InvalidSignature();
        }

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
        if ((v != 27 && v != 28) || uint256(s) > SECP256K1_HALF_ORDER) {
            revert InvalidSignature();
        }
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) {
            revert InvalidSignature();
        }
        return signer;
    }

}
