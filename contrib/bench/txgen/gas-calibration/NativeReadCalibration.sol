// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface ITokenRead { function balanceOf(address account) external view returns (uint256); }
interface IFactoryRead { function isTIP20(address token) external view returns (bool); }
interface IPolicyRead { function policyIdCounter() external view returns (uint64); }
interface IFeeRead { function userTokens(address account) external view returns (address); }
interface IDexRead { function balanceOf(address account, address token) external view returns (uint128); }
interface INonceRead { function getNonce(address account, uint256 key) external view returns (uint64); }
interface IValidatorRead { function validatorCount() external view returns (uint64); }
interface IKeyRead { function isAdminKey(address account, address key) external view returns (bool); }
interface IAddressRead { function resolveRecipient(address recipient) external view returns (address); }
interface IChannelRead { function storageCredits(address payer) external view returns (uint64); }
interface IGuardRead { function balanceOf(bytes calldata receipt) external view returns (uint256); }
interface ICreditRead { function balanceOf(address account) external view returns (uint64); }
interface ICommitteeRead { function getCommitteeMembers() external view returns (uint64, bytes32[] memory); }
interface IZoneRead { function owner() external view returns (address); }

/// Public-read coverage, not a substitute for native mutation/lifecycle pricing.
/// Every workload method makes one typed STATICCALL; native ABI decode failures revert.
contract NativeReadCalibration {
    address private constant TOKEN = address(bytes20(hex"20c0000000000000000000000000000000000000"));
    address private constant FACTORY = address(bytes20(hex"20fc000000000000000000000000000000000000"));

    constructor() {
        require(IFactoryRead(FACTORY).isTIP20(TOKEN), "factory must recognize pathUSD");
        require(ITokenRead(TOKEN).balanceOf(msg.sender) > 0, "deployer must be funded");
    }

    function tokenBalance() external view returns (uint256) {
        return ITokenRead(TOKEN).balanceOf(msg.sender);
    }

    function factoryTokenCheck() external view returns (bool) {
        return IFactoryRead(FACTORY).isTIP20(TOKEN);
    }

    function policyCounter() external view returns (uint64) {
        return IPolicyRead(address(bytes20(hex"403c000000000000000000000000000000000000"))).policyIdCounter();
    }

    function feeToken() external view returns (address) {
        return IFeeRead(address(bytes20(hex"feec000000000000000000000000000000000000"))).userTokens(msg.sender);
    }

    function dexBalance() external view returns (uint128) {
        return IDexRead(address(bytes20(hex"dec0000000000000000000000000000000000000"))).balanceOf(msg.sender, TOKEN);
    }

    function nonceValue() external view returns (uint64) {
        return INonceRead(address(bytes20(hex"4e4f4e4345000000000000000000000000000000"))).getNonce(msg.sender, 1);
    }

    function legacyValidatorCount() external view returns (uint64) {
        return IValidatorRead(address(bytes20(hex"cccccccc00000000000000000000000000000000"))).validatorCount();
    }

    function validatorCount() external view returns (uint64) {
        return IValidatorRead(address(bytes20(hex"cccccccc00000000000000000000000000000001"))).validatorCount();
    }

    function adminKeyCheck() external view returns (bool) {
        return IKeyRead(address(bytes20(hex"aaaaaaaa00000000000000000000000000000000"))).isAdminKey(msg.sender, msg.sender);
    }

    function resolveRecipient() external view returns (address) {
        return IAddressRead(address(bytes20(hex"fdc0000000000000000000000000000000000000"))).resolveRecipient(msg.sender);
    }

    function channelCredits() external view returns (uint64) {
        return IChannelRead(address(bytes20(hex"4d50500000000000000000000000000000000000"))).storageCredits(msg.sender);
    }

    /// Query a structurally valid, unknown receipt; no claim or fund movement.
    function guardBalance() external view returns (uint256) {
        bytes memory receipt = abi.encode(uint8(1), TOKEN, address(0), msg.sender,
            msg.sender, uint64(1), uint64(99), uint8(2), uint8(0), bytes32(0));
        return IGuardRead(address(bytes20(hex"b10c000000000000000000000000000000000000"))).balanceOf(receipt);
    }

    function storageCredits() external view returns (uint64) {
        return ICreditRead(address(bytes20(hex"1060000000000000000000000000000000000000"))).balanceOf(msg.sender);
    }

    function committee() external view returns (uint64 epoch, bytes32[] memory publicKeys) {
        return ICommitteeRead(address(bytes20(hex"c077e00000000000000000000000000000000000"))).getCommitteeMembers();
    }

    function zoneOwner() external view returns (address) {
        return IZoneRead(address(bytes20(hex"5af2000000000000000000000000000000000000"))).owner();
    }
}
