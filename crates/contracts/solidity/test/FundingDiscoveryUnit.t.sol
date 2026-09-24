// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {
    FundingDiscovery,
    IDiscoverySource as IUnitDiscoverySource
} from "../src/FundingDiscovery.sol";
import {IFundingPolicy} from "../src/IFundingPolicy.sol";
import {IFundingDiscovery} from "../src/IFundingDiscovery.sol";

contract PolicyStore {
    bytes private encoded;

    function set(IFundingPolicy.Policy memory policy) external {
        encoded = abi.encode(policy);
    }

    function getPolicy(uint64 id) external view returns (IFundingPolicy.Policy memory) {
        if (id != 1) revert IFundingPolicy.PolicyNotFound();
        return abi.decode(encoded, (IFundingPolicy.Policy));
    }
}

contract TokenBalance {
    mapping(address => uint256) public balanceOf;

    function set(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }
}

contract UnitSource {
    address immutable account;
    address immutable token;
    uint256 immutable amount;
    uint256 immutable budget;
    bytes private candidates;
    error SourceFailure();

    constructor(
        address account_,
        address token_,
        uint256 amount_,
        uint256 budget_,
        IUnitDiscoverySource.Candidate[] memory candidates_
    ) {
        account = account_;
        token = token_;
        amount = amount_;
        budget = budget_;
        candidates = abi.encode(candidates_);
    }

    function verify(bytes calldata executionData, bytes calldata configData)
        external
        pure
        returns (bool)
    {
        return executionData.length > 0 && keccak256(executionData) != keccak256(hex"ff")
            && keccak256(configData) == keccak256(hex"1122");
    }

    function discover(
        address account_,
        address token_,
        uint256 amount_,
        uint256 budget_,
        bytes calldata data
    ) external view returns (IUnitDiscoverySource.Candidate[] memory) {
        if (keccak256(data) == keccak256(hex"ff")) revert SourceFailure();
        require(account_ == account && token_ == token && amount_ == amount && budget_ == budget);
        require(keccak256(data) == keccak256(hex"1122"));
        return abi.decode(candidates, (IUnitDiscoverySource.Candidate[]));
    }
}

contract WritingSource {
    uint256 public writes;

    function discover(address, address, uint256, uint256, bytes calldata)
        external
        returns (IUnitDiscoverySource.Candidate[] memory)
    {
        ++writes;
        return new IUnitDiscoverySource.Candidate[](0);
    }
}

interface TestVm {
    function etch(address target, bytes calldata code) external;
    function deal(address account, uint256 balance) external;
}

contract FundingDiscoveryTest {
    TestVm constant vm = TestVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant ACCOUNT = address(0xa11ce);
    PolicyStore store;
    TokenBalance token;
    FundingDiscovery helper;
    bytes rulesData;

    function setUp() public {
        vm.etch(0x1120000000000000000000000000000000000002, type(PolicyStore).runtimeCode);
        store = PolicyStore(0x1120000000000000000000000000000000000002);
        token = new TokenBalance();
        helper = new FundingDiscovery();
    }

    function testRulesHashCheckedBeforeBalanceShortcut() public {
        setSources(new IFundingPolicy.Source[](0), 0);
        token.set(ACCOUNT, 50);
        rulesData = abi.encode(IFundingPolicy.Rules(1, new IFundingPolicy.Route[](0)));
        require(bytes4(failure(1, address(token), 0)) == IFundingPolicy.InvalidPolicyData.selector);
        rulesData = "";
        require(bytes4(failure(1, address(token), 0)) == IFundingPolicy.InvalidPolicyData.selector);
    }

    function testNoncanonicalCommittedRulesRejectedBeforeBalanceShortcut() public {
        setSources(new IFundingPolicy.Source[](0), 0);
        bytes memory valid = rulesData;
        for (uint256 i; i < 3; ++i) {
            rulesData = i == 0 ? bytes("") : i == 1 ? bytes(hex"01") : bytes.concat(valid, hex"00");
            store.set(
                IFundingPolicy.Policy(
                    new address[](0),
                    keccak256(abi.encode(keccak256("tempo.funding-policy.rules.v1"), rulesData))
                )
            );
            require(
                bytes4(failure(1, address(token), 0)) == IFundingPolicy.InvalidPolicyData.selector
            );
        }
    }

    function testPolicyFreeDiscoveryWithoutPolicyStore() public {
        token.set(ACCOUNT, 20_000_000);
        address target = source(30_000_000, 30_300_000, 2);
        setSources(single(target, hex"1122"), 100);
        IFundingDiscovery.Discovery memory expected =
            helper.discover(ACCOUNT, address(token), 50_000_000, 1, rulesData);
        vm.etch(address(store), hex"");
        IFundingDiscovery.Discovery memory result =
            helper.discover(ACCOUNT, address(token), 50_000_000, 100, single(target, hex"1122"));
        require(keccak256(abi.encode(result)) == keccak256(abi.encode(expected)));
        require(token.balanceOf(ACCOUNT) == 20_000_000);
    }

    function testPolicyFreeDiscoveryAcceptsUncommittedRules() public {
        setSources(new IFundingPolicy.Source[](0), 0);
        IFundingPolicy.Rules memory rules = abi.decode(rulesData, (IFundingPolicy.Rules));
        rules.maxSlippageBps = 100;
        rules.routes[0].sources = single(source(50, 50, 1), hex"1122");
        rulesData = abi.encode(rules);
        IFundingDiscovery.Discovery memory result = helper.discover(
            ACCOUNT, address(token), 50, rules.maxSlippageBps, rules.routes[0].sources
        );
        require(result.slippageBps == 100 && result.sources.length == 1);
        require(bytes4(failure(1, address(token), 50)) == IFundingPolicy.InvalidPolicyData.selector);
    }

    function testPolicyFreeValidationBeforeBalanceShortcut() public {
        token.set(ACCOUNT, 50);
        IFundingPolicy.Source[] memory sources = single(address(0), hex"1122");
        require(helper.discover(ACCOUNT, address(token), 50, 100, sources).sources.length == 0);
        setSources(sources, 10_001);
        require(bytes4(failure(address(token), 0)) == IFundingDiscovery.InvalidSlippage.selector);
    }

    function testPolicyFreeEmptySources() public view {
        IFundingDiscovery.Discovery memory result =
            helper.discover(ACCOUNT, address(token), 50, 100, new IFundingPolicy.Source[](0));
        require(result.sources.length == 0 && result.slippageBps == 100 && result.amount == 50);
    }

    function testPolicyFreeSourceFailuresAndInvalidCandidates() public {
        IUnitDiscoverySource.Candidate[] memory candidates = new IUnitDiscoverySource.Candidate[](1);
        candidates[0] = IUnitDiscoverySource.Candidate(hex"ff", 50);
        address target = address(new UnitSource(ACCOUNT, address(token), 50, 50, candidates));
        setSources(single(target, hex"1122"), 0);
        require(bytes4(failure(address(token), 50)) == IFundingDiscovery.InvalidCandidate.selector);
        setSources(single(source(50, 50, 0), hex"ff"), 0);
        require(bytes4(failure(address(token), 50)) == UnitSource.SourceFailure.selector);
    }

    function failure(address output, uint256 amount) internal view returns (bytes memory reason) {
        IFundingPolicy.Rules memory rules = abi.decode(rulesData, (IFundingPolicy.Rules));
        (bool ok, bytes memory data) = address(helper)
            .staticcall(
                abi.encodeWithSignature(
                    "discover(address,address,uint256,uint16,(address,bytes)[])",
                    ACCOUNT,
                    output,
                    amount,
                    rules.maxSlippageBps,
                    rules.routes[0].sources
                )
            );
        require(!ok, "expected failure");
        return data;
    }

    function testRejectsValue() public {
        vm.deal(address(this), 1);
        (bool success,) = address(helper).call{value: 1}(
            abi.encodeWithSignature(
                "discover(address,address,uint256,uint64,bytes)",
                ACCOUNT,
                address(token),
                50,
                uint64(1),
                rulesData
            )
        );
        require(!success);
    }

    function setSources(IFundingPolicy.Source[] memory sources, uint16 slippage) internal {
        IFundingPolicy.Route[] memory routes = new IFundingPolicy.Route[](1);
        routes[0] = IFundingPolicy.Route(address(token), sources);
        address[] memory admins = new address[](1);
        admins[0] = address(this);
        rulesData = abi.encode(IFundingPolicy.Rules(slippage, routes));
        store.set(
            IFundingPolicy.Policy(
                admins, keccak256(abi.encode(keccak256("tempo.funding-policy.rules.v1"), rulesData))
            )
        );
    }

    function source(uint256 amount, uint256 budget, uint256 count) internal returns (address) {
        IUnitDiscoverySource.Candidate[] memory candidates =
            new IUnitDiscoverySource.Candidate[](count);
        for (uint256 i; i < count; ++i) {
            candidates[i] = IUnitDiscoverySource.Candidate(abi.encode(i), amount);
        }
        return address(new UnitSource(ACCOUNT, address(token), amount, budget, candidates));
    }

    function single(address target, bytes memory data)
        internal
        pure
        returns (IFundingPolicy.Source[] memory sources)
    {
        sources = new IFundingPolicy.Source[](1);
        sources[0] = IFundingPolicy.Source(target, data);
    }

    function failure(uint64 id, address output, uint256 amount)
        internal
        view
        returns (bytes memory reason)
    {
        (bool ok, bytes memory data) = address(helper)
            .staticcall(
                abi.encodeWithSignature(
                    "discover(address,address,uint256,uint64,bytes)",
                    ACCOUNT,
                    output,
                    amount,
                    id,
                    rulesData
                )
            );
        require(!ok, "expected failure");
        return data;
    }

    function testIndependentCandidatesPreserveOrderAndShortfall() public {
        token.set(ACCOUNT, 20_000_000);
        address first = source(30_000_000, 30_300_000, 2);
        address second = source(30_000_000, 30_300_000, 1);
        IFundingPolicy.Source[] memory sources = new IFundingPolicy.Source[](2);
        sources[0] = IFundingPolicy.Source(first, hex"1122");
        sources[1] = IFundingPolicy.Source(second, hex"1122");
        setSources(sources, 100);
        IFundingDiscovery.Discovery memory result =
            helper.discover(ACCOUNT, address(token), 50_000_000, 1, rulesData);
        require(
            result.token == address(token) && result.amount == 50_000_000
                && result.slippageBps == 100
        );
        require(result.sources.length == 3);
        require(
            result.sources[0].target == first && result.sources[1].target == first
                && result.sources[2].target == second
        );
        require(abi.decode(result.sources[0].data, (uint256)) == 0);
        require(abi.decode(result.sources[1].data, (uint256)) == 1);
        require(abi.decode(result.sources[2].data, (uint256)) == 0);
        for (uint256 i; i < 3; ++i) {
            require(result.sources[i].availableAmount == 30_000_000);
        }
        require(token.balanceOf(ACCOUNT) == 20_000_000);
    }

    function testBalanceShortcutStillValidatesPolicyAndToken() public {
        setSources(single(address(0), hex"1122"), 100);
        require(bytes4(failure(2, address(token), 0)) == IFundingPolicy.PolicyNotFound.selector);
        require(bytes4(failure(1, address(0xdead), 0)) == IFundingPolicy.TokenNotAllowed.selector);
        token.set(ACCOUNT, 50);
        require(helper.discover(ACCOUNT, address(token), 50, 1, rulesData).sources.length == 0);
        require(helper.discover(ACCOUNT, address(token), 0, 1, rulesData).sources.length == 0);
    }

    function testEmptyRoutesRejectAndEmptySourcesReturnNoCandidates() public {
        rulesData = abi.encode(IFundingPolicy.Rules(0, new IFundingPolicy.Route[](0)));
        store.set(
            IFundingPolicy.Policy(
                new address[](0),
                keccak256(abi.encode(keccak256("tempo.funding-policy.rules.v1"), rulesData))
            )
        );
        require(bytes4(failure(1, address(token), 0)) == IFundingPolicy.TokenNotAllowed.selector);
        setSources(new IFundingPolicy.Source[](0), 0);
        require(helper.discover(ACCOUNT, address(token), 50, 1, rulesData).sources.length == 0);
    }

    function testSourceFailuresPropagate() public {
        setSources(single(source(50, 50, 0), hex"ff"), 0);
        require(bytes4(failure(1, address(token), 50)) == UnitSource.SourceFailure.selector);
    }

    function testRejectsInvalidCandidates() public {
        for (uint256 mode; mode < 4; ++mode) {
            IUnitDiscoverySource.Candidate[] memory candidates =
                new IUnitDiscoverySource.Candidate[](1);
            candidates[0] = IUnitDiscoverySource.Candidate(
                mode == 0 ? bytes("") : mode == 3 ? bytes(hex"ff") : bytes(hex"01"),
                mode == 1 ? 0 : mode == 2 ? 51 : 50
            );
            address target = address(new UnitSource(ACCOUNT, address(token), 50, 50, candidates));
            setSources(single(target, hex"1122"), 0);
            require(
                keccak256(failure(1, address(token), 50))
                    == keccak256(
                        abi.encodeWithSelector(IFundingDiscovery.InvalidCandidate.selector, target)
                    )
            );
        }
    }

    function testSourcesCannotWriteEvenWhenHelperIsCalledNormally() public {
        WritingSource writer = new WritingSource();
        setSources(single(address(writer), hex"1122"), 0);
        // CALL the helper: its view interface must still STATICCALL the source.
        (bool ok,) = address(helper)
            .call(
                abi.encodeWithSignature(
                    "discover(address,address,uint256,uint64,bytes)",
                    ACCOUNT,
                    address(token),
                    50,
                    uint64(1),
                    rulesData
                )
            );
        require(!ok && writer.writes() == 0);
    }

    function testFuzzBudgetRoundsDown(uint128 amount, uint16 bps) public {
        bps = uint16(uint256(bps) % 10_001);
        uint256 budget = uint256(amount) * (10_000 + uint256(bps)) / 10_000;
        setSources(single(source(amount, budget, 0), hex"1122"), bps);
        helper.discover(ACCOUNT, address(token), amount, 1, rulesData);
    }

    function testMaximumAmountAndOverflow() public {
        uint256 maximum = type(uint256).max;
        setSources(single(source(maximum, maximum, 0), hex"1122"), 0);
        helper.discover(ACCOUNT, address(token), maximum, 1, rulesData);
        setSources(single(source(maximum, maximum, 0), hex"1122"), 1);
        require(bytes4(failure(1, address(token), maximum)) == bytes4(0x4e487b71));
    }

    function testInvalidSlippageReverts() public {
        setSources(new IFundingPolicy.Source[](0), 10_001);
        require(bytes4(failure(1, address(token), 0)) == IFundingDiscovery.InvalidSlippage.selector);
    }
}
