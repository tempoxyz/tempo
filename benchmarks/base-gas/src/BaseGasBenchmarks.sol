// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract BenchmarkERC20 {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Approval(address indexed owner, address indexed spender, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "ALLOWANCE");
            allowance[from][msg.sender] = allowed - amount;
            emit Approval(from, msg.sender, allowed - amount);
        }
        _transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnFrom(address from, uint256 amount) external {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "ALLOWANCE");
            allowance[from][msg.sender] = allowed - amount;
            emit Approval(from, msg.sender, allowed - amount);
        }
        _burn(from, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "ZERO_TO");
        uint256 balance = balanceOf[from];
        require(balance >= amount, "BALANCE");
        unchecked {
            balanceOf[from] = balance - amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        uint256 balance = balanceOf[from];
        require(balance >= amount, "BALANCE");
        unchecked {
            balanceOf[from] = balance - amount;
            totalSupply -= amount;
        }
        emit Transfer(from, address(0), amount);
    }
}

contract MockAuthRegistry {
    mapping(uint64 => mapping(address => bool)) public authorized;

    function setAuthorized(uint64 policyId, address user, bool allowed) external {
        authorized[policyId][user] = allowed;
    }

    function isAuthorized(uint64 policyId, address user) external view returns (bool) {
        return authorized[policyId][user];
    }
}

contract BaseTokenAuthority {
    BenchmarkERC20 public immutable reserveLedger;

    constructor(BenchmarkERC20 reserveLedger_) {
        reserveLedger = reserveLedger_;
    }

    function unwrap(address token, uint256 amount) external {
        require(BenchmarkERC20(token).transferFrom(msg.sender, address(this), amount), "PULL_IN");
        BenchmarkERC20(token).burn(amount);
        reserveLedger.mint(msg.sender, amount);
    }

    function wrap(address token, address recipient, uint256 amount) external {
        require(reserveLedger.transferFrom(msg.sender, address(this), amount), "PULL_RESERVE");
        reserveLedger.burn(amount);
        BenchmarkERC20(token).mint(recipient, amount);
    }
}

contract BaseReserveLedgerWrappedHandler {
    BaseTokenAuthority public immutable tokenAuthority;
    BenchmarkERC20 public immutable reserveLedger;
    address public directSwapContract;

    mapping(address => bool) public stablecoinRegistered;

    event Deposited(
        address indexed sender, address indexed token, address indexed destination, uint256 amount
    );
    event Withdrawn(
        address indexed sender, address indexed token, address indexed source, uint256 amount
    );

    constructor(BaseTokenAuthority tokenAuthority_, BenchmarkERC20 reserveLedger_) {
        tokenAuthority = tokenAuthority_;
        reserveLedger = reserveLedger_;
    }

    function setDirectSwapContract(address directSwapContract_) external {
        require(directSwapContract_ != address(0), "DIRECT");
        directSwapContract = directSwapContract_;
    }

    function registerStablecoin(address stablecoin, bool registered) external {
        stablecoinRegistered[stablecoin] = registered;
    }

    function deposit(address token, uint256 amount) external {
        require(msg.sender == directSwapContract, "CALLER");
        require(stablecoinRegistered[token], "TOKEN");

        require(BenchmarkERC20(token).transferFrom(msg.sender, address(this), amount), "IN");
        require(BenchmarkERC20(token).approve(address(tokenAuthority), amount), "APPROVE_IN");
        tokenAuthority.unwrap(token, amount);
        require(reserveLedger.transfer(msg.sender, amount), "RESERVE_OUT");

        emit Deposited(msg.sender, token, msg.sender, amount);
    }

    function withdraw(address token, uint256 amount) external {
        require(msg.sender == directSwapContract, "CALLER");
        require(stablecoinRegistered[token], "TOKEN");

        require(reserveLedger.transferFrom(msg.sender, address(this), amount), "RESERVE_IN");
        require(reserveLedger.approve(address(tokenAuthority), amount), "APPROVE_RESERVE");
        tokenAuthority.wrap(token, msg.sender, amount);

        emit Withdrawn(msg.sender, token, msg.sender, amount);
    }
}

contract BaseDirectSwapRouter {
    uint256 private constant BPS_DENOMINATOR = 10_000;
    bytes32 private constant TRANSIENT_MINT_LIMIT_SLOT =
        0xd21a8481dbdfecff978f311939ec8b63cac43b11c4553304925477428350ed00;

    MockAuthRegistry public immutable authRegistry;
    BaseReserveLedgerWrappedHandler public immutable stablecoinHandler;
    BenchmarkERC20 public immutable reserveLedger;
    uint64 public immutable allowedCallerPolicyId;
    uint96 public immutable transactionLimit;
    uint256 public immutable feeBps;
    address public immutable feeRecipient;

    event SwapExactOut(
        address indexed swapper,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );

    constructor(
        MockAuthRegistry authRegistry_,
        BaseReserveLedgerWrappedHandler stablecoinHandler_,
        BenchmarkERC20 reserveLedger_,
        uint64 allowedCallerPolicyId_,
        uint96 transactionLimit_,
        uint256 feeBps_,
        address feeRecipient_
    ) {
        authRegistry = authRegistry_;
        stablecoinHandler = stablecoinHandler_;
        reserveLedger = reserveLedger_;
        allowedCallerPolicyId = allowedCallerPolicyId_;
        transactionLimit = transactionLimit_;
        feeBps = feeBps_;
        require(feeRecipient_ != address(0), "FEE_RECIPIENT");
        feeRecipient = feeRecipient_;
    }

    function swapExactOut(address tokenIn, address tokenOut, uint256 amountOut) external {
        require(tokenIn != tokenOut, "TOKEN");
        require(BenchmarkERC20(tokenOut).decimals() == BenchmarkERC20(tokenIn).decimals(), "DEC");
        require(authRegistry.isAuthorized(allowedCallerPolicyId, msg.sender), "AUTH");
        require(amountOut > 0, "AMOUNT");

        uint256 netBps = BPS_DENOMINATOR - feeBps;
        uint256 amountIn = (amountOut * BPS_DENOMINATOR + netBps - 1) / netBps;
        uint256 feeAmount = amountIn - amountOut;

        _increaseTransientLimit(amountOut);

        require(BenchmarkERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn), "IN");
        require(
            BenchmarkERC20(tokenIn).approve(address(stablecoinHandler), amountOut), "APPROVE_IN"
        );
        stablecoinHandler.deposit(tokenIn, amountOut);

        require(reserveLedger.approve(address(stablecoinHandler), amountOut), "APPROVE_RESERVE");
        stablecoinHandler.withdraw(tokenOut, amountOut);

        require(BenchmarkERC20(tokenOut).transfer(msg.sender, amountOut), "OUT");
        if (feeAmount > 0) {
            require(BenchmarkERC20(tokenIn).transfer(feeRecipient, feeAmount), "FEE");
        }

        emit SwapExactOut(msg.sender, tokenIn, tokenOut, amountIn, amountOut);
    }

    function _increaseTransientLimit(uint256 amount) private {
        require(amount <= transactionLimit, "LIMIT");
        require(amount <= type(uint96).max, "LIMIT_MAX");
        uint256 limit = transactionLimit;
        assembly {
            let used := tload(TRANSIENT_MINT_LIMIT_SLOT)
            let next := add(used, amount)
            if or(iszero(gt(next, used)), gt(next, limit)) { revert(0, 0) }
            tstore(TRANSIENT_MINT_LIMIT_SLOT, next)
        }
    }
}

contract BaseMinimalDirectSwap {
    MockAuthRegistry public immutable authRegistry;
    BaseTokenAuthority public immutable tokenAuthority;
    BenchmarkERC20 public immutable reserveLedger;
    address public owner;

    mapping(bytes32 => bool) private routeSupported;
    mapping(bytes32 => uint64) private routePolicyIds;

    event Swap(
        address indexed swapper,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut,
        address recipient
    );

    constructor(
        MockAuthRegistry authRegistry_,
        BaseTokenAuthority tokenAuthority_,
        BenchmarkERC20 reserveLedger_
    ) {
        authRegistry = authRegistry_;
        tokenAuthority = tokenAuthority_;
        reserveLedger = reserveLedger_;
        owner = msg.sender;
        require(
            reserveLedger.approve(address(tokenAuthority_), type(uint256).max), "APPROVE_RESERVE"
        );
    }

    function configureRoute(address tokenA, address tokenB, uint64 policyId) external {
        require(msg.sender == owner, "OWNER");
        require(tokenA != tokenB, "TOKEN");

        bytes32 forward = _routeKey(tokenA, tokenB);
        bytes32 reverse = _routeKey(tokenB, tokenA);
        routeSupported[forward] = true;
        routeSupported[reverse] = true;
        routePolicyIds[forward] = policyId;
        routePolicyIds[reverse] = policyId;

        require(
            BenchmarkERC20(tokenA).approve(address(tokenAuthority), type(uint256).max), "APPROVE_A"
        );
        require(
            BenchmarkERC20(tokenB).approve(address(tokenAuthority), type(uint256).max), "APPROVE_B"
        );
    }

    function swapExactOut(address tokenIn, address tokenOut, uint256 amountOut) external {
        _checkAllowedCaller(tokenIn, tokenOut);
        require(amountOut > 0, "AMOUNT");
        require(BenchmarkERC20(tokenIn).decimals() == BenchmarkERC20(tokenOut).decimals(), "DEC");

        require(BenchmarkERC20(tokenIn).transferFrom(msg.sender, address(this), amountOut), "IN");
        tokenAuthority.unwrap(tokenIn, amountOut);
        tokenAuthority.wrap(tokenOut, msg.sender, amountOut);

        emit Swap(msg.sender, tokenIn, tokenOut, amountOut, amountOut, msg.sender);
    }

    function _checkAllowedCaller(address tokenIn, address tokenOut) private view {
        bytes32 route = _routeKey(tokenIn, tokenOut);
        require(routeSupported[route], "ROUTE");

        uint64 policyId = routePolicyIds[route];
        if (policyId != 0) {
            require(authRegistry.isAuthorized(policyId, msg.sender), "AUTH");
        }
    }

    function _routeKey(address tokenIn, address tokenOut) private pure returns (bytes32) {
        return keccak256(abi.encode(tokenIn, tokenOut));
    }
}

contract MockMorpho {
    mapping(address => mapping(address => uint256)) public supplied;

    event Supplied(
        address indexed asset, address indexed supplier, address indexed onBehalf, uint256 amount
    );

    function supply(address asset, uint256 amount, address onBehalf) external {
        require(BenchmarkERC20(asset).transferFrom(msg.sender, address(this), amount), "SUPPLY");
        supplied[asset][onBehalf] += amount;
        emit Supplied(asset, msg.sender, onBehalf, amount);
    }
}

contract MockERC4626Vault {
    BenchmarkERC20 public immutable asset;
    MockERC4626Vault public nestedVault;
    MockMorpho public morpho;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);

    constructor(BenchmarkERC20 asset_) {
        asset = asset_;
    }

    function setNestedVault(MockERC4626Vault nestedVault_) external {
        nestedVault = nestedVault_;
    }

    function setMorpho(MockMorpho morpho_) external {
        morpho = morpho_;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        require(asset.transferFrom(msg.sender, address(this), assets), "DEPOSIT");

        shares = assets;
        totalSupply += shares;
        balanceOf[receiver] += shares;

        if (address(nestedVault) != address(0)) {
            require(asset.approve(address(nestedVault), assets), "APPROVE_NESTED");
            uint256 nestedShares = nestedVault.deposit(assets, address(this));
            require(nestedShares == assets, "NESTED_SHARES");
        }

        if (address(morpho) != address(0)) {
            require(asset.approve(address(morpho), assets), "APPROVE_MORPHO");
            morpho.supply(address(asset), assets, address(this));
        }

        emit Deposit(msg.sender, receiver, assets, shares);
    }
}

contract MockLayerZeroMessagingChannel {
    mapping(bytes32 => uint256) public messages;

    event MessageSent(
        address indexed sender, address indexed recipient, bytes32 payloadHash, uint256 amount
    );

    function send(address recipient, bytes32 payloadHash, uint256 amount) external {
        messages[payloadHash] = amount;
        emit MessageSent(msg.sender, recipient, payloadHash, amount);
    }
}

contract MockLayerZeroEndpoint {
    MockLayerZeroMessagingChannel public immutable messagingChannel;

    constructor(MockLayerZeroMessagingChannel messagingChannel_) {
        messagingChannel = messagingChannel_;
    }

    function send(address recipient, bytes32 payloadHash, uint256 amount) external {
        messagingChannel.send(recipient, payloadHash, amount);
    }
}

contract MockLayerZeroSendLib {
    MockLayerZeroEndpoint public immutable endpoint;

    constructor(MockLayerZeroEndpoint endpoint_) {
        endpoint = endpoint_;
    }

    function send(address recipient, bytes32 payloadHash, uint256 amount) external {
        endpoint.send(recipient, payloadHash, amount);
    }
}

contract MockLayerZeroWrapper {
    BenchmarkERC20 public immutable wrappedToken;

    event Wrapped(address indexed token, address indexed recipient, uint256 amount);

    constructor(BenchmarkERC20 wrappedToken_) {
        wrappedToken = wrappedToken_;
    }

    function wrap(address token, address recipient, uint256 amount) external {
        require(BenchmarkERC20(token).transferFrom(msg.sender, address(this), amount), "WRAP");
        wrappedToken.mint(recipient, amount);
        emit Wrapped(token, recipient, amount);
    }
}

contract MockStargate {
    MockLayerZeroSendLib public immutable sendLib;

    event BridgeSent(
        address indexed sender,
        address indexed recipient,
        address bridgeToken,
        uint256 bridgeAmount,
        address wrappedToken,
        uint256 wrappedAmount
    );

    constructor(MockLayerZeroSendLib sendLib_) {
        sendLib = sendLib_;
    }

    function sendBridge(
        address bridgeToken,
        uint256 bridgeAmount,
        address wrappedToken,
        uint256 wrappedAmount,
        address recipient
    ) external {
        require(
            BenchmarkERC20(bridgeToken).transferFrom(msg.sender, address(this), bridgeAmount),
            "BRIDGE"
        );
        require(
            BenchmarkERC20(wrappedToken).transferFrom(msg.sender, address(this), wrappedAmount),
            "WRAPPED"
        );

        bytes32 payloadHash =
            keccak256(abi.encode(msg.sender, recipient, bridgeAmount, wrappedAmount));
        sendLib.send(recipient, payloadHash, bridgeAmount + wrappedAmount);

        emit BridgeSent(
            msg.sender, recipient, bridgeToken, bridgeAmount, wrappedToken, wrappedAmount
        );
    }
}

contract BaseGasFixture {
    uint256 public constant DIRECT_SWAP_AMOUNT = 4_000_000_000;
    uint256 public constant MINIMAL_SWAP_AMOUNT = 4_000_000_000;
    uint256 public constant MORPHO_DEPOSIT_AMOUNT = 1_200_000_000;
    uint256 public constant LAYERZERO_BRIDGE_AMOUNT = 922_346_250;
    uint256 public constant LAYERZERO_WRAP_AMOUNT = 108_287;
    uint64 public constant AUTH_POLICY_ID = 469;

    BenchmarkERC20 public pathusd;
    BenchmarkERC20 public dlusd;
    BenchmarkERC20 public reserveLedger;
    BenchmarkERC20 public bridgeToken;
    BenchmarkERC20 public wrappedToken;

    MockAuthRegistry public authRegistry;
    BaseTokenAuthority public tokenAuthority;
    BaseReserveLedgerWrappedHandler public directSwapHandler;
    BaseDirectSwapRouter public directSwapRouter;
    BaseMinimalDirectSwap public minimalDirectSwap;
    MockMorpho public morpho;
    MockERC4626Vault public primaryVault;
    MockERC4626Vault public nestedVault;
    MockLayerZeroWrapper public layerZeroWrapper;
    MockLayerZeroMessagingChannel public messagingChannel;
    MockLayerZeroEndpoint public endpoint;
    MockLayerZeroSendLib public sendLib;
    MockStargate public stargate;

    constructor(address user) {
        pathusd = new BenchmarkERC20("Path USD", "pathUSD", 6);
        dlusd = new BenchmarkERC20("DL USD", "DLUSD", 6);
        reserveLedger = new BenchmarkERC20("Reserve Ledger", "RL", 6);
        bridgeToken = new BenchmarkERC20("Bridge Token", "BRG", 6);
        wrappedToken = new BenchmarkERC20("Wrapped Bridge Token", "WBRG", 6);

        authRegistry = new MockAuthRegistry();
        tokenAuthority = new BaseTokenAuthority(reserveLedger);
        directSwapHandler = new BaseReserveLedgerWrappedHandler(tokenAuthority, reserveLedger);
        directSwapRouter = new BaseDirectSwapRouter(
            authRegistry,
            directSwapHandler,
            reserveLedger,
            AUTH_POLICY_ID,
            type(uint96).max,
            0,
            user
        );
        directSwapHandler.setDirectSwapContract(address(directSwapRouter));
        directSwapHandler.registerStablecoin(address(pathusd), true);
        directSwapHandler.registerStablecoin(address(dlusd), true);
        minimalDirectSwap = new BaseMinimalDirectSwap(authRegistry, tokenAuthority, reserveLedger);
        minimalDirectSwap.configureRoute(address(pathusd), address(dlusd), AUTH_POLICY_ID);
        authRegistry.setAuthorized(AUTH_POLICY_ID, user, true);

        morpho = new MockMorpho();
        nestedVault = new MockERC4626Vault(pathusd);
        primaryVault = new MockERC4626Vault(pathusd);
        nestedVault.setMorpho(morpho);
        primaryVault.setNestedVault(nestedVault);

        messagingChannel = new MockLayerZeroMessagingChannel();
        endpoint = new MockLayerZeroEndpoint(messagingChannel);
        sendLib = new MockLayerZeroSendLib(endpoint);
        layerZeroWrapper = new MockLayerZeroWrapper(wrappedToken);
        stargate = new MockStargate(sendLib);

        uint256 userPathUsd = 50_000_000_000;
        pathusd.mint(user, userPathUsd);
        bridgeToken.mint(user, LAYERZERO_BRIDGE_AMOUNT);
        reserveLedger.mint(address(0xdead), 1);
        dlusd.mint(address(0xdead), 1);
        wrappedToken.mint(address(0xdead), 1);
    }
}
