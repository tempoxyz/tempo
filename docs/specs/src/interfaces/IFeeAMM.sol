// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IFeeAMM {

    error InsufficientLiquidity();
    error IdenticalAddresses();
    error InvalidToken();
    error InvalidCurrency();

    event Burn(
        address indexed sender,
        address indexed userToken,
        address indexed validatorToken,
        uint256 amountUserToken,
        uint256 amountValidatorToken,
        uint256 liquidity,
        address to
    );
    event FeeSwap(
        address indexed userToken,
        address indexed validatorToken,
        uint256 amountIn,
        uint256 amountOut
    );
    event MintWithValidatorToken(
        address sender,
        address indexed to,
        address indexed userToken,
        address indexed validatorToken,
        uint256 amountValidatorToken,
        uint256 liquidity
    );
    event RebalanceSwap(
        address indexed userToken,
        address indexed validatorToken,
        address indexed swapper,
        uint256 amountIn,
        uint256 amountOut
    );

    // Each pool is directional: userToken -> validatorToken
    // For a pair of tokens A and B, there are two separate pools:
    // - Pool(A, B): for swapping A to B at fixed rate of 0.997 (fee swaps) and B to A at fixed rate of 0.9985 (rebalancing)
    // - Pool(B, A): for swapping B to A at fixed rate of 0.997 (fee swaps) and A to B at fixed rate of 0.9985 (rebalancing)
    struct Pool {
        uint128 reserveUserToken;
        uint128 reserveValidatorToken;
    }

    function M() external view returns (uint256);

    function MIN_LIQUIDITY() external view returns (uint256);

    function N() external view returns (uint256);

    function SCALE() external view returns (uint256);

    function burn(address userToken, address validatorToken, uint256 liquidity, address to)
        external
        returns (uint256 amountUserToken, uint256 amountValidatorToken);

    function getPool(address userToken, address validatorToken) external view returns (Pool memory);

    function getPoolId(address userToken, address validatorToken) external pure returns (bytes32);

    function liquidityBalances(bytes32, address) external view returns (uint256);

    function mint(
        address userToken,
        address validatorToken,
        uint256 amountValidatorToken,
        address to
    ) external returns (uint256 liquidity);

    function pools(bytes32)
        external
        view
        returns (uint128 reserveUserToken, uint128 reserveValidatorToken);

    function rebalanceSwap(address userToken, address validatorToken, uint256 amountOut, address to)
        external
        returns (uint256 amountIn);

    function totalSupply(bytes32) external view returns (uint256);

}
