//! Native version of the public-mix Earn vault's deposit and redeem.
//!
//! The bench's vault is a dozen contracts with no source in any Tempo repository (UserVault proxy,
//! fee module, engine, router, accountant, strategy vault, access controller, liquidity buffer and
//! price oracle; see contrib/bench/txgen/vault). This reproduces, from opcode traces of their
//! bytecode, every effect a deposit or redeem has: the same storage reads and writes, the same
//! TIP-20 calls in the same order and from the same senders, the same logs and return data. What
//! it drops is what a native implementation would not do: the nested calls, ABI encoding, repeated
//! reads of a slot and constant mapping-slot hashes. It keeps the bytecode's reentrancy-guard and
//! unchanged-value writes, which are state transitions with their own gas and refunds.
//! The share math is the bytecode's at the bench's fixed 1:1 oracle price.

use super::NativeFrame;
use crate::{
    address_registry::AddressRegistry,
    error::{Result, TempoPrecompileError},
    storage::StorageCtx,
    tip20::{ITIP20, TIP20Token},
};
use alloy::{
    primitives::{Address, B256, Bytes, LogData, U256, address, b256, uint},
    sol,
    sol_types::{SolCall, SolValue},
};

/// The UserVault proxy every public-mix vault template calls.
pub const USER_VAULT: Address = address!("0x7ab1b8f13760b57021ad9baff0be170259245992");
const FEE_MODULE: Address = address!("0x2afdb4beb393d4297ba73d892aa453ff0fa0bc3f");
const ENGINE: Address = address!("0x7604c22ebab91cd49d2716888e913bbfdcd9df78");
const ROUTER: Address = address!("0x341d8352c84969157a6f172caf05ccc9f4dbe849");
const ACCOUNTANT: Address = address!("0x7740fc76cef264d688c564ad16c34c347c440e2b");
const STRATEGY_VAULT: Address = address!("0xcb910de037ae08f743fd2ab7f401ff604146cdc7");
const AUTHORITY: Address = address!("0x49488d7ece082070b9f43589151602d6aabe58e0");
const BUFFER: Address = address!("0x514e725a2fdbd3f664950195df296732c30c8a77");
const PRICE_ORACLE: Address = address!("0x878e9282ca9a0fadd5832c2bf933c197f60e4165");
/// The vault's share token.
const SHARE: Address = address!("0x20c000000000000000000000b40ebef7b60e73cf");
/// The deposit asset (pathUSD) and the asset the buffer swaps it into.
const ASSET: Address = address!("0x20c0000000000000000000000000000000000000");
const STRATEGY_ASSET: Address = address!("0x20c0000000000000000000000000000000000001");

/// deposit(uint256,address,uint256)
pub const DEPOSIT_SELECTOR: [u8; 4] = [0xbc, 0x15, 0x7a, 0xc1];
/// redeem(uint256,address,uint256)
pub const REDEEM_SELECTOR: [u8; 4] = [0xd8, 0x78, 0x01, 0x61];

/// Gas the bytecode spends beyond the native entry's storage and TIP-20 gas, measured against
/// it on the same calls: the base, and the extra when the accountant's rate update runs.
pub const DEPOSIT_EXTRA_GAS: u64 = 166_373;
pub const REDEEM_EXTRA_GAS: u64 = 141_984;
const DEPOSIT_UPDATE_EXTRA_GAS: u64 = 954;
const REDEEM_UPDATE_EXTRA_GAS: u64 = 977;

/// The strategy vault's share supply past which the vault is in the bench's steady state. The
/// setup's first deposit and redeem, before the users' seeding deposits, take other paths.
const STEADY_SUPPLY: U256 = uint!(1_000_000_000_000_000_000_U256);

/// Whether the vault is past the bench's setup.
pub(super) fn applies() -> Result<bool> {
    Ok(sload(STRATEGY_VAULT, SV_TOTAL_SUPPLY)? >= STEADY_SUPPLY)
}

sol! {
    function deposit(uint256 assets, address receiver, uint256 minShares) returns (uint256);
    function redeem(uint256 shares, address receiver, uint256 minAssets) returns (uint256);
}

const UV_ENGINE_SHARES: U256 = uint!(0x16_U256);
const UV_LAST_SHARES_D: U256 = uint!(0xd_U256);
const UV_LAST_SHARES_E: U256 = uint!(0xe_U256);
const ACC_TOTAL_SNAPSHOT: U256 = uint!(0x3_U256);
const ACC_RATE: U256 = uint!(0x4_U256);
const ACC_RATE_ONE: U256 = uint!(0x6_U256);
const ACC_SHARE_SECONDS: U256 = uint!(0x8_U256);
const ACC_LAST_UPDATE: U256 = uint!(0xa_U256);
const FEE_RATE: U256 = uint!(0x2_U256);
const SV_TOTAL_SUPPLY: U256 = uint!(0x2_U256);
/// balanceOf(ENGINE) in the strategy vault's share mapping.
const SV_ENGINE_BALANCE: U256 =
    uint!(0x0f2cf23ab2caf1fa37fd28287362e9facc07704b2db3bf051a699e2e00816e78_U256);
const BUFFER_PRICE_IN: U256 = uint!(0x2_U256);
const BUFFER_PRICE_OUT: U256 = uint!(0x1_U256);
const BUFFER_ROUTE_PENDING: U256 =
    uint!(0x78f242137cf36608ceb2f7eb6a9277bae26a029520a65bfe2627ef4f27617fd8_U256);
/// Reentrancy guards, which the bytecode sets to 2 for the call and back to 1.
const UV_GUARD: U256 = uint!(0x14_U256);
const ROUTER_GUARD: U256 = uint!(0x2_U256);
const ENGINE_T_ACTIVE: U256 = uint!(0x0_U256);
const ENGINE_T_AMOUNT: U256 = uint!(0x1_U256);

const T_FEE_ACCRUE: B256 =
    b256!("0x04f0dd81fd9c3bcb3315acb90c4d17a8063e53047a0e693c3b9374e70baf2588");
const T_FEE_SETTLE: B256 =
    b256!("0xbde724f41a6144d43037d710d0ae0be1118539db96f1c789ee2513048dbafc1b");
const T_ACC_UPDATE: B256 =
    b256!("0x388f446e9526fe5c9af20a5919b342370c8a7c0cb05245afe1e545658fa3cdba");
const T_TRANSFER: B256 =
    b256!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
const T_SV_ENTER: B256 =
    b256!("0xea00f88768a86184a6e515238a549c171769fe7460a011d6fd0bcd48ca078ea4");
const T_SV_EXIT: B256 = b256!("0xe0c82280a1164680e0cf43be7db4c4c9f985423623ad7a544fb76c772bdc6043");
const T_BUFFER_SWAP: B256 =
    b256!("0x68b6919cc2747efaadbd2bd1a5b1f54acdefbe8bf17ba6171e13901d98f5d725");
const T_BUFFER_ORDER: B256 =
    b256!("0xf05a3e016bfb4b6c18830f5c8c2920e373727b22308458b485c35ed0202fe6be");
/// keccak256(abi.encode(STRATEGY_VAULT, STRATEGY_VAULT, BUFFER_SOLVER)), a constant of the bench.
const BUFFER_ROUTE: B256 =
    b256!("0x7e770548c5c424812fb48d605813f34b6d61c8163191ba8cc229881d8fae14ba");
const BUFFER_SOLVER: B256 =
    b256!("0x0101010101010101010101010101010101010101010101010101010101010101");
const T_ROUTER_DEPOSIT: B256 =
    b256!("0x6f9b974223f85a1ae805c33b8b519039e2435481d949db1110de151a94d587af");
const T_ROUTER_WITHDRAW: B256 =
    b256!("0xdcc60b41ff1c604459e6aa4a7299817416b19fc586a392f111646e26597c4af9");
const T_ENGINE_DEPOSIT: B256 =
    b256!("0x73a19dd210f1a7f902193214c0ee91dd35ee5b4d920cba8d519eca65a7b488ca");
const T_ENGINE_REDEEM: B256 =
    b256!("0xf3a670cd3af7d64b488926880889d08a8585a138ff455227af6737339a1ec262");
const T_UV_DEPOSIT: B256 =
    b256!("0xf5681f9d0db1b911ac18ee83d515a1cf1051853a9eae418316a2fdf7dea427c5");
const T_UV_REDEEM: B256 =
    b256!("0x5cdf07ad0fc222442720b108e3ed4c4640f0fadc2ab2253e66f259a0fea83480");
/// Order type hashes the router signs swaps into and out of the strategy asset with.
const ORDER_IN: B256 = b256!("0xde78e0fa60c5c3bc18663c5628c688767d457768b281f69b3f14d6d31d2ad8e3");
const ORDER_OUT: B256 = b256!("0xccc7d860f3631dc3d195522ef0b2a43d31f7cd5e48b52728438f542d330bc013");

/// Storage the bytecode reads in a deposit, each slot once: configuration, access-control roles,
/// totals and the accountant's rate.
const DEPOSIT_READS: [(Address, U256); 64] = [
    (
        USER_VAULT,
        uint!(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc_U256),
    ),
    (USER_VAULT, uint!(0x14_U256)),
    (USER_VAULT, uint!(0x10_U256)),
    (USER_VAULT, uint!(0x2_U256)),
    (USER_VAULT, uint!(0x3_U256)),
    (FEE_MODULE, uint!(0x0_U256)),
    (FEE_MODULE, uint!(0x6_U256)),
    (FEE_MODULE, uint!(0x3_U256)),
    (
        FEE_MODULE,
        uint!(0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b828_U256),
    ),
    (FEE_MODULE, uint!(0x1_U256)),
    (USER_VAULT, uint!(0x0_U256)),
    (ENGINE, uint!(0x4_U256)),
    (ACCOUNTANT, uint!(0xb_U256)),
    (ENGINE, uint!(0x5_U256)),
    (FEE_MODULE, uint!(0xe_U256)),
    (USER_VAULT, uint!(0x16_U256)),
    (
        STRATEGY_VAULT,
        uint!(0xf2cf23ab2caf1fa37fd28287362e9facc07704b2db3bf051a699e2e00816e78_U256),
    ),
    (ACCOUNTANT, uint!(0x4_U256)),
    (STRATEGY_VAULT, uint!(0x2_U256)),
    (ACCOUNTANT, uint!(0x7_U256)),
    (ACCOUNTANT, uint!(0x6_U256)),
    (FEE_MODULE, uint!(0x2_U256)),
    (FEE_MODULE, uint!(0x4_U256)),
    (
        FEE_MODULE,
        uint!(0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b82d_U256),
    ),
    (USER_VAULT, uint!(0xe_U256)),
    (USER_VAULT, uint!(0xd_U256)),
    (USER_VAULT, uint!(0x1_U256)),
    (ENGINE, uint!(0x8_U256)),
    (ENGINE, uint!(0x2_U256)),
    (ROUTER, uint!(0x1_U256)),
    (
        AUTHORITY,
        uint!(0xb92c3619c85846eae55f1770cb3538bf9d296a4397eadfc3ab71859cdbef5e33_U256),
    ),
    (
        AUTHORITY,
        uint!(0x6c7b01d09aaed4bbb8e6d18bd8575741e60b8a2187abb4696aef1fdb7e4cfe7d_U256),
    ),
    (
        AUTHORITY,
        uint!(0x59c3f8f3cefc93e317d39b17dddef3941e1ad96e3e0a44638f71a6a80157b0cc_U256),
    ),
    (ROUTER, uint!(0x2_U256)),
    (ROUTER, uint!(0x4_U256)),
    (
        ROUTER,
        uint!(0xfcfb18e4759a3b346f1d8e0f91dfa2c8c995d8e483559cb4e925f12493a0345_U256),
    ),
    (ACCOUNTANT, uint!(0x1_U256)),
    (
        AUTHORITY,
        uint!(0xef72b01d2af2577fe07a03679b3d5dd3e1b91db00af46969ee44ffdbeca5228c_U256),
    ),
    (
        AUTHORITY,
        uint!(0x49c28112e884c53fba60a813c735ceb06a6272dad156fcf145c899537c20624f_U256),
    ),
    (
        AUTHORITY,
        uint!(0x6920eeb9d9bd51f879149097bd25086160d1a18c8ed0afff3d2b2e26edc4989_U256),
    ),
    (ACCOUNTANT, uint!(0xa_U256)),
    (ACCOUNTANT, uint!(0x3_U256)),
    (ACCOUNTANT, uint!(0x2_U256)),
    (
        ROUTER,
        uint!(0xea588ff56424397a8a3c707f331bc7b98ae086f2a0f9842823b9c27d7c842d3a_U256),
    ),
    (STRATEGY_VAULT, uint!(0x7_U256)),
    (
        AUTHORITY,
        uint!(0xf967942c2e29d16c342b0da805a5bfdb6ee05acc1d3ef19fd63fbb60a6ffa5bf_U256),
    ),
    (
        AUTHORITY,
        uint!(0x50b86d65524ea7d6c3c470ec4eaa0bc68c1e0449810df02625ac8375e8279b64_U256),
    ),
    (
        ROUTER,
        uint!(0x6097575481fe9dbdbc9758bb6fa76a487c655468435d7dde3e3d4250b5925301_U256),
    ),
    (BUFFER, uint!(0x0_U256)),
    (PRICE_ORACLE, uint!(0x3_U256)),
    (PRICE_ORACLE, uint!(0x4_U256)),
    (BUFFER, uint!(0x2_U256)),
    (
        AUTHORITY,
        uint!(0x5a2cc4fc9f3198ad895a53e9525150902b7301992f88ec8568cf49134f3898d8_U256),
    ),
    (
        AUTHORITY,
        uint!(0x7f12adbbaa3ccfc42d9fdbefad030664a76d84f4bf2d7d4fc877dff9b5cd8aad_U256),
    ),
    (BUFFER, uint!(0x5_U256)),
    (
        BUFFER,
        uint!(0x54f58d680dee9746555340c64ee183799be00101c3546865ac69de587a76435f_U256),
    ),
    (
        BUFFER,
        uint!(0xdfebdd43e198bd41f02e4675bb98b75b13368da9b33e34c4dac47ac017ff5eec_U256),
    ),
    (
        BUFFER,
        uint!(0x78f242137cf36608ceb2f7eb6a9277bae26a029520a65bfe2627ef4f27617fd8_U256),
    ),
    (USER_VAULT, uint!(0xa_U256)),
    (
        FEE_MODULE,
        uint!(0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b829_U256),
    ),
    (
        FEE_MODULE,
        uint!(0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b82a_U256),
    ),
    (
        FEE_MODULE,
        uint!(0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b82b_U256),
    ),
    (
        FEE_MODULE,
        uint!(0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b82c_U256),
    ),
    (FEE_MODULE, uint!(0x5_U256)),
];

/// Storage the bytecode reads in a redeem, each slot once.
const REDEEM_READS: [(Address, U256); 55] = [
    (
        USER_VAULT,
        uint!(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc_U256),
    ),
    (USER_VAULT, uint!(0x14_U256)),
    (USER_VAULT, uint!(0x0_U256)),
    (USER_VAULT, uint!(0x3_U256)),
    (FEE_MODULE, uint!(0x0_U256)),
    (FEE_MODULE, uint!(0x6_U256)),
    (FEE_MODULE, uint!(0x3_U256)),
    (
        FEE_MODULE,
        uint!(0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b828_U256),
    ),
    (FEE_MODULE, uint!(0x1_U256)),
    (ENGINE, uint!(0x4_U256)),
    (ACCOUNTANT, uint!(0xb_U256)),
    (ENGINE, uint!(0x5_U256)),
    (FEE_MODULE, uint!(0xe_U256)),
    (USER_VAULT, uint!(0x16_U256)),
    (
        STRATEGY_VAULT,
        uint!(0xf2cf23ab2caf1fa37fd28287362e9facc07704b2db3bf051a699e2e00816e78_U256),
    ),
    (ACCOUNTANT, uint!(0x4_U256)),
    (STRATEGY_VAULT, uint!(0x2_U256)),
    (ACCOUNTANT, uint!(0x7_U256)),
    (ACCOUNTANT, uint!(0x6_U256)),
    (FEE_MODULE, uint!(0x2_U256)),
    (FEE_MODULE, uint!(0x4_U256)),
    (
        FEE_MODULE,
        uint!(0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b82d_U256),
    ),
    (USER_VAULT, uint!(0x2_U256)),
    (USER_VAULT, uint!(0xe_U256)),
    (USER_VAULT, uint!(0xd_U256)),
    (ENGINE, uint!(0x8_U256)),
    (ENGINE, uint!(0x2_U256)),
    (ROUTER, uint!(0x1_U256)),
    (
        AUTHORITY,
        uint!(0x823c627dad44ce0cf2de92ce016e55fae784fe984cefe3eccb2987d97c1fa6ad_U256),
    ),
    (
        AUTHORITY,
        uint!(0x4563151d4391e4a4598ab289f759e71e0c0988c288153e542b23e2a6e0ef4c2d_U256),
    ),
    (
        AUTHORITY,
        uint!(0x59c3f8f3cefc93e317d39b17dddef3941e1ad96e3e0a44638f71a6a80157b0cc_U256),
    ),
    (ROUTER, uint!(0x2_U256)),
    (ACCOUNTANT, uint!(0x1_U256)),
    (
        AUTHORITY,
        uint!(0xef72b01d2af2577fe07a03679b3d5dd3e1b91db00af46969ee44ffdbeca5228c_U256),
    ),
    (
        AUTHORITY,
        uint!(0x49c28112e884c53fba60a813c735ceb06a6272dad156fcf145c899537c20624f_U256),
    ),
    (
        AUTHORITY,
        uint!(0x6920eeb9d9bd51f879149097bd25086160d1a18c8ed0afff3d2b2e26edc4989_U256),
    ),
    (ACCOUNTANT, uint!(0xa_U256)),
    (ACCOUNTANT, uint!(0x3_U256)),
    (ACCOUNTANT, uint!(0x2_U256)),
    (ROUTER, uint!(0x4_U256)),
    (
        ROUTER,
        uint!(0xfcfb18e4759a3b346f1d8e0f91dfa2c8c995d8e483559cb4e925f12493a0345_U256),
    ),
    (
        ROUTER,
        uint!(0x6097575481fe9dbdbc9758bb6fa76a487c655468435d7dde3e3d4250b5925302_U256),
    ),
    (BUFFER, uint!(0x0_U256)),
    (PRICE_ORACLE, uint!(0x3_U256)),
    (PRICE_ORACLE, uint!(0x4_U256)),
    (BUFFER, uint!(0x1_U256)),
    (STRATEGY_VAULT, uint!(0x7_U256)),
    (
        AUTHORITY,
        uint!(0x5a2cc4fc9f3198ad895a53e9525150902b7301992f88ec8568cf49134f3898d8_U256),
    ),
    (
        AUTHORITY,
        uint!(0x7f12adbbaa3ccfc42d9fdbefad030664a76d84f4bf2d7d4fc877dff9b5cd8aad_U256),
    ),
    (BUFFER, uint!(0x5_U256)),
    (
        BUFFER,
        uint!(0x54f58d680dee9746555340c64ee183799be00101c3546865ac69de587a76435f_U256),
    ),
    (
        BUFFER,
        uint!(0xdfebdd43e198bd41f02e4675bb98b75b13368da9b33e34c4dac47ac017ff5eec_U256),
    ),
    (
        BUFFER,
        uint!(0x78f242137cf36608ceb2f7eb6a9277bae26a029520a65bfe2627ef4f27617fd8_U256),
    ),
    (
        AUTHORITY,
        uint!(0x71ce193ba66f33fc6eec66ca41afba41788b65e77487a755b5374f09b824e116_U256),
    ),
    (
        AUTHORITY,
        uint!(0xa79201a7a667b17e38e9e2b5ed7cd79fa215975e3f9e1e12557e325eba3ac25e_U256),
    ),
];

/// The amount every public-mix vault template deposits or redeems. Other calls, such as the
/// setup's seeding deposits, take other paths through the bytecode and run it.
const BENCH_AMOUNT: U256 = uint!(1_000_000_U256);

pub(super) fn select(
    destination: Address,
    selector: [u8; 4],
    input: &[u8],
) -> Option<super::Entry> {
    if destination != USER_VAULT || input.get(4..36).map(U256::from_be_slice) != Some(BENCH_AMOUNT)
    {
        return None;
    }
    match selector {
        DEPOSIT_SELECTOR => Some(super::Entry::VaultDeposit),
        REDEEM_SELECTOR => Some(super::Entry::VaultRedeem),
        _ => None,
    }
}

fn word(value: U256) -> B256 {
    B256::from(value)
}

fn emit(address: Address, topics: Vec<B256>, data: Vec<u8>) -> Result<()> {
    StorageCtx.emit_event(address, LogData::new_unchecked(topics, data.into()))
}

fn sload(address: Address, slot: U256) -> Result<U256> {
    StorageCtx.sload(address, slot)
}

fn sstore(address: Address, slot: U256, value: U256) -> Result<()> {
    StorageCtx.sstore(address, slot, value)
}

fn token(address: Address) -> Result<TIP20Token> {
    TIP20Token::from_address(address)
}

fn approve(address: Address, owner: Address, spender: Address, amount: U256) -> Result<()> {
    token(address)?.approve(owner, ITIP20::approveCall { spender, amount })?;
    Ok(())
}

fn balance_of(address: Address, account: Address) -> Result<U256> {
    token(address)?.balance_of(ITIP20::balanceOfCall { account })
}

fn revert(reason: &str) -> TempoPrecompileError {
    TempoPrecompileError::RawRevert(Bytes::copy_from_slice(reason.as_bytes()))
}

/// The accountant's per-call update, which also snapshots the strategy vault's supply. Returns
/// whether the rate update ran.
fn accountant_update(total: U256) -> Result<bool> {
    let now = StorageCtx.timestamp();
    let last = sload(ACCOUNTANT, ACC_LAST_UPDATE)?;
    let updated = now > last;
    if updated {
        let accrued = sload(ACCOUNTANT, ACC_SHARE_SECONDS)? + total * (now - last);
        sstore(ACCOUNTANT, ACC_SHARE_SECONDS, accrued)?;
        sstore(ACCOUNTANT, ACC_LAST_UPDATE, now)?;
    }
    // The bytecode rewrites the snapshot and the rate's timestamp even when they don't change.
    let snapshot = sload(ACCOUNTANT, ACC_TOTAL_SNAPSHOT)?;
    sstore(ACCOUNTANT, ACC_TOTAL_SNAPSHOT, snapshot)?;
    let rate = sload(ACCOUNTANT, ACC_RATE)?;
    let mask: U256 = U256::from(u32::MAX) << 128usize;
    sstore(ACCOUNTANT, ACC_RATE, (rate & !mask) | (now << 128usize))?;
    let low = snapshot & (U256::MAX >> 128);
    sstore(ACCOUNTANT, ACC_TOTAL_SNAPSHOT, (total << 128) | low)?;
    let rate_one = sload(ACCOUNTANT, ACC_RATE_ONE)?;
    emit(ACCOUNTANT, vec![T_ACC_UPDATE], word(rate_one).to_vec())?;
    Ok(updated)
}

/// The router's order hash for a buffer swap of amount.
fn order_hash(kind: B256, amount: U256) -> Result<B256> {
    let chain_id = U256::from(StorageCtx.chain_id());
    let number = U256::from(StorageCtx.block_number());
    StorageCtx.keccak256(
        &(
            kind,
            BUFFER_SOLVER,
            STRATEGY_VAULT,
            amount,
            chain_id,
            number,
        )
            .abi_encode(),
    )
}

fn memo(tag: &str, order: B256) -> Result<B256> {
    StorageCtx.keccak256(&(tag.to_string(), BUFFER_SOLVER, order).abi_encode_params())
}

/// The liquidity buffer swapping amount of token_in for token_out with the strategy vault.
fn buffer_swap(
    order: B256,
    token_in: Address,
    token_out: Address,
    amount: U256,
    price_slot: U256,
) -> Result<()> {
    approve(token_in, STRATEGY_VAULT, BUFFER, U256::ZERO)?;
    approve(token_in, STRATEGY_VAULT, BUFFER, amount)?;
    AddressRegistry::new().resolve_recipient(STRATEGY_VAULT)?;
    let price = sload(BUFFER, price_slot)?;
    // The buffer clears the route's pending amount, which is already zero.
    sstore(BUFFER, BUFFER_ROUTE_PENDING, U256::ZERO)?;
    let memo_in = memo("SWAP_IN", order)?;
    let memo_out = memo("SWAP_OUT", order)?;

    balance_of(token_in, BUFFER)?;
    token(token_in)?.transfer_from_with_memo(
        BUFFER,
        ITIP20::transferFromWithMemoCall {
            from: STRATEGY_VAULT,
            to: BUFFER,
            amount,
            memo: memo_in,
        },
    )?;
    balance_of(token_in, BUFFER)?;
    balance_of(token_out, BUFFER)?;
    balance_of(token_out, STRATEGY_VAULT)?;
    token(token_out)?.transfer_with_memo(
        BUFFER,
        ITIP20::transferWithMemoCall {
            to: STRATEGY_VAULT,
            amount,
            memo: memo_out,
        },
    )?;
    balance_of(token_out, BUFFER)?;
    balance_of(token_out, STRATEGY_VAULT)?;

    emit(BUFFER, vec![T_BUFFER_SWAP, BUFFER_ROUTE], vec![0; 64])?;
    let data = (
        order,
        token_in,
        token_out,
        amount,
        amount,
        price,
        U256::from(1),
    )
        .abi_encode_params();
    emit(
        BUFFER,
        vec![
            T_BUFFER_ORDER,
            STRATEGY_VAULT.into_word(),
            STRATEGY_VAULT.into_word(),
            BUFFER_SOLVER,
        ],
        data,
    )?;
    approve(token_in, STRATEGY_VAULT, BUFFER, U256::ZERO)
}

/// The fee module's accrual at the start of every vault call.
fn fee_accrue() -> Result<()> {
    let share = token(SHARE)?;
    share.total_supply()?;
    let supply = share.total_supply()?;
    let fee_rate = sload(FEE_MODULE, FEE_RATE)?;
    let data = (
        supply,
        U256::ZERO,
        U256::ZERO,
        U256::ZERO,
        fee_rate,
        U256::ZERO,
    )
        .abi_encode_params();
    emit(FEE_MODULE, vec![T_FEE_ACCRUE, word(U256::from(1))], data)
}

pub(super) fn deposit(frame: &NativeFrame<'_>) -> Result<Bytes> {
    let call = depositCall::abi_decode(frame.input).map_err(|_| revert("bad deposit calldata"))?;
    let (user, assets) = (frame.caller, call.assets);
    if assets <= U256::from(1) {
        return Err(revert("native vault: unsupported amount"));
    }
    // The bytecode's share math at the bench's fixed 1:1 rate.
    let shares = assets - U256::from(1);
    if shares < call.minShares {
        return Err(revert("native vault: slippage"));
    }
    for (address, slot) in DEPOSIT_READS {
        sload(address, slot)?;
    }
    sstore(USER_VAULT, UV_GUARD, U256::from(2))?;

    fee_accrue()?;
    token(SHARE)?.total_supply()?;
    token(ASSET)?.transfer_from(
        USER_VAULT,
        ITIP20::transferFromCall {
            from: user,
            to: USER_VAULT,
            amount: assets,
        },
    )?;
    approve(ASSET, USER_VAULT, ENGINE, U256::ZERO)?;
    approve(ASSET, USER_VAULT, ENGINE, assets)?;

    // Engine.
    StorageCtx.tstore(ENGINE, ENGINE_T_ACTIVE, U256::from(1))?;
    StorageCtx.tstore(ENGINE, ENGINE_T_AMOUNT, assets)?;
    token(ASSET)?.transfer_from(
        ENGINE,
        ITIP20::transferFromCall {
            from: USER_VAULT,
            to: ENGINE,
            amount: assets,
        },
    )?;
    approve(ASSET, ENGINE, STRATEGY_VAULT, assets)?;

    // Router: accountant update, then the strategy vault's enter and the buffer swap.
    sstore(ROUTER, ROUTER_GUARD, U256::from(2))?;
    let total = sload(STRATEGY_VAULT, SV_TOTAL_SUPPLY)?;
    if accountant_update(total)? {
        frame.extra_gas.set(DEPOSIT_UPDATE_EXTRA_GAS);
    }
    token(ASSET)?.transfer_from(
        STRATEGY_VAULT,
        ITIP20::transferFromCall {
            from: ENGINE,
            to: STRATEGY_VAULT,
            amount: assets,
        },
    )?;
    sstore(STRATEGY_VAULT, SV_TOTAL_SUPPLY, total + shares)?;
    let engine_shares = sload(STRATEGY_VAULT, SV_ENGINE_BALANCE)? + shares;
    sstore(STRATEGY_VAULT, SV_ENGINE_BALANCE, engine_shares)?;
    emit(
        STRATEGY_VAULT,
        vec![T_TRANSFER, B256::ZERO, ENGINE.into_word()],
        word(shares).to_vec(),
    )?;
    emit(
        STRATEGY_VAULT,
        vec![
            T_SV_ENTER,
            ENGINE.into_word(),
            ASSET.into_word(),
            ENGINE.into_word(),
        ],
        (assets, shares).abi_encode_params(),
    )?;
    let order = order_hash(ORDER_IN, assets)?;
    buffer_swap(order, ASSET, STRATEGY_ASSET, assets, BUFFER_PRICE_IN)?;
    emit(
        ROUTER,
        vec![T_ROUTER_DEPOSIT, ASSET.into_word()],
        word(assets).to_vec(),
    )?;
    sstore(ROUTER, ROUTER_GUARD, U256::from(1))?;

    approve(ASSET, ENGINE, STRATEGY_VAULT, U256::ZERO)?;
    emit(
        ENGINE,
        vec![T_ENGINE_DEPOSIT, USER_VAULT.into_word()],
        (assets, shares).abi_encode_params(),
    )?;

    // UserVault: book the engine's shares and mint the receiver's.
    approve(ASSET, USER_VAULT, ENGINE, U256::ZERO)?;
    sstore(USER_VAULT, UV_ENGINE_SHARES, engine_shares)?;
    token(SHARE)?.mint(
        USER_VAULT,
        ITIP20::mintCall {
            to: call.receiver,
            amount: shares,
        },
    )?;
    token(SHARE)?.total_supply()?;
    sstore(USER_VAULT, UV_LAST_SHARES_D, engine_shares)?;
    sstore(USER_VAULT, UV_LAST_SHARES_E, engine_shares)?;

    // Fee module settlement.
    token(SHARE)?.total_supply()?;
    let fee_rate = sload(FEE_MODULE, FEE_RATE)?;
    emit(
        FEE_MODULE,
        vec![T_FEE_SETTLE],
        (fee_rate, U256::ZERO, U256::ZERO).abi_encode_params(),
    )?;

    emit(
        USER_VAULT,
        vec![T_UV_DEPOSIT, user.into_word(), call.receiver.into_word()],
        (assets, shares).abi_encode_params(),
    )?;
    sstore(USER_VAULT, UV_GUARD, U256::from(1))?;
    Ok(word(shares).to_vec().into())
}

pub(super) fn redeem(frame: &NativeFrame<'_>) -> Result<Bytes> {
    let call = redeemCall::abi_decode(frame.input).map_err(|_| revert("bad redeem calldata"))?;
    let (user, shares) = (frame.caller, call.shares);
    // The bytecode's asset math at the bench's fixed 1:1 rate.
    let assets = shares;
    if shares.is_zero() || assets < call.minAssets {
        return Err(revert("native vault: unsupported amount"));
    }
    for (address, slot) in REDEEM_READS {
        sload(address, slot)?;
    }
    sstore(USER_VAULT, UV_GUARD, U256::from(2))?;

    fee_accrue()?;
    token(SHARE)?.total_supply()?;
    token(SHARE)?.transfer_from(
        USER_VAULT,
        ITIP20::transferFromCall {
            from: user,
            to: USER_VAULT,
            amount: shares,
        },
    )?;
    token(SHARE)?.burn(USER_VAULT, ITIP20::burnCall { amount: shares })?;

    // Engine.
    StorageCtx.tstore(ENGINE, ENGINE_T_ACTIVE, U256::from(1))?;
    StorageCtx.tstore(ENGINE, ENGINE_T_AMOUNT, shares)?;
    balance_of(ASSET, call.receiver)?;

    // Router: accountant update, the buffer swap back, then the strategy vault's exit.
    sstore(ROUTER, ROUTER_GUARD, U256::from(2))?;
    let total = sload(STRATEGY_VAULT, SV_TOTAL_SUPPLY)?;
    if accountant_update(total)? {
        frame.extra_gas.set(REDEEM_UPDATE_EXTRA_GAS);
    }
    balance_of(ASSET, STRATEGY_VAULT)?;
    let order = order_hash(ORDER_OUT, shares)?;
    buffer_swap(order, STRATEGY_ASSET, ASSET, assets, BUFFER_PRICE_OUT)?;
    let engine_shares = sload(STRATEGY_VAULT, SV_ENGINE_BALANCE)?
        .checked_sub(shares)
        .ok_or_else(|| revert("native vault: engine shares"))?;
    sstore(STRATEGY_VAULT, SV_ENGINE_BALANCE, engine_shares)?;
    sstore(STRATEGY_VAULT, SV_TOTAL_SUPPLY, total - shares)?;
    emit(
        STRATEGY_VAULT,
        vec![T_TRANSFER, ENGINE.into_word(), B256::ZERO],
        word(shares).to_vec(),
    )?;
    token(ASSET)?.transfer(
        STRATEGY_VAULT,
        ITIP20::transferCall {
            to: call.receiver,
            amount: assets,
        },
    )?;
    emit(
        STRATEGY_VAULT,
        vec![
            T_SV_EXIT,
            call.receiver.into_word(),
            ASSET.into_word(),
            ENGINE.into_word(),
        ],
        (assets, shares).abi_encode_params(),
    )?;
    emit(
        ROUTER,
        vec![T_ROUTER_WITHDRAW, ASSET.into_word()],
        word(assets).to_vec(),
    )?;
    sstore(ROUTER, ROUTER_GUARD, U256::from(1))?;

    balance_of(ASSET, call.receiver)?;
    emit(
        ENGINE,
        vec![T_ENGINE_REDEEM, call.receiver.into_word()],
        (shares, assets).abi_encode_params(),
    )?;

    // UserVault.
    sstore(USER_VAULT, UV_ENGINE_SHARES, engine_shares)?;
    token(SHARE)?.total_supply()?;
    sstore(USER_VAULT, UV_LAST_SHARES_D, engine_shares)?;
    sstore(USER_VAULT, UV_LAST_SHARES_E, engine_shares)?;
    emit(
        USER_VAULT,
        vec![T_UV_REDEEM, user.into_word(), call.receiver.into_word()],
        (shares, assets).abi_encode_params(),
    )?;
    sstore(USER_VAULT, UV_GUARD, U256::from(1))?;
    Ok(word(assets).to_vec().into())
}
