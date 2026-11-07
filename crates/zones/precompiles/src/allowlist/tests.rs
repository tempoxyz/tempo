use super::*;

use alloy_primitives::{Bytes, keccak256};
use alloy_sol_types::{SolCall, SolError};
use evm2::evm::precompile::PrecompileProvider;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::zones::IZoneAllowlist::{self, AllowlistFull, BatchTooLarge, Unauthorized};
use tempo_precompiles::storage::{PrecompileStorageProvider, StorageCtx};
use tempo_primitives::TempoHeader;

use crate::{
    tempo_state::TempoState,
    test_utils::{
        MockL1Reader, PrecompileOutput, PrecompileStatus, TestContext, TestPrecompiles,
        call_precompile, test_context_with_hardfork, test_precompiles, test_storage_provider,
    },
};

const GAS: u64 = 30_000_000;
const PORTAL: Address = Address::repeat_byte(0x42);
const SEQUENCER: Address = Address::with_last_byte(0xa1);
const ADMIN: Address = Address::with_last_byte(0xad);
const ALICE: Address = Address::with_last_byte(0xa2);
const BOB: Address = Address::with_last_byte(0xb0);
const CAROL: Address = Address::with_last_byte(0xc0);

struct Harness {
    ctx: TestContext,
    precompile: TestPrecompiles,
}

impl Harness {
    fn new() -> eyre::Result<Self> {
        let mut ctx = test_context_with_hardfork(TempoHardfork::T15);
        {
            let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
            StorageCtx::enter(&mut storage, || {
                TempoState::new().initialize(&alloy_rlp::encode(TempoHeader::default()))
            })?;
        }
        let l1 = MockL1Reader::default();
        l1.seed_active_sequencer(PORTAL, 0, SEQUENCER);
        let precompile = test_precompiles(&ctx, L1State::new(l1, PORTAL));
        Ok(Self { ctx, precompile })
    }

    /// Returns a harness whose admin is [`ADMIN`], set by the sequencer.
    fn with_admin() -> eyre::Result<Self> {
        let mut harness = Self::new()?;
        harness.ensure_success(SEQUENCER, IZoneAllowlist::setAdminCall { newAdmin: ADMIN })?;
        Ok(harness)
    }

    fn call(&mut self, caller: Address, call: impl SolCall) -> eyre::Result<PrecompileOutput> {
        self.call_raw(caller, &call.abi_encode(), false)
    }

    fn call_raw(
        &mut self,
        caller: Address,
        data: &[u8],
        is_static: bool,
    ) -> eyre::Result<PrecompileOutput> {
        let checkpoint = self.ctx.checkpoint();
        let output = call_precompile(
            &mut self.ctx,
            &mut self.precompile,
            caller,
            data,
            GAS,
            is_static,
            ZONE_ALLOWLIST_ADDRESS,
            ZONE_ALLOWLIST_ADDRESS,
        )?;
        if !output.is_success() {
            self.ctx.checkpoint_revert(checkpoint);
        }
        Ok(output)
    }

    fn ensure_success<T: SolCall>(&mut self, caller: Address, call: T) -> eyre::Result<T::Return> {
        let output = self.call(caller, call)?;
        eyre::ensure!(output.is_success(), "call failed: {output:?}");
        Ok(T::abi_decode_returns(&output.bytes)?)
    }

    fn set_allowed(&mut self, accounts: &[Address], allowed: bool) -> eyre::Result<()> {
        self.ensure_success(
            ADMIN,
            IZoneAllowlist::setAllowedCall {
                accounts: accounts.to_vec(),
                allowed,
            },
        )?;
        Ok(())
    }

    fn accounts(&mut self, offset: u64, limit: U256) -> eyre::Result<Vec<Address>> {
        self.ensure_success(
            ADMIN,
            IZoneAllowlist::accountsCall {
                offset: U256::from(offset),
                limit,
            },
        )
    }

    /// Reads the allowlist in a read-only storage context, as the node does.
    fn read<T>(
        &mut self,
        f: impl FnOnce(&ZoneAllowlist) -> tempo_precompiles::Result<T>,
    ) -> eyre::Result<T> {
        let mut storage = test_storage_provider(&mut self.ctx, u64::MAX, true);
        Ok(StorageCtx::enter(
            &mut storage,
            || f(&ZoneAllowlist::new()),
        )?)
    }
}

fn assert_reverts(output: &PrecompileOutput, expected: impl SolError) {
    assert!(output.is_revert(), "expected revert, got {output:?}");
    assert_eq!(output.bytes, Bytes::from(expected.abi_encode()));
}

#[test]
fn address_is_a_precompile_only_from_t15() -> eyre::Result<()> {
    for (hardfork, active) in [(TempoHardfork::T14, false), (TempoHardfork::T15, true)] {
        let mut ctx = test_context_with_hardfork(hardfork);
        let mut precompile = test_precompiles(&ctx, L1State::new(Default::default(), PORTAL));
        assert_eq!(precompile.contains(&ZONE_ALLOWLIST_ADDRESS), active);

        let message = evm2::interpreter::Message::<tempo_evm::TempoEvmTypes> {
            gas_limit: GAS,
            input: Bytes::from(IZoneAllowlist::adminCall {}.abi_encode()).into(),
            destination: ZONE_ALLOWLIST_ADDRESS,
            call_target: ZONE_ALLOWLIST_ADDRESS,
            code_address: ZONE_ALLOWLIST_ADDRESS,
            ..Default::default()
        };
        let mut gas = evm2::interpreter::GasTracker::new(GAS);
        assert_eq!(
            precompile.execute(ctx.evm(), &message, &mut gas).is_some(),
            active
        );
    }
    Ok(())
}

#[test]
fn sequencer_bootstraps_and_recovers_admin() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    // With no admin set, neither an outsider nor `address(0)` may claim it.
    for caller in [ALICE, Address::ZERO] {
        let output = harness.call(caller, IZoneAllowlist::setAdminCall { newAdmin: caller })?;
        assert_reverts(&output, Unauthorized {});
    }

    harness.ensure_success(SEQUENCER, IZoneAllowlist::setAdminCall { newAdmin: ADMIN })?;
    assert_eq!(
        harness.ensure_success(BOB, IZoneAllowlist::adminCall {})?,
        ADMIN
    );
    assert!(harness.read(|allowlist| allowlist.is_initialized())?);

    // The admin hands over; the previous admin loses its rights.
    harness.ensure_success(ADMIN, IZoneAllowlist::setAdminCall { newAdmin: ALICE })?;
    let output = harness.call(ADMIN, IZoneAllowlist::setAdminCall { newAdmin: ADMIN })?;
    assert_reverts(&output, Unauthorized {});
    let output = harness.call(ADMIN, IZoneAllowlist::setEnabledCall { enabled: true })?;
    assert_reverts(&output, Unauthorized {});

    // The sequencer recovers it regardless of the current admin.
    harness.ensure_success(SEQUENCER, IZoneAllowlist::setAdminCall { newAdmin: ADMIN })?;
    assert_eq!(
        harness.ensure_success(BOB, IZoneAllowlist::adminCall {})?,
        ADMIN
    );
    Ok(())
}

#[test]
fn list_changes_are_admin_only() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    // An unset admin matches nobody, including `address(0)`.
    let output = harness.call(
        Address::ZERO,
        IZoneAllowlist::setEnabledCall { enabled: true },
    )?;
    assert_reverts(&output, Unauthorized {});

    harness.ensure_success(SEQUENCER, IZoneAllowlist::setAdminCall { newAdmin: ADMIN })?;
    for caller in [ALICE, SEQUENCER, Address::ZERO] {
        let output = harness.call(caller, IZoneAllowlist::setEnabledCall { enabled: true })?;
        assert_reverts(&output, Unauthorized {});
        let output = harness.call(
            caller,
            IZoneAllowlist::setAllowedCall {
                accounts: vec![caller],
                allowed: true,
            },
        )?;
        assert_reverts(&output, Unauthorized {});
    }
    assert!(!harness.ensure_success(ALICE, IZoneAllowlist::enabledCall {})?);
    Ok(())
}

#[test]
fn allows_follows_enforcement_and_membership() -> eyre::Result<()> {
    let mut harness = Harness::with_admin()?;
    // Disabled by default: everyone is allowed.
    assert!(!harness.read(|allowlist| allowlist.is_enabled())?);
    assert!(harness.read(|allowlist| allowlist.allows(BOB))?);
    assert!(harness.read(|allowlist| allowlist.allows_all(&[ALICE, BOB]))?);

    // Enabled with an empty list: nobody is allowed.
    harness.ensure_success(ADMIN, IZoneAllowlist::setEnabledCall { enabled: true })?;
    assert!(harness.read(|allowlist| allowlist.is_enabled())?);
    assert!(!harness.read(|allowlist| allowlist.allows(ALICE))?);

    harness.set_allowed(&[ALICE], true)?;
    assert!(harness.read(|allowlist| allowlist.allows(ALICE))?);
    assert!(!harness.read(|allowlist| allowlist.allows(BOB))?);
    assert!(harness.read(|allowlist| allowlist.allows_all(&[ALICE]))?);
    assert!(!harness.read(|allowlist| allowlist.allows_all(&[ALICE, BOB]))?);
    assert!(harness.read(|allowlist| allowlist.allows_all(&[]))?);
    assert!(!harness.ensure_success(BOB, IZoneAllowlist::isAllowedCall { account: BOB })?);

    harness.ensure_success(ADMIN, IZoneAllowlist::setEnabledCall { enabled: false })?;
    assert!(harness.read(|allowlist| allowlist.allows_all(&[ALICE, BOB]))?);
    assert!(harness.ensure_success(BOB, IZoneAllowlist::isAllowedCall { account: BOB })?);
    Ok(())
}

#[test]
fn set_allowed_is_idempotent_and_compacts_by_swap_and_pop() -> eyre::Result<()> {
    let mut harness = Harness::with_admin()?;
    harness.set_allowed(&[ALICE, BOB, CAROL, ALICE], true)?;
    harness.set_allowed(&[BOB], true)?;
    assert_eq!(harness.accounts(0, U256::MAX)?, vec![ALICE, BOB, CAROL]);

    // Removing the first member moves the last into its place.
    harness.set_allowed(&[ALICE, ALICE], false)?;
    assert_eq!(harness.accounts(0, U256::MAX)?, vec![CAROL, BOB]);
    assert_eq!(
        harness.ensure_success(ADMIN, IZoneAllowlist::countCall {})?,
        U256::from(2)
    );
    assert!(!harness.read(|allowlist| allowlist.is_member(ALICE))?);
    assert!(harness.read(|allowlist| allowlist.is_member(BOB))?);

    // Pages are clamped to the list.
    assert_eq!(harness.accounts(1, U256::from(10))?, vec![BOB]);
    assert_eq!(harness.accounts(0, U256::from(1))?, vec![CAROL]);
    assert_eq!(harness.accounts(2, U256::MAX)?, Vec::<Address>::new());
    assert_eq!(
        harness.ensure_success(
            ADMIN,
            IZoneAllowlist::accountsCall {
                offset: U256::MAX,
                limit: U256::MAX,
            },
        )?,
        Vec::<Address>::new()
    );

    // Removing the last member needs no move; re-adding appends.
    harness.set_allowed(&[BOB], false)?;
    harness.set_allowed(&[ALICE], true)?;
    assert_eq!(harness.accounts(0, U256::MAX)?, vec![CAROL, ALICE]);
    harness.set_allowed(&[CAROL, ALICE, BOB], false)?;
    assert_eq!(
        harness.ensure_success(ADMIN, IZoneAllowlist::countCall {})?,
        U256::ZERO
    );
    Ok(())
}

#[test]
fn set_allowed_enforces_batch_and_total_caps() -> eyre::Result<()> {
    let mut harness = Harness::with_admin()?;
    let oversized = (0..=MAX_ZONE_ALLOWLIST_BATCH)
        .map(|index| Address::from_word(keccak256(index.to_be_bytes())))
        .collect::<Vec<_>>();
    let output = harness.call(
        ADMIN,
        IZoneAllowlist::setAllowedCall {
            accounts: oversized,
            allowed: true,
        },
    )?;
    assert_reverts(
        &output,
        BatchTooLarge {
            length: U256::from(MAX_ZONE_ALLOWLIST_BATCH + 1),
            max: U256::from(MAX_ZONE_ALLOWLIST_BATCH),
        },
    );
    assert_eq!(output.gas_used, SET_ALLOWED_BASE_GAS);

    // Model a list one short of the cap by setting the member count directly.
    {
        let mut storage = test_storage_provider(&mut harness.ctx, u64::MAX, false);
        storage.sstore(
            ZONE_ALLOWLIST_ADDRESS,
            slots::MEMBERS,
            U256::from(MAX_ZONE_ALLOWLIST_LEN - 1),
        )?;
    }
    let output = harness.call(
        ADMIN,
        IZoneAllowlist::setAllowedCall {
            accounts: vec![ALICE, BOB],
            allowed: true,
        },
    )?;
    assert_reverts(
        &output,
        AllowlistFull {
            max: U256::from(MAX_ZONE_ALLOWLIST_LEN),
        },
    );
    assert!(!harness.read(|allowlist| allowlist.is_member(ALICE))?);

    // Re-adding a member and filling the last place both fit.
    harness.set_allowed(&[ALICE, ALICE], true)?;
    assert_eq!(
        harness.ensure_success(ADMIN, IZoneAllowlist::countCall {})?,
        U256::from(MAX_ZONE_ALLOWLIST_LEN)
    );
    Ok(())
}

#[test]
fn mutations_fail_in_static_context() -> eyre::Result<()> {
    let mut harness = Harness::with_admin()?;
    for data in [
        IZoneAllowlist::setAdminCall { newAdmin: ALICE }.abi_encode(),
        IZoneAllowlist::setEnabledCall { enabled: true }.abi_encode(),
        IZoneAllowlist::setAllowedCall {
            accounts: vec![ALICE],
            allowed: true,
        }
        .abi_encode(),
    ] {
        let output = harness.call_raw(ADMIN, &data, true)?;
        assert!(
            matches!(output.status, PrecompileStatus::Halt(_)),
            "expected a halt, got {output:?}"
        );
    }
    assert_eq!(
        harness.ensure_success(BOB, IZoneAllowlist::adminCall {})?,
        ADMIN
    );
    assert!(!harness.ensure_success(BOB, IZoneAllowlist::enabledCall {})?);
    assert_eq!(harness.accounts(0, U256::MAX)?, Vec::<Address>::new());
    Ok(())
}

#[test]
fn restricted_reads_admit_only_privileged_callers() -> eyre::Result<()> {
    let mut harness = Harness::with_admin()?;
    harness.set_allowed(&[ALICE], true)?;

    let restricted = [
        IZoneAllowlist::countCall {}.abi_encode(),
        IZoneAllowlist::accountsCall {
            offset: U256::ZERO,
            limit: U256::MAX,
        }
        .abi_encode(),
        IZoneAllowlist::isAllowedCall { account: ALICE }.abi_encode(),
    ];
    for data in &restricted {
        for caller in [ADMIN, SEQUENCER, Address::ZERO] {
            assert!(harness.call_raw(caller, data, true)?.is_success());
        }
        assert_reverts(&harness.call_raw(BOB, data, true)?, Unauthorized {});
    }

    // Accounts may query themselves; the public getters need no privilege.
    assert!(harness.ensure_success(ALICE, IZoneAllowlist::isAllowedCall { account: ALICE })?);
    assert!(harness.ensure_success(BOB, IZoneAllowlist::isAllowedCall { account: BOB })?);
    assert!(!harness.ensure_success(BOB, IZoneAllowlist::enabledCall {})?);
    assert_eq!(
        harness.ensure_success(BOB, IZoneAllowlist::adminCall {})?,
        ADMIN
    );
    Ok(())
}

#[test]
fn mutations_charge_fixed_gas() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let output = harness.call(SEQUENCER, IZoneAllowlist::setAdminCall { newAdmin: ADMIN })?;
    assert!(output.is_success());
    assert_eq!(output.gas_used, SET_ADMIN_GAS);

    let output = harness.call(ADMIN, IZoneAllowlist::setEnabledCall { enabled: true })?;
    assert!(output.is_success());
    assert_eq!(output.gas_used, SET_ENABLED_GAS);

    // New members cost the same as already listed ones, and removals as additions.
    for (accounts, allowed) in [
        (vec![ALICE, BOB, CAROL], true),
        (vec![ALICE, BOB, CAROL], true),
        (vec![ALICE, BOB, CAROL], false),
    ] {
        let output = harness.call(ADMIN, IZoneAllowlist::setAllowedCall { accounts, allowed })?;
        assert!(output.is_success());
        assert_eq!(
            output.gas_used,
            SET_ALLOWED_BASE_GAS + 3 * SET_ALLOWED_ACCOUNT_GAS
        );
    }

    // Rejected calls pay the same fixed charge.
    let output = harness.call(
        BOB,
        IZoneAllowlist::setAllowedCall {
            accounts: vec![BOB],
            allowed: true,
        },
    )?;
    assert_reverts(&output, Unauthorized {});
    assert_eq!(
        output.gas_used,
        SET_ALLOWED_BASE_GAS + SET_ALLOWED_ACCOUNT_GAS
    );

    // Malformed calldata pays the base and reverts in dispatch.
    let mut malformed = IZoneAllowlist::setAllowedCall::SELECTOR.to_vec();
    malformed.extend_from_slice(&[0xff; 40]);
    let output = harness.call_raw(ADMIN, &malformed, false)?;
    assert!(output.is_revert());
    assert_eq!(output.gas_used, SET_ALLOWED_BASE_GAS);

    for data in [
        IZoneAllowlist::adminCall {}.abi_encode(),
        IZoneAllowlist::countCall {}.abi_encode(),
        Vec::new(),
    ] {
        assert_eq!(AllowlistRules.fixed_gas_for_call(&data), None);
    }
    Ok(())
}
