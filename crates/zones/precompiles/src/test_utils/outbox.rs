use alloy_primitives::{Address, B256, Bytes, U256};
use tempo_contracts::zones::IZoneOutbox;
use tempo_precompiles::test_util::TIP20Setup;
use zone_primitives::constants::ZONE_OUTBOX_ADDRESS;

/// Initialize Outbox and fund accounts with PathUSD approved for withdrawals.
/// Must run inside an active `StorageCtx`.
pub fn setup_outbox(
    admin: Address,
    accounts: impl IntoIterator<Item = Address>,
    balance: U256,
) -> crate::ZoneResult<()> {
    crate::ZoneOutbox::new().initialize()?;
    let mut token = TIP20Setup::path_usd(admin)
        .with_issuer(admin)
        .with_issuer(ZONE_OUTBOX_ADDRESS);
    for account in accounts {
        token = token.with_mint(account, balance).with_approval(
            account,
            ZONE_OUTBOX_ADDRESS,
            U256::MAX,
        );
    }
    token.apply()?;
    Ok(())
}

/// A withdrawal with no memo, callback, or reveal recipients.
pub fn withdrawal_call(
    token: Address,
    to: Address,
    amount: u128,
    fallback: Address,
) -> IZoneOutbox::requestWithdrawalCall {
    IZoneOutbox::requestWithdrawalCall {
        token,
        to,
        amount,
        zoneFallbackRecipient: fallback,
        memo: B256::ZERO,
        gasLimit: 0,
        data: Bytes::new(),
        revealTo: Bytes::new(),
    }
}
