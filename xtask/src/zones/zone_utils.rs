use alloy::{
    consensus::BlockHeader as _,
    network::primitives::ReceiptResponse,
    primitives::{Address, U256},
    providers::Provider,
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use eyre::{WrapErr as _, eyre};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::ITIP20 as TIP20Token;
use tempo_contracts::zones::{IZoneInbox, ZONE_FACTORY_ADDRESS, ZoneFactory, ZonePortal};

/// Write a file that may contain key material with owner-only permissions on Unix.
///
/// Permissions are restricted before truncating an existing file, so updating a
/// legacy file with broader permissions does not expose its new contents.
pub(crate) fn write_owner_only(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::{
            fs::{OpenOptions, Permissions},
            io::Write as _,
            os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
        };

        let mut options = OpenOptions::new();
        options.write(true).create(true).mode(0o600);
        let mut file = options.open(path)?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        file.set_len(0)?;
        file.write_all(contents.as_ref())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

pub(crate) const L1_EXPLORER: &str = "https://explore.moderato.tempo.xyz/tx";
/// Shared Moderato ZoneFactory.
///
/// `create-zone`, `deploy-router`, and `zone-info` use this as their default
/// factory unless the caller overrides `--zone-factory` or `ZONE_FACTORY`, or
/// `zone.json` already provides a zone-specific value.
/// Explorer: https://explore.moderato.tempo.xyz/address/0x5aF2000000000000000000000000000000000000
pub(crate) const MODERATO_ZONE_FACTORY: Address = ZONE_FACTORY_ADDRESS;
pub(crate) use tempo_contracts::precompiles::STABLECOIN_DEX_ADDRESS;
pub(crate) const ROUTER_CALLBACK_GAS_LIMIT: u64 = 2_000_000;
const DEFAULT_WAIT_ATTEMPTS: usize = 120;
const DEFAULT_WAIT_POLL: Duration = Duration::from_millis(500);
const LOG_QUERY_BLOCK_CHUNK: u64 = 5_000;

/// Finds the block of the single ZoneCreated event for `zone_id` and `portal` in
/// `from_block..=snapshot_block`.
///
/// Pass `0` when the creation block is unknown. Scanning from genesis issues one log query
/// per 5,000 blocks, so callers that already know the creation block should start there.
pub(crate) async fn find_zone_deployment_block<P: Provider<TempoNetwork>>(
    provider: &P,
    zone_id: u32,
    portal: Address,
    from_block: u64,
    snapshot_block: u64,
) -> eyre::Result<u64> {
    let events = ZoneFactory::new(ZONE_FACTORY_ADDRESS, provider)
        .ZoneCreated_filter()
        .topic1(U256::from(zone_id))
        .topic2(portal)
        .from_block(from_block)
        .to_block(snapshot_block)
        .chunked()
        .chunk_size(LOG_QUERY_BLOCK_CHUNK)
        .query()
        .await
        .wrap_err("failed scanning ZoneFactory ZoneCreated events")?;

    eyre::ensure!(
        events.len() == 1,
        "expected exactly one ZoneCreated event for Zone {zone_id} and portal {portal}, found {}",
        events.len()
    );
    let (event, log) = &events[0];
    eyre::ensure!(
        event.zoneId == zone_id && event.portal == portal,
        "ZoneCreated event does not match Zone {zone_id} and portal {portal}"
    );
    eyre::ensure!(!log.removed, "ZoneCreated query returned a removed log");
    let block_number = log
        .block_number
        .ok_or_else(|| eyre!("ZoneCreated log is missing its block number"))?;
    let block_hash = log
        .block_hash
        .ok_or_else(|| eyre!("ZoneCreated log is missing its block hash"))?;
    let header = provider
        .get_header_by_number(block_number.into())
        .await
        .wrap_err_with(|| format!("failed reading ZoneCreated block {block_number}"))?
        .ok_or_else(|| eyre!("ZoneCreated block {block_number} was not found"))?;
    eyre::ensure!(
        header.number() == block_number && header.hash == block_hash,
        "ZoneCreated log block ({block_number}, {block_hash}) does not match canonical header ({}, {})",
        header.number(),
        header.hash
    );
    Ok(block_number)
}

pub(crate) struct ZoneMetadata {
    path: PathBuf,
    value: Value,
}

impl ZoneMetadata {
    pub(crate) fn load(zone_dir: &Path) -> eyre::Result<Self> {
        let path = zone_dir.join("zone.json");
        let contents = std::fs::read_to_string(&path)
            .wrap_err_with(|| format!("failed reading {}", path.display()))?;
        let value: Value = serde_json::from_str(&contents)
            .wrap_err_with(|| format!("failed parsing {}", path.display()))?;
        if !value.is_object() {
            return Err(eyre!(
                "expected {} to contain a JSON object",
                path.display()
            ));
        }
        Ok(Self { path, value })
    }

    pub(crate) fn save(&self) -> eyre::Result<()> {
        write_owner_only(
            &self.path,
            serde_json::to_string_pretty(&self.value).wrap_err("failed encoding zone.json")?,
        )
        .wrap_err_with(|| format!("failed writing {}", self.path.display()))
    }

    pub(crate) fn get_required_address(&self, key: &str) -> eyre::Result<Address> {
        let value = self
            .value
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("{key} not found in {}", self.path.display()))?;
        value
            .parse()
            .wrap_err_with(|| format!("invalid {key} address in {}", self.path.display()))
    }

    pub(crate) fn get_optional_address(&self, key: &str) -> eyre::Result<Option<Address>> {
        self.value
            .get(key)
            .and_then(Value::as_str)
            .map(|value| {
                value
                    .parse()
                    .wrap_err_with(|| format!("invalid {key} address in {}", self.path.display()))
            })
            .transpose()
    }

    pub(crate) fn get_optional_string(&self, key: &str) -> Option<String> {
        self.value
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    pub(crate) fn set_address(&mut self, key: &str, value: Address) {
        self.set_string(key, value.to_string());
    }

    pub(crate) fn set_string(&mut self, key: &str, value: impl Into<String>) {
        if let Some(obj) = self.value.as_object_mut() {
            obj.insert(key.to_string(), Value::String(value.into()));
        }
    }
}

pub(crate) fn normalize_http_rpc(rpc_url: &str) -> String {
    rpc_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
}

pub(crate) fn parse_private_key(private_key: &str) -> eyre::Result<PrivateKeySigner> {
    Ok(private_key
        .strip_prefix("0x")
        .unwrap_or(private_key)
        .parse()?)
}

pub(crate) fn check(receipt: &impl ReceiptResponse, label: &str) -> eyre::Result<()> {
    if !receipt.status() {
        return Err(eyre!("{label} reverted"));
    }
    Ok(())
}

pub(crate) async fn fund_l1_wallet<P: Provider<TempoNetwork>>(
    provider: &P,
    address: Address,
) -> eyre::Result<()> {
    let _: Vec<alloy::primitives::B256> = provider
        .raw_request("tempo_fundAddress".into(), (address,))
        .await
        .wrap_err("tempo_fundAddress RPC request failed")?;
    Ok(())
}

/// Verifies that `resolved_admin` is the portal's on-chain admin.
///
/// Portal governance calls such as `enableToken` and portal unpause are admin-only,
/// so a key resolved via the sequencer fallback only works on legacy zones where
/// `admin == sequencer`. Checking against `portal.admin()` fails fast with a
/// clear message instead of reverting on-chain with `NotAdmin`.
pub(crate) async fn verify_portal_admin<P: Provider<TempoNetwork>>(
    provider: &P,
    portal: Address,
    resolved_admin: Address,
) -> eyre::Result<()> {
    let onchain_admin = ZonePortal::new(portal, provider)
        .admin()
        .call()
        .await
        .wrap_err("failed to read portal admin")?;
    if onchain_admin != resolved_admin {
        return Err(eyre!(
            "resolved admin {resolved_admin} is not the portal admin {onchain_admin}; \
             set ADMIN_KEY/adminKey for this zone (SEQUENCER_KEY only works when admin == sequencer)"
        ));
    }
    Ok(())
}

pub(crate) async fn token_balance<P: Provider<TempoNetwork>>(
    provider: &P,
    token: Address,
    account: Address,
) -> eyre::Result<U256> {
    TIP20Token::new(token, provider)
        .balanceOf(account)
        .call()
        .await
        .wrap_err("balanceOf failed")
}

pub(crate) async fn wait_for_token_enabled<P: Provider<TempoNetwork>>(
    l2: &P,
    from_block: u64,
    token: Address,
) -> eyre::Result<u64> {
    let filter = Filter::new()
        .address(tempo_contracts::zones::ZONE_INBOX_ADDRESS)
        .event_signature(IZoneInbox::TokenEnabled::SIGNATURE_HASH)
        .from_block(from_block);

    for _ in 0..DEFAULT_WAIT_ATTEMPTS {
        let logs = l2.get_logs(&filter).await.unwrap_or_default();
        for log in &logs {
            if let Ok(event) = IZoneInbox::TokenEnabled::decode_log(&log.inner)
                && event.data.token == token
            {
                return Ok(log.block_number.unwrap_or(0));
            }
        }
        tokio::time::sleep(DEFAULT_WAIT_POLL).await;
    }

    Err(eyre!("timeout waiting for TokenEnabled event on L2"))
}

pub(crate) async fn wait_for_deposit_processed<P: Provider<TempoNetwork>>(
    l2: &P,
    from_block: u64,
    sender: Address,
    to: Address,
    token: Address,
) -> eyre::Result<u64> {
    let filter = Filter::new()
        .address(tempo_contracts::zones::ZONE_INBOX_ADDRESS)
        .event_signature(IZoneInbox::DepositProcessed::SIGNATURE_HASH)
        .from_block(from_block);

    for _ in 0..DEFAULT_WAIT_ATTEMPTS {
        let logs = l2.get_logs(&filter).await.unwrap_or_default();
        for log in &logs {
            if let Ok(event) = IZoneInbox::DepositProcessed::decode_log(&log.inner)
                && event.data.sender == sender
                && event.data.to == to
                && event.data.token == token
            {
                return Ok(log.block_number.unwrap_or(0));
            }
        }
        tokio::time::sleep(DEFAULT_WAIT_POLL).await;
    }

    Err(eyre!("timeout waiting for DepositProcessed"))
}

pub(crate) async fn wait_for_balance<P: Provider<TempoNetwork>>(
    provider: &P,
    token: Address,
    account: Address,
    expected_balance: U256,
    label: &str,
) -> eyre::Result<U256> {
    for _ in 0..DEFAULT_WAIT_ATTEMPTS {
        let balance = token_balance(provider, token, account)
            .await
            .unwrap_or_default();
        if balance >= expected_balance {
            return Ok(balance);
        }
        tokio::time::sleep(DEFAULT_WAIT_POLL).await;
    }

    Err(eyre!(
        "timeout waiting for {label} balance to reach {expected_balance}"
    ))
}

pub(crate) async fn wait_for_withdrawal_processed<P: Provider<TempoNetwork>>(
    l1: &P,
    from_block: u64,
    portal: Address,
    to: Address,
    token: Address,
    amount: u128,
    callback_success: bool,
) -> eyre::Result<u64> {
    let filter = Filter::new()
        .address(portal)
        .event_signature(ZonePortal::WithdrawalProcessed::SIGNATURE_HASH)
        .from_block(from_block);

    for _ in 0..(DEFAULT_WAIT_ATTEMPTS * 2) {
        let logs = l1.get_logs(&filter).await.unwrap_or_default();
        for log in &logs {
            if let Ok(event) = ZonePortal::WithdrawalProcessed::decode_log(&log.inner)
                && event.data.to == to
                && event.data.token == token
                && event.data.amount == amount
                && event.data.callbackSuccess == callback_success
            {
                return Ok(log.block_number.unwrap_or(0));
            }
        }
        tokio::time::sleep(DEFAULT_WAIT_POLL).await;
    }

    Err(eyre!(
        "timeout waiting for WithdrawalProcessed(to={to}, token={token}, amount={amount}, callbackSuccess={callback_success})"
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_private_key;

    #[test]
    fn parses_prefixed_and_unprefixed_private_keys() {
        let key = "1111111111111111111111111111111111111111111111111111111111111111";

        assert_eq!(
            parse_private_key(key).unwrap().to_bytes(),
            parse_private_key(&format!("0x{key}")).unwrap().to_bytes()
        );
    }
}
