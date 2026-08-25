use std::{error::Error, fs};

use alloy::{
    primitives::{Address, U256, hex},
    sol_types::SolCall,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::IZoneVerifier;
use tempo_precompiles::{
    Precompile,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    zone_verifier::ZoneVerifier,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let portal = args.next().ok_or(USAGE)?.parse::<Address>()?;
    let chain_id = args.next().ok_or(USAGE)?.parse::<u64>()?;
    let block_timestamp = args.next().ok_or(USAGE)?.parse::<u64>()?;
    let calldata_arg = args.next().ok_or(USAGE)?;
    if args.next().is_some() {
        return Err(USAGE.into());
    }

    let calldata = read_calldata(&calldata_arg)?;
    let call = IZoneVerifier::verifyCall::abi_decode(&calldata)?;

    let mut dispatch_storage = storage(chain_id, block_timestamp);
    let precompile_result = StorageCtx::enter(&mut dispatch_storage, || {
        ZoneVerifier::new().call(&calldata, portal)
    })?;
    let valid = IZoneVerifier::verifyCall::abi_decode_returns(&precompile_result.bytes)?;

    let mut diagnostic_storage = storage(chain_id, block_timestamp);
    let diagnostic = StorageCtx::enter(&mut diagnostic_storage, || {
        ZoneVerifier::new().diagnose(portal, call)
    })?;

    println!("precompile result: {valid}");
    println!("diagnostic: {diagnostic:#?}");
    Ok(())
}

fn storage(chain_id: u64, timestamp: u64) -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_spec(chain_id, TempoHardfork::T11);
    storage.set_timestamp(U256::from(timestamp));
    storage
}

fn read_calldata(argument: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let value = if argument.starts_with("0x") {
        argument.to_owned()
    } else {
        fs::read_to_string(argument)?.trim().to_owned()
    };
    Ok(hex::decode(value.strip_prefix("0x").unwrap_or(&value))?)
}

const USAGE: &str = "usage: tempo-zone-verifier-debug <portal> <chain-id> <block-timestamp-seconds> <calldata-hex-or-file>";
