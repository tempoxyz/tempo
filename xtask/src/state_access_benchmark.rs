use alloy::{
    genesis::GenesisAccount,
    primitives::{Address, Bytes, address},
};
use eyre::{OptionExt as _, WrapErr as _};

pub(crate) const ADDRESS: Address = address!("535441544541434345535342454e434800000000");
pub(crate) const READS_PER_TX: u64 = 4096;

const ARTIFACT: &str = include_str!("../../contrib/bench/txgen/state-access-benchmark.json");

pub(crate) fn genesis_account() -> eyre::Result<GenesisAccount> {
    let artifact: serde_json::Value =
        serde_json::from_str(ARTIFACT).wrap_err("invalid state-access benchmark artifact")?;
    let runtime = artifact
        .pointer("/deployedBytecode/object")
        .and_then(serde_json::Value::as_str)
        .ok_or_eyre("state-access benchmark artifact has no deployed bytecode")?
        .parse::<Bytes>()
        .wrap_err("invalid state-access benchmark deployed bytecode")?;

    Ok(GenesisAccount {
        code: Some(runtime),
        nonce: Some(1),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_contains_runtime_code() {
        let account = genesis_account().unwrap();
        assert!(account.code.is_some_and(|code| !code.is_empty()));
    }
}
