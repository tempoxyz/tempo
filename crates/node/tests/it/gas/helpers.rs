use std::collections::BTreeMap;
use tempo_chainspec::constants::gas::TEMPO_T1_TX_GAS_LIMIT_CAP;

pub(crate) const GAS_LIMIT: u64 = TEMPO_T1_TX_GAS_LIMIT_CAP;
pub(crate) type GasSnapshot = BTreeMap<String, u64>;

pub(crate) fn print_gas_snapshot(title: &str, gas: &GasSnapshot) {
    eprintln!("\n{title}:");
    for (name, gas_used) in gas {
        eprintln!("{name}: {gas_used}");
    }
}
