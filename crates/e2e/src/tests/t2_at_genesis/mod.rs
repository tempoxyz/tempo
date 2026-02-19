//! Tests on chain DKG and epoch transition

mod dkg;
mod linkage;

fn ensure_no_v1(metric: &str, value: &str) {
    if metric.ends_with("_dkg_manager_read_players_from_v1_contract_total") {
        assert_eq!(0, value.parse::<u64>().unwrap());
    }
    if metric.ends_with("_dkg_manager_syncing_players") {
        assert_eq!(0, value.parse::<u64>().unwrap());
    }
    if metric.ends_with("_dkg_manager_read_re_dkg_epoch_from_v1_contract_total") {
        assert_eq!(0, value.parse::<u64>().unwrap());
    }
}
