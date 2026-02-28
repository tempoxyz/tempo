//! Tests on chain DKG and epoch transition

mod backfill;
mod consensus_rpc;
mod dkg;
mod restart;
mod simple;
mod snapshot;

// FIXME: subblocks are currently flaky. Don't want to add extra flaky tests
// right now.
// mod subblocks;

#[track_caller]
fn assert_no_v1(metric: &str, value: &str) {
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

#[track_caller]
fn assert_no_dkg_failure(metric: &str, value: &str) {
    if metric.ends_with("_dkg_manager_ceremony_failures_total") {
        assert_eq!(0, value.parse::<u64>().unwrap(),);
    }
}
