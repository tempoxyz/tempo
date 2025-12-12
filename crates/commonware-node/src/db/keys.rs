use crate::dkg::HardforkRegime;

pub(super) fn ceremony(epoch: u64) -> String {
    format!("ceremony_{epoch}")
}

pub(super) fn validators(epoch: u64) -> String {
    format!("validators_{epoch}")
}

pub(super) const DKG_OUTCOME: &str = "dkg_outcome";

pub(super) fn current_epoch(regime: HardforkRegime) -> &'static str {
    match regime {
        HardforkRegime::PreAllegretto => "pre_allegretto_epoch_current",
        HardforkRegime::PostAllegretto => "post_allegretto_epoch_current",
    }
}

pub(super) fn previous_epoch(regime: HardforkRegime) -> &'static str {
    match regime {
        HardforkRegime::PreAllegretto => "pre_allegretto_epoch_previous",
        HardforkRegime::PostAllegretto => "post_allegretto_epoch_previous",
    }
}
