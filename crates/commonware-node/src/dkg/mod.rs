use tempo_dkg_onchain_artifacts::IntermediateOutcome;

pub(crate) mod ceremony;
pub(crate) mod manager;

pub(crate) fn verify_dkg_dealing(
    dealing: &IntermediateOutcome,
    hardfork_regime: HardforkRegime,
) -> bool {
    match hardfork_regime {
        HardforkRegime::PreAllegretto => dealing.verify_pre_allegretto(ceremony::OUTCOME_NAMESPACE),
        HardforkRegime::PostAllegretto => dealing.verify(ceremony::OUTCOME_NAMESPACE),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum HardforkRegime {
    PreAllegretto,
    PostAllegretto,
}
