use tempo_evm::{ProtocolFeeContext, ProtocolFeeManager};

#[test]
fn protocol_fee_context_is_available_to_consumers() {
    fn assert_reexport(
        _ctx: Option<ProtocolFeeContext<'_, '_>>,
        _manager: Option<&dyn ProtocolFeeManager>,
    ) {
    }

    assert_reexport(None, None);
}
