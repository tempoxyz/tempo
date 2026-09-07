use tempo_evm::{ProtocolFeeContext, ProtocolFeeManager};

#[test]
fn protocol_fee_context_is_available_to_consumers() {
    fn assert_reexports<DB: revm::Database>(
        _ctx: Option<ProtocolFeeContext<'_, DB>>,
        _manager: Option<&dyn ProtocolFeeManager<DB>>,
    ) {
    }

    assert_reexports::<revm::database::EmptyDB>(None, None);
}
