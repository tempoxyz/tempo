use tempo_evm::ProtocolFeeManager;

#[test]
fn protocol_fee_manager_is_available_to_consumers() {
    fn assert_reexport(_manager: Option<&dyn ProtocolFeeManager>) {}

    assert_reexport(None);
}
