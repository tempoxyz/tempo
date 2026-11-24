use tempo_evm::{
    ExpiringNonce, ExpiringNonceManager, ProtocolFeeContext, ProtocolFeeManager,
    TempoExpiringNonceManager,
};

#[test]
fn protocol_fee_context_is_available_to_consumers() {
    fn assert_reexport(
        _ctx: Option<ProtocolFeeContext<'_, '_>>,
        _manager: Option<&dyn ProtocolFeeManager>,
        _nonce: Option<ExpiringNonce>,
        _nonce_manager: Option<&dyn ExpiringNonceManager>,
        _default_nonce_manager: TempoExpiringNonceManager,
    ) {
    }

    assert_reexport(None, None, None, None, TempoExpiringNonceManager::new());
}
