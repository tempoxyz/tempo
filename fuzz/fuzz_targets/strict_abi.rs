#![no_main]

use alloy_sol_types::{SolCall, abi::AbiDecoderConfig};
use libfuzzer_sys::fuzz_target;
use tempo_contracts::precompiles::{
    IAccountKeychain, IReceivePolicyGuard, ITIP20ChannelReserve, IValidatorConfigV2, IZoneFactory,
    createTokenCall, createTokenWithLogoCall,
};

const DECODER_MEMORY_LIMIT: usize = 4 * 1024 * 1024;

fn assert_strict_call_roundtrip<T: SolCall>(bytes: &[u8]) {
    let config = AbiDecoderConfig::new()
        .strict(true)
        .memory_limit(DECODER_MEMORY_LIMIT);
    let Ok(call) = T::abi_decode_raw_with_config(bytes, config) else {
        return;
    };

    let mut reencoded = Vec::new();
    call.abi_encode_raw(&mut reencoded);
    assert_eq!(
        reencoded,
        bytes,
        "{}: strict decode accepted non-canonical ABI",
        T::SIGNATURE
    );
}

fuzz_target!(|bytes: &[u8]| {
    assert_strict_call_roundtrip::<IAccountKeychain::authorizeKey_1Call>(bytes);
    assert_strict_call_roundtrip::<IAccountKeychain::authorizeKey_2Call>(bytes);
    assert_strict_call_roundtrip::<IAccountKeychain::setAllowedCallsCall>(bytes);
    assert_strict_call_roundtrip::<IValidatorConfigV2::addValidatorCall>(bytes);
    assert_strict_call_roundtrip::<IValidatorConfigV2::rotateValidatorCall>(bytes);
    assert_strict_call_roundtrip::<IZoneFactory::createZoneCall>(bytes);
    assert_strict_call_roundtrip::<IReceivePolicyGuard::claimCall>(bytes);
    assert_strict_call_roundtrip::<ITIP20ChannelReserve::settleCall>(bytes);
    assert_strict_call_roundtrip::<ITIP20ChannelReserve::getChannelStatesBatchCall>(bytes);
    assert_strict_call_roundtrip::<createTokenCall>(bytes);
    assert_strict_call_roundtrip::<createTokenWithLogoCall>(bytes);
});
