#[macro_export]
macro_rules! dispatch_view_call {
    ($contract:expr, $selector:expr, $call_type:ty, $method:ident, $gas:expr) => {{
        if $selector == <$call_type>::SELECTOR {
            let result = $contract.$method();

            return Ok(PrecompileOutput::new(
                $gas,
                <$call_type>::abi_encode_returns(&result).into(),
            ));
        }
    }};
    ($contract:expr, $selector:expr, $call_type:ty, $method:ident, $calldata:expr, $gas:expr) => {{
        if $selector == <$call_type>::SELECTOR {
            let call = <$call_type>::abi_decode($calldata)
                .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;

            let result = $contract.$method(call);

            return Ok(PrecompileOutput::new(
                $gas,
                <$call_type>::abi_encode_returns(&result).into(),
            ));
        }
    }};
}

#[macro_export]
macro_rules! dispatch_mutating_call {
    // Version for calls that return a value with custom error type
    ($contract:expr, $selector:expr, $call_type:ty, $method:ident, $calldata:expr, $msg_sender:expr, $gas:expr, $error_type:ty, returns) => {{
        if $selector == <$call_type>::SELECTOR {
            let call = <$call_type>::abi_decode($calldata)
                .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;

            match $contract.$method($msg_sender, call) {
                Ok(retval) => {
                    return Ok(PrecompileOutput::new(
                        $gas,
                        <$call_type>::abi_encode_returns(&retval).into(),
                    ));
                }
                Err(e) => {
                    return Err(PrecompileError::Other(
                        <$error_type as ::alloy::sol_types::SolInterface>::abi_encode(&e)
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect(),
                    ));
                }
            }
        }
    }};

    // Version for calls that return nothing with custom error type
    ($contract:expr, $selector:expr, $call_type:ty, $method:ident, $calldata:expr, $msg_sender:expr, $gas:expr, $error_type:ty) => {{
        if $selector == <$call_type>::SELECTOR {
            let call = <$call_type>::abi_decode($calldata)
                .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;

            match $contract.$method($msg_sender, call) {
                Ok(()) => {
                    return Ok(PrecompileOutput::new($gas, alloy_primitives::Bytes::new()));
                }
                Err(e) => {
                    return Err(PrecompileError::Other(
                        <$error_type as ::alloy::sol_types::SolInterface>::abi_encode(&e)
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect(),
                    ));
                }
            }
        }
    }};
}
