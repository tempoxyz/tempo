//! ABI encoding utilities for test vectors.
//!
//! Provides dynamic ABI encoding from function signatures and JSON arguments,
//! allowing test vectors to use human-readable function calls instead of raw hex.

use alloy_dyn_abi::{DynSolType, DynSolValue, JsonAbiExt, Specifier};
use alloy_json_abi::Function;
use alloy_primitives::Bytes;
use eyre::{Result, bail, eyre};

/// Encode a function call from its signature and JSON arguments.
///
/// # Arguments
///
/// * `signature` - Function signature (e.g., "createToken(string,string,string,address,address,bytes32)")
/// * `args` - JSON array of argument values
///
/// # Returns
///
/// ABI-encoded calldata: 4-byte selector + encoded arguments
///
/// # Example
///
/// ```ignore
/// let calldata = encode_call(
///     "createToken(string,string,string,address,address,bytes32)",
///     &[
///         json!("Test Token"),
///         json!("TEST"),
///         json!("USD"),
///         json!("0x20C0000000000000000000000000000000000000"),
///         json!("0x1111111111111111111111111111111111111111"),
///         json!("0x0000000000000000000000000000000000000000000000000000000000000001"),
///     ],
/// )?;
/// ```
pub fn encode_call(signature: &str, args: &[serde_json::Value]) -> Result<Bytes> {
    let func = Function::parse(signature)
        .map_err(|e| eyre!("failed to parse function signature '{}': {}", signature, e))?;

    if args.len() != func.inputs.len() {
        bail!(
            "argument count mismatch: signature has {} params, got {} args",
            func.inputs.len(),
            args.len()
        );
    }

    let values: Vec<DynSolValue> = func
        .inputs
        .iter()
        .zip(args)
        .map(|(param, v)| {
            let ty: DynSolType = param
                .resolve()
                .map_err(|e| eyre!("failed to resolve param type '{}': {}", param.ty, e))?;
            json_to_dyn_value(&ty, v)
        })
        .collect::<Result<_>>()?;

    let calldata = func
        .abi_encode_input(&values)
        .map_err(|e| eyre!("failed to encode call: {}", e))?;

    Ok(Bytes::from(calldata))
}

/// Convert a JSON value to a [`DynSolValue`], constructing compound types directly
/// and using `coerce_str` for scalar leaves.
fn json_to_dyn_value(ty: &DynSolType, v: &serde_json::Value) -> Result<DynSolValue> {
    match ty {
        DynSolType::Tuple(elems) => {
            let arr = v
                .as_array()
                .ok_or_else(|| eyre!("expected array for tuple, got {:?}", v))?;
            if arr.len() != elems.len() {
                bail!(
                    "tuple requires {} elements, got {}",
                    elems.len(),
                    arr.len()
                );
            }
            let inner = elems
                .iter()
                .zip(arr)
                .map(|(t, vv)| json_to_dyn_value(t, vv))
                .collect::<Result<_>>()?;
            Ok(DynSolValue::Tuple(inner))
        }
        DynSolType::Array(inner) => {
            let arr = v
                .as_array()
                .ok_or_else(|| eyre!("expected array, got {:?}", v))?;
            let values = arr
                .iter()
                .map(|vv| json_to_dyn_value(inner, vv))
                .collect::<Result<_>>()?;
            Ok(DynSolValue::Array(values))
        }
        DynSolType::FixedArray(inner, n) => {
            let arr = v
                .as_array()
                .ok_or_else(|| eyre!("expected array, got {:?}", v))?;
            if arr.len() != *n {
                bail!("fixed array requires {} elements, got {}", n, arr.len());
            }
            let values = arr
                .iter()
                .map(|vv| json_to_dyn_value(inner, vv))
                .collect::<Result<_>>()?;
            Ok(DynSolValue::FixedArray(values))
        }
        DynSolType::String => {
            let s = v
                .as_str()
                .ok_or_else(|| eyre!("expected string, got {:?}", v))?;
            Ok(DynSolValue::String(s.to_owned()))
        }
        _ => {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => bail!("unsupported JSON value for type {}: {:?}", ty, v),
            };
            ty.coerce_str(&s)
                .map_err(|e| eyre!("failed to coerce '{}' as {}: {}", s, ty, e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use serde_json::json;

    #[test]
    fn test_encode_call_simple() {
        let calldata = encode_call(
            "transfer(address,uint256)",
            &[
                json!("0x1111111111111111111111111111111111111111"),
                json!("1000"),
            ],
        )
        .unwrap();

        assert_eq!(hex::encode(&calldata[..4]), "a9059cbb");
        assert_eq!(calldata.len(), 68);
    }

    #[test]
    fn test_encode_call_no_args() {
        let calldata = encode_call("totalSupply()", &[]).unwrap();
        assert_eq!(calldata.len(), 4);
    }

    #[test]
    fn test_encode_call_with_strings() {
        let calldata = encode_call(
            "createToken(string,string,string,address,address,bytes32)",
            &[
                json!("Test Token"),
                json!("TEST"),
                json!("USD"),
                json!("0x20C0000000000000000000000000000000000000"),
                json!("0x1111111111111111111111111111111111111111"),
                json!("0x0000000000000000000000000000000000000000000000000000000000000001"),
            ],
        )
        .unwrap();

        assert_eq!(hex::encode(&calldata[..4]), "68130445");
    }

    #[test]
    fn test_encode_call_arg_count_mismatch() {
        let result = encode_call(
            "transfer(address,uint256)",
            &[json!("0x1111111111111111111111111111111111111111")],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("argument count"));
    }

    #[test]
    fn test_encode_call_invalid_signature() {
        let result = encode_call("noparens", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_call_bool() {
        let calldata = encode_call(
            "setApproval(address,bool)",
            &[
                json!("0x1111111111111111111111111111111111111111"),
                json!(true),
            ],
        )
        .unwrap();

        assert_eq!(calldata.len(), 68);
    }

    #[test]
    fn test_encode_call_bytes() {
        let calldata = encode_call("execute(bytes)", &[json!("0xdeadbeef")]).unwrap();
        assert_eq!(calldata.len(), 100);
    }

    #[test]
    fn test_encode_call_array() {
        let calldata = encode_call(
            "batchTransfer(address[])",
            &[json!([
                "0x1111111111111111111111111111111111111111",
                "0x2222222222222222222222222222222222222222"
            ])],
        )
        .unwrap();

        assert_eq!(calldata.len(), 132);
    }

    #[test]
    fn test_encode_call_numeric_values() {
        let calldata = encode_call("setValue(uint256)", &[json!("12345")]).unwrap();
        assert_eq!(calldata.len(), 36);

        let calldata = encode_call("setValue(uint256)", &[json!("0xff")]).unwrap();
        assert_eq!(calldata.len(), 36);

        let calldata = encode_call("setValue(uint256)", &[json!(42)]).unwrap();
        assert_eq!(calldata.len(), 36);
    }

    #[test]
    fn test_encode_call_tuple() {
        let calldata = encode_call(
            "processOrder((address,uint256))",
            &[json!(["0x1111111111111111111111111111111111111111", "100"])],
        )
        .unwrap();

        assert_eq!(calldata.len(), 68);
    }
}
