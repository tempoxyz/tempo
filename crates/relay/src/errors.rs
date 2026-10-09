//! Viem-compatible execution error capabilities without converting transport failures.

use crate::RpcError;
use alloy_dyn_abi::{DynSolValue, ErrorExt};
use alloy_primitives::{Bytes, keccak256};
use serde_json::{Value, json};
use std::sync::OnceLock;

/// Decoded error and arguments retained for optimistic insufficient-funds previews.
pub struct ExecutionError {
    /// Wire-format capability, excluding non-JSON bigint arguments.
    pub rpc: Value,
    /// Typed ABI arguments.
    pub arguments: Vec<DynSolValue>,
}

/// Execution reverts only; auth, network and plugin errors must propagate unchanged.
pub fn is_execution(error: &RpcError) -> bool {
    error.code == 3
        || error
            .message
            .to_lowercase()
            .starts_with("execution reverted")
        || error
            .data
            .as_ref()
            .is_some_and(|value| nested_execution(value, 0))
}

fn nested_execution(value: &Value, depth: usize) -> bool {
    depth < 24
        && (value.get("code") == Some(&json!(3))
            || ["message", "details"].iter().any(|key| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|message| message.to_lowercase().starts_with("execution reverted"))
            })
            || ["cause", "error"].iter().any(|key| {
                value
                    .get(key)
                    .is_some_and(|value| nested_execution(value, depth + 1))
            }))
}

/// Decodes the pinned viem core ABI and human-readable error templates.
pub fn decode(error: &RpcError) -> ExecutionError {
    static CATALOG: OnceLock<Vec<Value>> = OnceLock::new();
    let catalog = CATALOG.get_or_init(|| {
        let mut catalog: Vec<Value> = serde_json::from_str(include_str!("errors.json")).expect("embedded viem error catalog");
        catalog.extend([
            json!({"abiItem": {"type": "error", "name": "Error", "inputs": [{"name": "message", "type": "string"}]}}),
            json!({"abiItem": {"type": "error", "name": "Panic", "inputs": [{"name": "reason", "type": "uint256"}]}}),
        ]);
        catalog
    });
    if let Some(data) = error.data.as_ref().and_then(revert_data)
        && data.len() >= 4
    {
        for entry in catalog {
            let Ok(abi) = serde_json::from_value::<alloy_json_abi::Error>(entry["abiItem"].clone())
            else {
                continue;
            };
            if keccak256(abi.signature())[..4] != data[..4] {
                continue;
            }
            let arguments = match abi.decode_error(&data) {
                Ok(decoded) => decoded.body,
                Err(_) if data.len() == 4 && entry.get("message").is_some() => Vec::new(),
                Err(_) => continue,
            };
            let mut message = entry["message"]
                .as_str()
                .unwrap_or_else(|| fallback_message(&error.message))
                .to_owned();
            for (index, argument) in arguments.iter().enumerate() {
                message = message.replace(&format!("{{{index}}}"), &display(argument));
            }
            return ExecutionError {
                rpc: json!({"errorName": abi.name, "abiItem": entry["abiItem"], "message": message, "data": data}),
                arguments,
            };
        }
    }
    let mut message = fallback_message(&error.message);
    if let Some((_, text)) = error.message.split_once(':')
        && let Some((name, arguments)) = text.trim().split_once('(')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        && let Some((arguments, _)) = arguments.split_once(')')
    {
        let matching = catalog
            .iter()
            .filter(|entry| entry["abiItem"]["name"] == name && entry.get("message").is_some())
            .collect::<Vec<_>>();
        let matched = if arguments.is_empty() {
            matching
                .iter()
                .find(|entry| {
                    entry["abiItem"]["inputs"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                })
                .copied()
        } else if matching.len() == 1 {
            matching.first().copied()
        } else {
            None
        };
        if let Some(template) = matched.and_then(|entry| entry["message"].as_str()) {
            message = template;
        }
    }
    ExecutionError {
        rpc: json!({"errorName": "unknown", "message": message}),
        arguments: Vec::new(),
    }
}

fn fallback_message(message: &str) -> &str {
    if message
        .get(..19)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("execution reverted:"))
    {
        message[19..].trim_start()
    } else {
        message
    }
}

fn revert_data(value: &Value) -> Option<Bytes> {
    if let Ok(bytes) = serde_json::from_value::<Bytes>(value.clone()) {
        return Some(bytes);
    }
    ["data", "cause", "error"]
        .iter()
        .find_map(|key| value.get(key).and_then(revert_data))
}

fn display(value: &DynSolValue) -> String {
    match value {
        DynSolValue::Uint(value, _) => value.to_string(),
        DynSolValue::Int(value, _) => value.to_string(),
        DynSolValue::Address(value) => value.to_checksum(None),
        DynSolValue::Bool(value) => value.to_string(),
        DynSolValue::String(value) => value.clone(),
        _ => format!("{value:?}"),
    }
}
