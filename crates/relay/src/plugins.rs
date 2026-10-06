//! Small request plugins usable without a fee-payer signer.

use crate::{Backend, Next, Plugin, Request, RpcError};
use alloy_primitives::Address;
use async_trait::async_trait;
use serde_json::{Map, Value, json};

/// Sets a configured development fee token only when the caller omitted one.
pub struct FeeToken(pub Address);

#[async_trait]
impl Plugin for FeeToken {
    async fn handle(&self, mut request: Request, next: Next<'_>) -> Result<Value, RpcError> {
        if request.method != "eth_fillTransaction" {
            return next.run(request).await;
        }
        let transaction = request.transaction_mut()?;
        let token = transaction
            .get("feeToken")
            .filter(|token| !token.is_null())
            .cloned()
            .unwrap_or_else(|| json!(self.0));
        if transaction.get("feePayer") != Some(&json!(true)) {
            transaction.insert("feeToken".into(), token.clone());
        }
        let mut result = next.run(request).await?;
        if let Some(transaction) = result.get_mut("tx").and_then(Value::as_object_mut)
            && transaction.get("feeToken").is_none_or(Value::is_null)
        {
            transaction.insert("feeToken".into(), token);
        }
        Ok(result)
    }
}

/// Re-estimates the finalized fill before signing, propagating execution errors.
/// This is a preflight check, not viem's balance-diff simulation capability.
pub struct Preflight;

#[async_trait]
impl Plugin for Preflight {
    async fn after_fill(
        &self,
        request: &Request,
        filled: &Value,
        backend: &dyn Backend,
    ) -> Result<Map<String, Value>, RpcError> {
        let mut transaction = filled["tx"].clone();
        for field in ["keyType", "keyId", "keyData"] {
            if let Some(value) = request.transaction()?.get(field) {
                transaction[field] = value.clone();
            }
        }
        if transaction.get("from").is_none() {
            transaction["from"] = request
                .transaction()?
                .get("from")
                .cloned()
                .unwrap_or(Value::Null);
        }
        if request.transaction()?.get("feePayer") == Some(&json!(true)) {
            // Before signing, the node cannot recover the fee payer. Estimate with
            // zero fees rather than charging the unfunded sender; this checks
            // execution only, not sponsor solvency or fee-dependent behavior.
            transaction["maxFeePerGas"] = json!("0x0");
            transaction["maxPriorityFeePerGas"] = json!("0x0");
            transaction
                .as_object_mut()
                .expect("validated fill")
                .remove("gasPrice");
        }
        backend
            .request(Request::new("eth_estimateGas", vec![transaction]))
            .await?;
        Ok(Map::new())
    }
}
