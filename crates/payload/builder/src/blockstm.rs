use alloy_primitives::Address;
use reth_evm::Database;
use tempo_evm::Tip20TransferBlockstmTx;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::TipFeeManager,
};
use tempo_transaction_pool::best::BestTransaction;

/// Builds an executor-owned BlockSTM candidate from a pooled transaction.
pub(crate) fn candidate(tx: &BestTransaction) -> Tip20TransferBlockstmTx<'_> {
    Tip20TransferBlockstmTx {
        tx_env: tx.transaction.clone_tx_env(),
        recovered: tx.transaction.inner(),
        fee_token: tx.transaction.effective_fee_token(),
    }
}

/// Reads the validator's preferred fee token from FeeManager storage.
pub(crate) fn validator_token<DB: Database>(
    db: &mut DB,
    beneficiary: Address,
) -> Result<Address, DB::Error> {
    let slot = TipFeeManager::new().validator_tokens[beneficiary].slot();
    let token = db.storage(TIP_FEE_MANAGER_ADDRESS, slot)?;
    if token.is_zero() {
        Ok(DEFAULT_FEE_TOKEN)
    } else {
        Ok(Address::from_word(token.into()))
    }
}
