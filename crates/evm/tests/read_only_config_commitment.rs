//! Account config commitments through the read-only storage context.

use alloy_primitives::{Address, B256};
use evm2::evm::{AccountExtension, AccountInfo, InMemoryDB};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{ConfigCommitmentWriteGas, StorageActions, StorageCtx},
};
use tempo_primitives::account::encode_config_commitment;

const ACCOUNT: Address = Address::repeat_byte(1);
const COMMITMENT: B256 = B256::repeat_byte(2);

#[test]
fn read_only_context_reads_commitments_and_rejects_writes() {
    let mut info = AccountInfo::empty();
    info.extension = AccountExtension::from(encode_config_commitment(COMMITMENT));
    let mut db = InMemoryDB::default();
    db.insert_account_info(&ACCOUNT, info);

    db.with_read_only_storage_ctx(TempoHardfork::T14, StorageActions::disabled(), || {
        let mut ctx = StorageCtx;
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), COMMITMENT);
        assert_eq!(
            ctx.config_commitment(Address::repeat_byte(9)).unwrap(),
            B256::ZERO
        );

        for gas in [
            ConfigCommitmentWriteGas::Intrinsic,
            ConfigCommitmentWriteGas::Precompile,
        ] {
            assert_eq!(
                ctx.set_config_commitment(ACCOUNT, B256::repeat_byte(3), gas),
                Err(TempoPrecompileError::InvalidConfigCommitmentWrite)
            );
        }
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), COMMITMENT);
    });
}
