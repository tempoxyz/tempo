use alloy::primitives::{Address, Bytes, U256};
use alloy_evm::{
    EthEvmFactory, EvmEnv, EvmFactory, EvmInternals,
    precompiles::{Precompile as AlloyEvmPrecompile, PrecompileInput},
};
use revm::{
    context::{CfgEnv, ContextTr, TxEnv},
    database::{CacheDB, EmptyDB},
    precompile::{PrecompileOutput, PrecompileResult},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{Precompile, tempo_precompile};

#[derive(Default)]
struct ExternalPrecompile;

impl Precompile for ExternalPrecompile {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        Ok(PrecompileOutput::new(
            0,
            Bytes::copy_from_slice(calldata),
            0,
        ))
    }
}

#[test]
fn exported_tempo_precompile_macro_builds_from_external_crate() {
    let cfg = CfgEnv::<TempoHardfork>::default();
    let precompile = tempo_precompile!("ExternalPrecompile", &cfg, |_input| { ExternalPrecompile });

    let db = CacheDB::new(EmptyDB::new());
    let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
    let block = evm.block.clone();
    let tx = TxEnv::default();
    let internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);

    let calldata = Bytes::from_static(b"tempo");
    let input = PrecompileInput {
        data: &calldata,
        caller: Address::ZERO,
        internals,
        gas: 0,
        value: U256::ZERO,
        is_static: false,
        target_address: Address::ZERO,
        bytecode_address: Address::ZERO,
        reservoir: 0,
    };

    let output = AlloyEvmPrecompile::call(&precompile, input).expect("precompile call succeeds");
    assert_eq!(output.bytes, calldata);
}
