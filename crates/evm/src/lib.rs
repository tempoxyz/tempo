use alloy_primitives::Address;
use reth::revm::{
    Inspector,
    context::{
        TxEnv,
        result::{EVMError, HaltReason},
    },
    inspector::NoOpInspector,
    primitives::hardfork::SpecId,
};
use reth_evm::{
    Database, EthEvm, EthEvmFactory, Evm, EvmEnv, EvmFactory,
    eth::EthEvmContext,
    precompiles::{DynPrecompile, PrecompilesMap},
};
use tempo_precompiles::{
    contracts::{
        ERC20Factory, ERC20Token, EvmStorageProvider, TIP403Registry,
        utils::{
            FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, address_is_token_address,
            address_to_token_id_unchecked,
        },
    },
    precompiles::Precompile,
};

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoEvmFactory {
    inner: EthEvmFactory,
}

impl TempoEvmFactory {
    fn customize_evm<DB: Database, I: Inspector<EthEvmContext<DB>>>(
        &self,
        evm: &mut EthEvm<DB, I, PrecompilesMap>,
    ) {
        if evm.cfg.spec >= SpecId::PRAGUE {
            let chain_id = evm.cfg.chain_id;

            let precompiles = evm.precompiles_mut();

            precompiles.set_precompile_lookup(move |address: &Address| match address {
                a if address_is_token_address(a) => {
                    let token_id = address_to_token_id_unchecked(a);
                    Some(DynPrecompile::new(move |input| {
                        ERC20Token::new(
                            token_id,
                            &mut EvmStorageProvider::new(input.internals, chain_id),
                        )
                        .call(input.data, &input.caller)
                    }))
                }
                a if *a == FACTORY_ADDRESS => Some(DynPrecompile::new(move |input| {
                    ERC20Factory::new(&mut EvmStorageProvider::new(input.internals, chain_id))
                        .call(input.data, &input.caller)
                })),
                a if *a == TIP403_REGISTRY_ADDRESS => Some(DynPrecompile::new(move |input| {
                    TIP403Registry::new(&mut EvmStorageProvider::new(input.internals, chain_id))
                        .call(input.data, &input.caller)
                })),
                _ => None,
            });
        }
    }
}

impl EvmFactory for TempoEvmFactory {
    type Evm<DB: Database, I: Inspector<Self::Context<DB>>> = EthEvm<DB, I, PrecompilesMap>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = TxEnv;
    type Error<DBError: std::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        evm_env: EvmEnv<Self::Spec>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let mut evm = self.inner.create_evm(db, evm_env);
        self.customize_evm(&mut evm);
        evm
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let mut evm = self.inner.create_evm_with_inspector(db, input, inspector);
        self.customize_evm(&mut evm);
        evm
    }
}
