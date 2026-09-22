use alloy_primitives::{Address, B256};
use alloy_rlp::Encodable;
use alloy_sol_types::SolCall;
use std::{fs, path::Path};
use tempo_contracts::precompiles::{IReceivePolicyGuard, IValidatorConfigV2, createTokenCall};
use tempo_primitives::{TempoHeader, TempoTransaction};

fn write_seed(corpus: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(corpus).expect("create fuzz corpus");
    fs::write(corpus.join(name), bytes).expect("write fuzz seed");
}

fn write_rlp_seed<T: Encodable>(corpus: &Path, name: &str, value: &T) {
    write_seed(corpus, name, &alloy_rlp::encode(value));
}

fn write_call_seed<T: SolCall>(corpus: &Path, name: &str, call: &T) {
    let encoded = call.abi_encode();
    write_seed(corpus, name, &encoded[4..]);
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory");
    let manifest_dir = Path::new(&manifest_dir);

    let rlp_corpus = manifest_dir.join("corpus/consensus-rlp");
    write_rlp_seed(&rlp_corpus, "tempo-header-default", &TempoHeader::default());
    write_rlp_seed(
        &rlp_corpus,
        "tempo-transaction-default",
        &TempoTransaction::default(),
    );

    let abi_corpus = manifest_dir.join("corpus/strict-abi");
    write_call_seed(
        &abi_corpus,
        "create-token-empty-strings",
        &createTokenCall {
            name: String::new(),
            symbol: String::new(),
            currency: String::new(),
            quoteToken: Address::ZERO,
            admin: Address::ZERO,
            salt: B256::ZERO,
        },
    );
    write_call_seed(
        &abi_corpus,
        "claim-empty-receipt",
        &IReceivePolicyGuard::claimCall {
            to: Address::ZERO,
            receipt: Vec::new().into(),
        },
    );
    write_call_seed(
        &abi_corpus,
        "add-validator-empty-fields",
        &IValidatorConfigV2::addValidatorCall {
            validatorAddress: Address::ZERO,
            publicKey: B256::ZERO,
            ingress: String::new(),
            egress: String::new(),
            feeRecipient: Address::ZERO,
            signature: Vec::new().into(),
        },
    );
}
