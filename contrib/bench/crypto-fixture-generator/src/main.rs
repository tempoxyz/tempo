//! Deterministic ordinary fixtures only: no RPC, transaction sending or timing.
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use revm_precompile::{
    Precompiles,
    primitives::{hex, keccak256},
    u64_to_address,
};
use serde_json::{Value, json};

fn pad(bytes: &[u8], length: usize) -> Vec<u8> {
    assert!(bytes.len() <= length);
    let mut out = vec![0; length];
    out[length - bytes.len()..].copy_from_slice(bytes);
    out
}

fn field<F: PrimeField>(value: &F, length: usize) -> Vec<u8> {
    pad(&value.into_bigint().to_bytes_be(), length)
}

fn scalar<F: PrimeField>(label: &str) -> F {
    let result = F::from_be_bytes_mod_order(keccak256(label).as_slice());
    assert!(!result.is_zero());
    result
}

fn bls1(point: ark_bls12_381::G1Affine) -> Vec<u8> {
    assert!(!point.is_zero());
    [field(&point.x, 64), field(&point.y, 64)].concat()
}

fn bls2(point: ark_bls12_381::G2Affine) -> Vec<u8> {
    assert!(!point.is_zero());
    [
        field(&point.x.c0, 64),
        field(&point.x.c1, 64),
        field(&point.y.c0, 64),
        field(&point.y.c1, 64),
    ]
    .concat()
}

fn bn1(point: ark_bn254::G1Affine) -> Vec<u8> {
    assert!(!point.is_zero());
    [field(&point.x, 32), field(&point.y, 32)].concat()
}

fn bn2(point: ark_bn254::G2Affine) -> Vec<u8> {
    assert!(!point.is_zero());
    // Ethereum BN254 encoding is imaginary component first, unlike EIP-2537.
    [
        field(&point.x.c1, 32),
        field(&point.x.c0, 32),
        field(&point.y.c1, 32),
        field(&point.y.c0, 32),
    ]
    .concat()
}

fn output(address: u64, input: &[u8]) -> (Vec<u8>, u64) {
    assert!(input.len() <= 1024, "ordinary fixture size bound");
    let result = Precompiles::osaka()
        .get(&u64_to_address(address))
        .unwrap()
        .execute(input, 500_000, 0)
        .unwrap();
    assert!(result.status.is_success(), "precompile {address} failed");
    assert!(!result.bytes.is_empty());
    (result.bytes.to_vec(), result.gas_used)
}

fn add(
    rows: &mut Vec<Value>,
    name: &str,
    address: u64,
    input: Vec<u8>,
    expected: Vec<u8>,
    oracle: &str,
) {
    let (actual, gas) = output(address, &input);
    assert_eq!(actual, expected, "{name} result mismatch");
    rows.push(json!({
        "name": name, "address": format!("{}", u64_to_address(address)),
        "input": format!("0x{}", hex::encode(input)),
        "expected": format!("0x{}", hex::encode(expected)),
        "operation_gas": gas, "fork": "Osaka", "oracle": oracle,
        "source": "revm-precompile 42.0.1; deterministic valid fixture, not a timing result"
    }));
}

fn main() {
    let mut rows = Vec::new();
    let message = keccak256("Tempo ordinary calibration fixture v1");

    // Public, fixed test keys only. Never use these keys for funds or identity.
    let signing = k256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let (signature, recovery) = signing
        .sign_prehash_recoverable(message.as_slice())
        .unwrap();
    let mut v = vec![0; 32];
    v[31] = 27 + recovery.to_byte();
    let public = signing.verifying_key().to_encoded_point(false);
    let address = keccak256(&public.as_bytes()[1..]);
    add(
        &mut rows,
        "ecrecover",
        1,
        [message.to_vec(), v, signature.to_bytes().to_vec()].concat(),
        pad(&address.as_slice()[12..], 32),
        "k256 recovered signer address",
    );

    let input: Vec<u8> = (0u8..=255).collect();
    for (name, address) in [("sha256-256", 2), ("ripemd160-256", 3), ("identity-256", 4)] {
        let (expected, _) = output(address, &input);
        add(
            &mut rows,
            name,
            address,
            input.clone(),
            expected,
            "pinned implementation consistency; independent hash fixtures also exist in GasCalibration",
        );
    }

    // Ordinary RSA-sized modular exponentiation, exponent 65537; no length tricks.
    let mut modulus_bytes = vec![0; 256];
    let mut base_bytes = vec![0; 256];
    for index in 0..8 {
        modulus_bytes[index * 32..(index + 1) * 32]
            .copy_from_slice(keccak256(format!("ordinary modulus {index}")).as_slice());
        base_bytes[index * 32..(index + 1) * 32]
            .copy_from_slice(keccak256(format!("ordinary base {index}")).as_slice());
    }
    modulus_bytes[0] |= 0x80;
    modulus_bytes[255] |= 1;
    let modulus = BigUint::from_bytes_be(&modulus_bytes);
    let base = BigUint::from_bytes_be(&base_bytes) % &modulus;
    let exponent = BigUint::from(65537u32);
    let input = [
        pad(&256u64.to_be_bytes(), 32),
        pad(&3u64.to_be_bytes(), 32),
        pad(&256u64.to_be_bytes(), 32),
        pad(&base.to_bytes_be(), 256),
        exponent.to_bytes_be(),
        modulus_bytes,
    ]
    .concat();
    add(
        &mut rows,
        "modexp-2048-e65537",
        5,
        input,
        pad(&base.modpow(&exponent, &modulus).to_bytes_be(), 256),
        "num-bigint modpow; odd 2048-bit modulus, not an RSA key claim",
    );

    let p = (ark_bn254::G1Affine::generator() * scalar::<ark_bn254::Fr>("bn p")).into_affine();
    let q = (ark_bn254::G1Affine::generator() * scalar::<ark_bn254::Fr>("bn q")).into_affine();
    let g2 = (ark_bn254::G2Affine::generator() * scalar::<ark_bn254::Fr>("bn g2")).into_affine();
    let s = scalar::<ark_bn254::Fr>("bn scalar");
    add(
        &mut rows,
        "bn254-add",
        6,
        [bn1(p), bn1(q)].concat(),
        bn1((p + q).into_affine()),
        "arkworks point addition",
    );
    add(
        &mut rows,
        "bn254-mul",
        7,
        [bn1(p), field(&s, 32)].concat(),
        bn1((p * s).into_affine()),
        "arkworks scalar multiplication",
    );
    add(
        &mut rows,
        "bn254-pairing-2",
        8,
        [bn1(p), bn2(g2), bn1(-p), bn2(g2)].concat(),
        pad(&[1], 32),
        "pairing cancellation identity; two nonzero pairs",
    );

    // Reuse the source-attributed standard BLAKE2b and correct KZG proof vectors.
    let fixed: Vec<Value> = serde_json::from_str(include_str!(
        "../../txgen/gas-calibration/crypto-fixtures.json"
    ))
    .unwrap();
    for row in fixed {
        let address = u64::from_str_radix(
            row["address"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap();
        add(
            &mut rows,
            row["name"].as_str().unwrap(),
            address,
            hex::decode(row["input"].as_str().unwrap()).unwrap(),
            hex::decode(row["expected"].as_str().unwrap()).unwrap(),
            row["case"].as_str().unwrap(),
        );
    }

    let p =
        (ark_bls12_381::G1Affine::generator() * scalar::<ark_bls12_381::Fr>("bls p")).into_affine();
    let q =
        (ark_bls12_381::G1Affine::generator() * scalar::<ark_bls12_381::Fr>("bls q")).into_affine();
    let r =
        (ark_bls12_381::G2Affine::generator() * scalar::<ark_bls12_381::Fr>("bls r")).into_affine();
    let t =
        (ark_bls12_381::G2Affine::generator() * scalar::<ark_bls12_381::Fr>("bls t")).into_affine();
    let s = scalar::<ark_bls12_381::Fr>("bls scalar");
    add(
        &mut rows,
        "bls-g1-add",
        11,
        [bls1(p), bls1(q)].concat(),
        bls1((p + q).into_affine()),
        "arkworks point addition",
    );
    add(
        &mut rows,
        "bls-g1-msm-1",
        12,
        [bls1(p), field(&s, 32)].concat(),
        bls1((p * s).into_affine()),
        "arkworks scalar multiplication; one term",
    );
    add(
        &mut rows,
        "bls-g2-add",
        13,
        [bls2(r), bls2(t)].concat(),
        bls2((r + t).into_affine()),
        "arkworks point addition",
    );
    add(
        &mut rows,
        "bls-g2-msm-1",
        14,
        [bls2(r), field(&s, 32)].concat(),
        bls2((r * s).into_affine()),
        "arkworks scalar multiplication; one term",
    );
    add(
        &mut rows,
        "bls-pairing-2",
        15,
        [bls1(p), bls2(r), bls1(-p), bls2(r)].concat(),
        pad(&[1], 32),
        "pairing cancellation identity; two nonzero pairs",
    );

    let fp = scalar::<ark_bls12_381::Fq>("map fp");
    let fp2 = scalar::<ark_bls12_381::Fq>("map fp2");
    for (name, address, input) in [
        ("bls-map-g1", 16, field(&fp, 64)),
        ("bls-map-g2", 17, [field(&fp, 64), field(&fp2, 64)].concat()),
    ] {
        let (expected, _) = output(address, &input);
        if address == 16 {
            assert_eq!(expected.len(), 128);
            let point = ark_bls12_381::G1Affine::new_unchecked(
                ark_bls12_381::Fq::from_be_bytes_mod_order(&expected[..64]),
                ark_bls12_381::Fq::from_be_bytes_mod_order(&expected[64..]),
            );
            assert!(
                !point.is_zero()
                    && point.is_on_curve()
                    && point.is_in_correct_subgroup_assuming_on_curve()
            );
        } else {
            assert_eq!(expected.len(), 256);
            let fields: Vec<_> = expected
                .as_chunks::<64>()
                .0
                .iter()
                .map(|chunk| ark_bls12_381::Fq::from_be_bytes_mod_order(chunk))
                .collect();
            let point = ark_bls12_381::G2Affine::new_unchecked(
                ark_bls12_381::Fq2::new(fields[0], fields[1]),
                ark_bls12_381::Fq2::new(fields[2], fields[3]),
            );
            assert!(
                !point.is_zero()
                    && point.is_on_curve()
                    && point.is_in_correct_subgroup_assuming_on_curve()
            );
        }
        add(
            &mut rows,
            name,
            address,
            input,
            expected,
            "pinned map output; independently checked nonzero/on-curve/subgroup with arkworks, not an independent exact map oracle",
        );
    }

    let signing = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
    let signature: p256::ecdsa::Signature = signing.sign_prehash(message.as_slice()).unwrap();
    let public = signing.verifying_key().to_encoded_point(false);
    add(
        &mut rows,
        "p256verify",
        256,
        [
            message.to_vec(),
            signature.to_bytes().to_vec(),
            public.as_bytes()[1..].to_vec(),
        ]
        .concat(),
        pad(&[1], 32),
        "p256 signed prehash and matching public key",
    );

    assert_eq!(rows.len(), 18);
    let addresses: std::collections::BTreeSet<_> = rows
        .iter()
        .map(|r| r["address"].as_str().unwrap().to_owned())
        .collect();
    let registered: std::collections::BTreeSet<_> = Precompiles::osaka()
        .addresses()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        addresses, registered,
        "fixture set must exactly cover pinned Osaka precompiles"
    );
    println!("{}", serde_json::to_string_pretty(&rows).unwrap());
}
