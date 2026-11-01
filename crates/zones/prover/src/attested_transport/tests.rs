use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair},
};
use minicbor::Encoder;
use rcgen::{
    BasicConstraints, CertifiedIssuer, DnType, IsCa, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
};

use super::*;

// A real signed COSE document and P-384 certificate chain, trusted only by these private tests.
// Production always uses AWS_NITRO_ROOT_DER; no test verifier or alternate root is exposed.
struct TestNsm {
    root: Vec<u8>,
    leaf: Vec<u8>,
    key: EcdsaKeyPair,
}

impl TestNsm {
    fn new() -> Self {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test NSM root");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = CertifiedIssuer::self_signed(
            params,
            KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
        )
        .unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test NSM signer");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf = params.signed_by(&key, &root).unwrap().der().to_vec();
        Self {
            root: root.der().to_vec(),
            leaf,
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &key.serialize_der())
                .unwrap(),
        }
    }

    fn server(self: &Arc<Self>) -> AttestedServer {
        let nsm = self.clone();
        AttestedServer::new(move |nonce, binding| {
            Ok(nsm.attest(nonce, binding, UnixTime::now().as_secs() * 1000, 0x11))
        })
        .unwrap()
    }

    /// Signed NSM attestation document: COSE_Sign1 over the CBOR payload, using ES384.
    fn attest(&self, nonce: &[u8], binding: &[u8], timestamp: u64, pcr: u8) -> Vec<u8> {
        let payload = cbor(|p| {
            p.map(8)?;
            p.str("module_id")?.str("test-enclave")?;
            p.str("digest")?.str("SHA384")?;
            p.str("timestamp")?.u64(timestamp)?;
            p.str("pcrs")?.map(3)?;
            for index in 0..=2u8 {
                p.u8(index)?.bytes(&[pcr; SHA384_SIZE])?;
            }
            p.str("certificate")?.bytes(&self.leaf)?;
            p.str("cabundle")?.array(1)?.bytes(&self.root)?;
            p.str("nonce")?.bytes(nonce)?;
            p.str("user_data")?.bytes(binding)
        });
        // Protected header {alg: ES384 (ECDSA P-384 + SHA-384, COSE id -35)}.
        let protected = cbor(|p| p.map(1)?.u8(1)?.i8(-35));
        let sig_structure = cbor(|p| {
            p.array(4)?.str("Signature1")?.bytes(&protected)?;
            p.bytes(&[])?.bytes(&payload)
        });
        let signature = self
            .key
            .sign(&SystemRandom::new(), &sig_structure)
            .expect("ECDSA P-384 signing");
        cbor(|p| {
            p.array(4)?.bytes(&protected)?.map(0)?;
            p.bytes(&payload)?.bytes(signature.as_ref())
        })
    }
}

fn cbor<E: std::fmt::Debug>(
    encode: impl FnOnce(&mut Encoder<Vec<u8>>) -> Result<&mut Encoder<Vec<u8>>, E>,
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encode(&mut encoder).expect("encoding into a Vec cannot fail");
    encoder.into_writer()
}

fn policy() -> Policy {
    Policy {
        pcrs: (0..=2)
            .map(|i| (i, vec![FixedBytes::repeat_byte(0x11)]))
            .collect(),
        max_age_seconds: 300,
    }
}

#[tokio::test]
async fn authenticates_then_exchanges_prover_frames_with_a_reused_certificate() {
    let nsm = Arc::new(TestNsm::new());
    let server = nsm.server();
    // Same certificate, two independent nonce challenges and full TLS handshakes.
    for _ in 0..2 {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let serve = async {
            let tls = server.accept(server_io).await.unwrap();
            let mut connection = crate::ProverConnection::new(tls, 1024);
            assert_eq!(
                connection.receive::<String>().await.unwrap().unwrap(),
                "private witness"
            );
            connection.send("proof".to_owned()).await.unwrap();
        };
        let request = async {
            let tls = connect_stream(client_io, &policy(), &nsm.root)
                .await
                .unwrap();
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                tls.get_ref().1.peer_certificates().unwrap()[0],
                server.certificate
            );
            let mut connection = crate::ProverConnection::new(tls, 1024);
            connection.send("private witness".to_owned()).await.unwrap();
            assert_eq!(
                connection.receive::<String>().await.unwrap().unwrap(),
                "proof"
            );
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serve, request);
        })
        .await
        .unwrap();
    }
}

#[test]
fn verifies_signatures_root_freshness_nonce_certificate_context_and_pcrs() {
    let nsm = TestNsm::new();
    let now = UnixTime::now().as_secs();
    let nonce = [3; 32];
    let cert = b"certificate";
    let binding = certificate_binding(cert);
    let valid = nsm.attest(&nonce, &binding, now * 1000, 0x11);
    let verify = |doc: &[u8], cert: &[u8], nonce: &[u8]| {
        verify_evidence(doc, cert, nonce, &policy(), &nsm.root, now)
    };
    verify(&valid, cert, &nonce).unwrap();
    assert!(verify(&valid, cert, &[4; 32]).is_err());
    assert!(verify(&valid, b"substituted certificate", &nonce).is_err());
    assert!(verify_evidence(&valid, cert, &nonce, &policy(), AWS_NITRO_ROOT_DER, now).is_err());
    for (data, time, pcr, expected) in [
        (binding, (now - 300) * 1000, 0x11, true),
        (binding, (now + 300) * 1000, 0x11, true),
        (binding, (now - 301) * 1000, 0x11, false),
        (binding, (now + 301) * 1000, 0x11, false),
        (binding, now * 1000, 0x12, false),
        (binding, now * 1000, 0, false),
        (Sha256::digest(cert).into(), now * 1000, 0x11, false),
    ] {
        let result = verify(&nsm.attest(&nonce, &data, time, pcr), cert, &nonce);
        assert_eq!(result.is_ok(), expected, "{time}/{pcr}: {result:?}");
    }
    let mut tampered = valid;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(verify(&tampered, cert, &nonce).is_err());
}

#[tokio::test]
async fn attestation_does_not_replace_tls_key_possession() {
    let nsm = Arc::new(TestNsm::new());
    let legitimate = nsm.server();
    let impostor = nsm.server();
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
    let serve = async {
        let mut hello = [0; MAGIC.len() + NONCE_LEN];
        server_io.read_exact(&mut hello).await.unwrap();
        let doc = nsm.attest(
            &hello[MAGIC.len()..],
            &certificate_binding(&legitimate.certificate),
            UnixTime::now().as_secs() * 1000,
            0x11,
        );
        verify_evidence(
            &doc,
            &legitimate.certificate,
            &hello[MAGIC.len()..],
            &policy(),
            &nsm.root,
            UnixTime::now().as_secs(),
        )
        .unwrap();
        write_frame(&mut server_io, &legitimate.certificate, MAX_CERT_BYTES)
            .await
            .unwrap();
        write_frame(&mut server_io, &doc, MAX_DOCUMENT_SIZE)
            .await
            .unwrap();
        // Valid evidence relayed from another enclave cannot authenticate our different TLS key.
        assert!(impostor.acceptor.accept(server_io).await.is_err());
    };
    let request = async {
        assert!(
            connect_stream(client_io, &policy(), &nsm.root)
                .await
                .is_err()
        );
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serve, request);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejects_invalid_evidence_before_sending_tls_or_witness_bytes() {
    let nsm = Arc::new(TestNsm::new());
    let server = nsm.server();
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let serve = async {
        let mut hello = [0; MAGIC.len() + NONCE_LEN];
        peer.read_exact(&mut hello).await.unwrap();
        write_frame(&mut peer, &server.certificate, MAX_CERT_BYTES)
            .await
            .unwrap();
        write_frame(&mut peer, &[0], MAX_DOCUMENT_SIZE)
            .await
            .unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    };
    let request = async {
        assert!(connect_stream(client, &policy(), &nsm.root).await.is_err());
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serve, request);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejects_plaintext_and_oversized_bootstrap_frames() {
    let nsm = Arc::new(TestNsm::new());
    let server = nsm.server();
    let (mut client, peer) = tokio::io::duplex(64);
    client.write_all(&[0; 8]).await.unwrap();
    assert!(server.accept(peer).await.is_err());
    for length in [0, MAX_CERT_BYTES as u32 + 1, u32::MAX] {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_u32(length).await.unwrap();
        assert!(read_frame(&mut reader, MAX_CERT_BYTES).await.is_err());
    }
}

#[test]
fn rejects_incomplete_zero_and_malformed_measurement_policies() {
    let pcr = "11".repeat(48);
    let valid = serde_json::json!({"pcrs":{"0":[&pcr],"1":[&pcr],"2":[&pcr]}});
    let mut cases = vec![
        (valid.clone(), true),
        (serde_json::json!({"pcrs":{}}), false),
        (serde_json::json!({"pcrs":{"0":["invalid"]}}), false),
    ];
    for (index, values) in [
        ("0", serde_json::json!(["00".repeat(48)])),
        ("0", serde_json::json!([])),
        ("32", serde_json::json!([&pcr])),
    ] {
        let mut json = valid.clone();
        json["pcrs"][index] = values;
        cases.push((json, false));
    }
    let mut zero_age = valid;
    zero_age["max_age_seconds"] = serde_json::json!(0);
    cases.push((zero_age, false));
    for (json, expected) in cases {
        let result = RemoteProverConfig::from_policy_json(
            "localhost:5000".into(),
            &serde_json::to_vec(&json).unwrap(),
        );
        assert_eq!(result.is_ok(), expected, "policy: {json}: {result:?}");
    }
}
