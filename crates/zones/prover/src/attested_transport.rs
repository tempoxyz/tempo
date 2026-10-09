//! Fresh Nitro attestation followed by ordinary TLS 1.3, before any prover payload is sent.
//!
//! The plaintext bootstrap carries only a random challenge, certificate and attestation. The
//! measured enclave binds its own certificate (never a caller-supplied key) to that challenge.
//! Only after verification do we trust that certificate for TLS and expose the encrypted stream.

#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, io, path::Path, sync::Arc, time::Duration};

use alloy_primitives::FixedBytes;
use rcgen::{CertificateParams, KeyPair, date_time_ymd};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tempo_nitro_attestation::{AWS_NITRO_ROOT_DER, AwsLcP384, MAX_DOCUMENT_SIZE, SHA384_SIZE};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream,
    server::TlsStream as ServerTlsStream,
};

const MAGIC: &[u8; 8] = b"TZRATLS2";
const CONTEXT: &[u8] = b"tempo-zone-prover/tls-bootstrap/v1\0";
const SERVER_NAME: &str = "tempo-zone-prover.invalid";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CERT_BYTES: usize = 4096;
const MAX_POLICY_BYTES: usize = 64 * 1024;
const NONCE_LEN: usize = 32;
const DEFAULT_MAX_AGE_SECS: u64 = 300;
const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Approved deployment measurements; zero PCRs (Nitro debug mode) are never accepted.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Policy {
    pcrs: BTreeMap<u8, Vec<FixedBytes<SHA384_SIZE>>>,
    #[serde(default = "default_max_age_seconds")]
    max_age_seconds: u64,
}

fn default_max_age_seconds() -> u64 {
    DEFAULT_MAX_AGE_SECS
}

/// Remote prover address with a required, validated Nitro policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteProverConfig {
    address: String,
    policy: Policy,
}

impl RemoteProverConfig {
    pub fn from_policy_file(address: String, path: &Path) -> io::Result<Self> {
        Self::from_policy_json(address, &std::fs::read(path)?)
    }

    /// Parse a JSON PCR allowlist override for remote prover authentication.
    pub fn from_policy_json(address: String, bytes: &[u8]) -> io::Result<Self> {
        require(bytes.len() <= MAX_POLICY_BYTES, "invalid policy size")?;
        let policy = serde_json::from_slice(bytes).map_err(io::Error::other)?;
        Self::new(address, policy)
    }

    /// Use the exact PCR0/1/2 tuple approved by the Tempo verifier.
    pub fn from_pcrs(address: String, pcrs: [[u8; SHA384_SIZE]; 3]) -> io::Result<Self> {
        let policy = Policy {
            pcrs: pcrs
                .into_iter()
                .enumerate()
                .map(|(index, pcr)| (index as u8, vec![FixedBytes::from(pcr)]))
                .collect(),
            max_age_seconds: DEFAULT_MAX_AGE_SECS,
        };
        Self::new(address, policy)
    }

    fn new(address: String, policy: Policy) -> io::Result<Self> {
        require(!address.trim().is_empty(), "invalid prover address")?;
        require(
            policy.max_age_seconds > 0 && (0..=2).all(|i| policy.pcrs.contains_key(&i)),
            "policy must include PCR0-2 and positive freshness",
        )?;
        for (index, values) in &policy.pcrs {
            require(*index < 32 && !values.is_empty(), "invalid PCR allowlist")?;
            require(
                values.iter().all(|value| !value.is_zero()),
                "PCR must be a nonzero SHA-384 measurement",
            )?;
        }
        Ok(Self { address, policy })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    /// Authenticate before returning a stream on which witnesses can be sent.
    pub async fn connect(&self) -> io::Result<ClientTlsStream<TcpStream>> {
        timeout(HANDSHAKE_TIMEOUT, async {
            let stream = TcpStream::connect(&self.address).await?;
            connect_stream(stream, &self.policy, AWS_NITRO_ROOT_DER).await
        })
        .await?
    }
}

type Attester = dyn Fn(&[u8], &[u8]) -> io::Result<Vec<u8>> + Send + Sync;

/// One in-memory TLS key per enclave process. Construct only after configuring trusted entropy.
#[derive(Clone)]
pub struct AttestedServer {
    acceptor: TlsAcceptor,
    certificate: CertificateDer<'static>,
    attester: Arc<Attester>,
}

impl AttestedServer {
    /// `attester(nonce, user_data)` must return an NSM document containing both fields verbatim.
    pub fn new(
        attester: impl Fn(&[u8], &[u8]) -> io::Result<Vec<u8>> + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let mut params =
            CertificateParams::new(vec![SERVER_NAME.into()]).map_err(io::Error::other)?;
        // The enclave needs no wall clock. The client checks fresh NSM evidence on every connection.
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(9999, 12, 31);
        let certificate = params
            .self_signed(&key)
            .map_err(io::Error::other)?
            .der()
            .clone();
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .map_err(io::Error::other)?;
        // Every connection must prove key possession after its own attestation exchange.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            certificate,
            attester: Arc::new(attester),
        })
    }

    pub async fn accept<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: T,
    ) -> io::Result<ServerTlsStream<T>> {
        timeout(HANDSHAKE_TIMEOUT, async {
            let mut magic = [0; 8];
            stream.read_exact(&mut magic).await?;
            require(&magic == MAGIC, "invalid attestation bootstrap")?;
            let mut nonce = [0; NONCE_LEN];
            stream.read_exact(&mut nonce).await?;
            let binding = certificate_binding(&self.certificate);
            let attester = self.attester.clone();
            let evidence = tokio::task::spawn_blocking(move || attester(&nonce, &binding))
                .await
                .map_err(io::Error::other)??;
            write_frame(&mut stream, &self.certificate, MAX_CERT_BYTES).await?;
            write_frame(&mut stream, &evidence, MAX_DOCUMENT_SIZE).await?;
            stream.flush().await?;
            self.acceptor.accept(stream).await
        })
        .await?
    }
}

async fn connect_stream<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    policy: &Policy,
    root: &[u8],
) -> io::Result<ClientTlsStream<T>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut nonce = [0; NONCE_LEN];
    provider
        .secure_random
        .fill(&mut nonce)
        .map_err(|error| io::Error::other(rustls::Error::from(error)))?;
    stream.write_all(MAGIC).await?;
    stream.write_all(&nonce).await?;
    stream.flush().await?;
    let cert = read_frame(&mut stream, MAX_CERT_BYTES).await?;
    let evidence = read_frame(&mut stream, MAX_DOCUMENT_SIZE).await?;
    verify_evidence(
        &evidence,
        &cert,
        &nonce,
        policy,
        root,
        UnixTime::now().as_secs(),
    )?;

    // No system roots or permissive verifier: the only anchor is the attested enclave key.
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert))
        .map_err(io::Error::other)?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from(SERVER_NAME).expect("static DNS name"),
            stream,
        )
        .await
}

fn certificate_binding(certificate: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CONTEXT);
    hash.update(certificate);
    hash.finalize().into()
}

fn verify_evidence(
    evidence: &[u8],
    certificate: &[u8],
    nonce: &[u8],
    policy: &Policy,
    root: &[u8],
    now: u64,
) -> io::Result<()> {
    let doc = tempo_nitro_attestation::parse_attestation(evidence)
        .and_then(|parsed| tempo_nitro_attestation::verify_parsed(parsed, now, root, &AwsLcP384))
        .map_err(|error| io::Error::other(format!("invalid Nitro attestation: {error:?}")))?;
    require(
        doc.nonce == nonce && doc.user_data == certificate_binding(certificate),
        "attestation nonce or certificate binding mismatch",
    )?;
    let now_ms = now.saturating_mul(1000);
    require(
        doc.timestamp <= now_ms.saturating_add(MAX_FUTURE_SKEW_SECS * 1000)
            && now_ms.saturating_sub(doc.timestamp) <= policy.max_age_seconds.saturating_mul(1000),
        "attestation is stale or in the future",
    )?;
    for (index, allowed) in &policy.pcrs {
        require(
            doc.pcrs.iter().any(|pcr| {
                pcr.index == *index && allowed.iter().any(|a| a.as_slice() == pcr.value)
            }),
            "attestation PCR mismatch",
        )?;
    }
    Ok(())
}

fn require(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}

async fn read_frame<T: AsyncRead + Unpin>(stream: &mut T, maximum: usize) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    require(
        length > 0 && length <= maximum,
        "invalid bootstrap frame length",
    )?;
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame<T: AsyncWrite + Unpin>(
    stream: &mut T,
    bytes: &[u8],
    maximum: usize,
) -> io::Result<()> {
    require(
        !bytes.is_empty() && bytes.len() <= maximum,
        "invalid bootstrap frame length",
    )?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await
}
