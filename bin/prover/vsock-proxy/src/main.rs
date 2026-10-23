//! TCP-to-VSOCK proxy for connections to the Zones prover enclave.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::{NonZeroU64, NonZeroUsize},
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use metrics::{Counter, Gauge, Histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use reth_metrics::Metrics;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{sleep, timeout},
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod metrics_io;

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "VSOCK proxy failed");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Parser, PartialEq)]
#[command(
    version,
    about = "Forward TCP connections to a VSOCK endpoint via the host transport"
)]
struct Cli {
    /// TCP port on which to accept connections.
    #[arg(value_name = "TCP_PORT")]
    listen_port: u16,

    /// Destination VSOCK context identifier.
    #[arg(value_name = "VSOCK_CID")]
    vsock_cid: u32,

    /// Destination VSOCK port.
    #[arg(value_name = "VSOCK_PORT")]
    vsock_port: u32,

    /// Maximum number of connections that may be active at once.
    #[arg(long, default_value = "256")]
    max_connections: NonZeroUsize,

    /// Maximum time to wait for a VSOCK connection, in seconds.
    #[arg(long, default_value = "10", value_name = "SECONDS")]
    connect_timeout_secs: NonZeroU64,

    /// Address for the Prometheus HTTP metrics listener.
    #[arg(long, default_value = "127.0.0.1:9100")]
    metrics_addr: SocketAddr,
}

impl Cli {
    async fn run(self) -> io::Result<()> {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.listen_port);
        let listener = TcpListener::bind(listen_addr).await?;
        PrometheusBuilder::new()
            .with_http_listener(self.metrics_addr)
            .set_buckets(&[0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0])
            .map_err(io::Error::other)?
            .install()
            .map_err(io::Error::other)?;
        let metrics = ProxyMetrics::default();
        metrics.active_connections.set(0.0);
        metrics
            .max_connections
            .set(self.max_connections.get() as f64);
        let connections = Arc::new(Semaphore::new(self.max_connections.get()));
        let connect_timeout = Duration::from_secs(self.connect_timeout_secs.get());

        info!(
            %listen_addr,
            metrics_addr = %self.metrics_addr,
            vsock_cid = self.vsock_cid,
            vsock_port = self.vsock_port,
            max_connections = self.max_connections.get(),
            connect_timeout_secs = self.connect_timeout_secs.get(),
            "Listening for TCP connections"
        );

        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    metrics.accept_errors_total.increment(1);
                    error!(%error, "Failed to accept TCP connection; retrying");
                    sleep(ACCEPT_RETRY_DELAY).await;
                    continue;
                }
            };

            metrics.accepted_connections_total.increment(1);
            let permit = match Arc::clone(&connections).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    metrics.rejected_connections_total.increment(1);
                    warn!(%peer, "Connection limit reached; rejecting client");
                    continue;
                }
            };
            metrics.active_connections.increment(1.0);
            let session = Session {
                _permit: permit,
                started: Instant::now(),
                metrics: metrics.clone(),
            };

            let cid = self.vsock_cid;
            let port = self.vsock_port;

            tokio::spawn(async move {
                if let Err(error) = proxy_connection(tcp, cid, port, session, connect_timeout).await
                {
                    error!(%peer, %error, "Connection failed");
                }
            });
        }
    }
}

#[derive(Metrics, Clone)]
#[metrics(scope = "vsock_proxy")]
struct ProxyMetrics {
    /// Accepted TCP connections, including rejected clients.
    accepted_connections_total: Counter,
    /// Clients rejected at the connection limit.
    rejected_connections_total: Counter,
    /// Successfully established VSOCK sessions.
    connected_connections_total: Counter,
    /// Sessions whose forwarding completed without error.
    completed_connections_total: Counter,
    /// Occupied connection slots, including connecting sessions.
    active_connections: Gauge,
    /// Configured connection limit.
    max_connections: Gauge,
    /// TCP accept failures.
    accept_errors_total: Counter,
    /// VSOCK setup failures, excluding timeouts.
    connect_errors_total: Counter,
    /// VSOCK setup timeouts.
    connect_timeouts_total: Counter,
    /// Bidirectional forwarding failures.
    forward_errors_total: Counter,
    /// Time awaiting VSOCK setup, including failures and timeouts.
    connect_duration_seconds: Histogram,
    /// Time holding a connection slot, including setup and failed sessions.
    session_duration_seconds: Histogram,
    /// Bytes successfully written to VSOCK, including partial transfers before errors.
    tcp_to_vsock_bytes_total: Counter,
    /// Bytes successfully written to TCP, including partial transfers before errors.
    vsock_to_tcp_bytes_total: Counter,
}

struct Session {
    _permit: OwnedSemaphorePermit,
    started: Instant,
    metrics: ProxyMetrics,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.metrics.active_connections.decrement(1.0);
        self.metrics
            .session_duration_seconds
            .record(self.started.elapsed().as_secs_f64());
    }
}

async fn proxy_connection(
    tcp: TcpStream,
    cid: u32,
    port: u32,
    session: Session,
    connect_timeout: Duration,
) -> io::Result<()> {
    // A timed-out blocking task cannot be cancelled, so move the permit into it to keep the
    // connection counted until connect_blocking returns. On success, the returned permit remains
    // held for the lifetime of the proxy session.
    let metrics = session.metrics.clone();
    let started = Instant::now();
    let result = timeout(
        connect_timeout,
        tokio::task::spawn_blocking(move || (connect_blocking(cid, port), session)),
    )
    .await;
    metrics
        .connect_duration_seconds
        .record(started.elapsed().as_secs_f64());
    let (mut vsock, _session) = result
        .map_err(|_| {
            metrics.connect_timeouts_total.increment(1);
            io::Error::new(io::ErrorKind::TimedOut, "VSOCK connection timed out")
        })?
        .map_err(io::Error::other)
        .and_then(|(stream, session)| Ok((tokio_vsock::VsockStream::new(stream?)?, session)))
        .inspect_err(|_| {
            metrics.connect_errors_total.increment(1);
        })?;
    metrics.connected_connections_total.increment(1);
    let mut tcp = metrics_io::MeteredStream {
        inner: tcp,
        bytes: metrics.vsock_to_tcp_bytes_total.clone(),
    };
    let mut vsock = metrics_io::MeteredStream {
        inner: &mut vsock,
        bytes: metrics.tcp_to_vsock_bytes_total.clone(),
    };
    copy_bidirectional(&mut tcp, &mut vsock)
        .await
        .inspect_err(|_| {
            metrics.forward_errors_total.increment(1);
        })?;
    metrics.completed_connections_total.increment(1);
    Ok(())
}

#[cfg(target_os = "linux")]
const VMADDR_FLAG_TO_HOST: u8 = 1;

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockAddrVm {
    family: libc::sa_family_t,
    reserved: libc::c_ushort,
    port: libc::c_uint,
    cid: libc::c_uint,
    flags: u8,
    zero: [u8; 3],
}

#[cfg(target_os = "linux")]
fn connect_blocking(cid: u32, port: u32) -> io::Result<vsock::VsockStream> {
    use std::{mem::size_of, os::fd::FromRawFd};

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let addr = SockAddrVm {
        family: libc::AF_VSOCK as libc::sa_family_t,
        reserved: 0,
        port,
        cid,
        flags: VMADDR_FLAG_TO_HOST,
        zero: [0; 3],
    };

    let result = unsafe {
        libc::connect(
            fd,
            &addr as *const SockAddrVm as *const libc::sockaddr,
            size_of::<SockAddrVm>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }

    Ok(unsafe { vsock::VsockStream::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn connect_blocking(_cid: u32, _port: u32) -> io::Result<vsock::VsockStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "VMADDR_FLAG_TO_HOST is supported only on Linux",
    ))
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timed_out_connect_keeps_slot_and_gauge_until_blocking_task_finishes() {
        let handle = PrometheusBuilder::new().install_recorder().unwrap();
        let connections = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&connections).try_acquire_owned().unwrap();
        let metrics = ProxyMetrics::default();
        metrics.active_connections.increment(1.0);
        let session = Session {
            _permit: permit,
            started: Instant::now(),
            metrics,
        };
        let (release, wait) = std::sync::mpsc::channel();
        let mut connect = tokio::task::spawn_blocking(move || {
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            session
        });
        assert!(
            timeout(Duration::from_millis(10), &mut connect)
                .await
                .is_err()
        );
        assert_eq!(connections.available_permits(), 0);
        assert!(handle.render().contains("vsock_proxy_active_connections 1"));
        release.send(()).unwrap();
        drop(
            timeout(Duration::from_secs(1), connect)
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(connections.available_permits(), 1);
        let rendered = handle.render();
        assert!(rendered.contains("vsock_proxy_active_connections 0"));
        assert!(rendered.contains("vsock_proxy_session_duration_seconds_count 1"));
    }

    #[test]
    fn socket_address_matches_linux_abi() {
        assert_eq!(
            std::mem::size_of::<SockAddrVm>(),
            std::mem::size_of::<libc::sockaddr_vm>()
        );
        assert_eq!(std::mem::offset_of!(SockAddrVm, flags), 12);

        let addr = SockAddrVm {
            family: libc::AF_VSOCK as libc::sa_family_t,
            reserved: 0,
            port: 5000,
            cid: 16,
            flags: VMADDR_FLAG_TO_HOST,
            zero: [0; 3],
        };

        assert_eq!(addr.flags, VMADDR_FLAG_TO_HOST);
    }
}
