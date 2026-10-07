use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    num::{NonZeroU64, NonZeroUsize},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{sleep, timeout},
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

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
}

impl Cli {
    async fn run(self) -> io::Result<()> {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.listen_port);
        let listener = TcpListener::bind(listen_addr).await?;
        let connections = Arc::new(Semaphore::new(self.max_connections.get()));
        let connect_timeout = Duration::from_secs(self.connect_timeout_secs.get());

        info!(
            %listen_addr,
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
                    error!(%error, "Failed to accept TCP connection; retrying");
                    sleep(ACCEPT_RETRY_DELAY).await;
                    continue;
                }
            };

            let permit = match Arc::clone(&connections).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!(%peer, "Connection limit reached; rejecting client");
                    continue;
                }
            };

            let cid = self.vsock_cid;
            let port = self.vsock_port;

            tokio::spawn(async move {
                if let Err(error) = proxy_connection(tcp, cid, port, permit, connect_timeout).await
                {
                    error!(%peer, %error, "Connection failed");
                }
            });
        }
    }
}

async fn proxy_connection(
    mut tcp: TcpStream,
    cid: u32,
    port: u32,
    permit: OwnedSemaphorePermit,
    connect_timeout: Duration,
) -> io::Result<()> {
    // A timed-out blocking task cannot be cancelled, so move the permit into it to keep the
    // connection counted until connect_blocking returns. On success, the returned permit remains
    // held for the lifetime of the proxy session.
    let (stream, _permit) = timeout(
        connect_timeout,
        tokio::task::spawn_blocking(move || (connect_blocking(cid, port), permit)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VSOCK connection timed out"))??;
    let mut vsock = tokio_vsock::VsockStream::new(stream?)?;
    copy_bidirectional(&mut tcp, &mut vsock).await?;
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
