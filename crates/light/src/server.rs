//! Minimal read-only local API. No Ethereum forwarding, transaction methods, or signing.

use crate::{
    client::{Client, Error as ClientError, FailureKind},
    token::ReadRequest,
};
use jsonrpsee::{
    RpcModule,
    server::{BatchRequestConfig, Server, ServerConfig, ServerHandle},
    types::ErrorObjectOwned,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Semaphore;

/// Binds loopback unless remote access was explicitly authorized. Remote consumers still trust
/// this daemon unless they independently verify evidence; the response alone is not a proof.
pub async fn serve(
    client: Client,
    address: SocketAddr,
    allow_remote: bool,
) -> Result<(ServerHandle, SocketAddr), Error> {
    if !address.ip().is_loopback() && !allow_remote {
        return Err(Error::RemoteAccess);
    }
    let server = Server::builder()
        .set_config(
            ServerConfig::builder()
                .http_only()
                .max_connections(64)
                .max_request_body_size(64 * 1024)
                .max_response_body_size(256 * 1024)
                .set_batch_request_config(BatchRequestConfig::Disabled)
                .build(),
        )
        .build(address)
        .await?;
    let address = server.local_addr()?;
    let mut module = RpcModule::new((client, Arc::new(Semaphore::new(64))));
    module
        .register_async_method("light_readVerified", |params, context, _| async move {
            let _permit = context.1.clone().try_acquire_owned().map_err(|_| busy())?;
            let (requests,): (Vec<ReadRequest>,) = params.parse()?;
            context
                .0
                .read(requests)
                .await
                .map(|response| (*response).clone())
                .map_err(|error| rpc_error(&error))
        })
        .expect("static read method is unique");
    module
        .register_async_method("light_status", |params, context, _| async move {
            let _permit = context.1.clone().try_acquire_owned().map_err(|_| busy())?;
            let arguments: Option<Vec<serde::de::IgnoredAny>> = params.parse()?;
            if arguments.is_some_and(|arguments| !arguments.is_empty()) {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "status does not accept parameters",
                    None::<()>,
                ));
            }
            Ok::<_, ErrorObjectOwned>(context.0.status().await)
        })
        .expect("static status method is unique");
    Ok((server.start(module), address))
}

fn busy() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        -32015,
        "light request concurrency limit reached",
        None::<()>,
    )
}
fn rpc_error(error: &ClientError) -> ErrorObjectOwned {
    let code = match error {
        ClientError::Busy => -32015,
        ClientError::RequestLimit | ClientError::Token(_) => -32602,
        _ => match error.kind() {
            FailureKind::Integrity => -32010,
            FailureKind::Capability => -32011,
            FailureKind::Availability => -32012,
            FailureKind::Persistence => -32013,
        },
    };
    ErrorObjectOwned::owned(code, error.to_string(), None::<()>)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("non-loopback light API requires explicit --light.allow-remote")]
    RemoteAccess,
    #[error("light API listener I/O: {0}")]
    Io(#[from] std::io::Error),
}
