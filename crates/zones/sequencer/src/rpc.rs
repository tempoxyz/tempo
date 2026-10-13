use std::time::Duration;

use alloy_rpc_client::{ConnectionConfig, WebSocketConfig};
use zone_primitives::constants::MAX_WS_FRAME_AND_MESSAGE_SIZE;

pub(crate) fn rpc_connection_config(retry_connection_interval: Duration) -> ConnectionConfig {
    ConnectionConfig::new()
        .with_max_retries(u32::MAX)
        .with_retry_interval(retry_connection_interval)
        .with_ws_config(
            WebSocketConfig::default()
                .max_frame_size(Some(MAX_WS_FRAME_AND_MESSAGE_SIZE))
                .max_message_size(Some(MAX_WS_FRAME_AND_MESSAGE_SIZE)),
        )
}
