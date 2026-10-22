# VSOCK proxy

`tempo-vsock-proxy` is a small, bidirectional proxy for AWS Nitro Enclaves. It
accepts TCP connections on the host, forwards their traffic to a VSOCK endpoint
inside an enclave, and sends responses back over the same TCP connection.

Run it with a host TCP port, enclave context identifier (CID), and enclave VSOCK
port:

```console
tempo-vsock-proxy <TCP_PORT> <VSOCK_CID> <VSOCK_PORT>
```

For example, the following forwards host TCP port `5000` to VSOCK port `5000`
in enclave CID `16`:

```console
tempo-vsock-proxy 5000 16 5000
```

The proxy limits resource usage with two optional settings:

- `--max-connections` limits concurrent TCP/VSOCK sessions (default: `256`).
- `--connect-timeout-secs` limits VSOCK connection setup (default: `10`).

Clients above the connection limit are rejected. Transient TCP accept failures
are retried after a short delay.

## Metrics

Prometheus metrics are served at `http://127.0.0.1:9100/metrics`. Set
`--metrics-addr <IP:PORT>` to change the listener (use a different port for each
proxy instance). Bind to a non-loopback address only on a trusted network; the
endpoint has no authentication. Failure to bind the metrics listener fails startup.

All metrics have the `vsock_proxy_` prefix:

| Metric | Type | Meaning |
| --- | --- | --- |
| `accepted_connections_total` | Counter | Accepted TCP connections, including rejected clients. |
| `rejected_connections_total` | Counter | Clients rejected at the connection limit. |
| `connected_connections_total` | Counter | Successfully established VSOCK sessions. |
| `completed_connections_total` | Counter | Sessions whose bidirectional forwarding completed without error. |
| `active_connections` | Gauge | Occupied connection slots, including connecting sessions. |
| `max_connections` | Gauge | Configured connection limit. |
| `accept_errors_total` | Counter | TCP accept failures. |
| `connect_errors_total` | Counter | VSOCK setup failures, excluding timeouts. |
| `connect_timeouts_total` | Counter | VSOCK setup timeouts. |
| `forward_errors_total` | Counter | Bidirectional forwarding failures. |
| `connect_duration_seconds` | Histogram | Time awaiting VSOCK setup, including failures and timeouts. |
| `session_duration_seconds` | Histogram | Time holding a connection slot, including setup and failed sessions. |
| `tcp_to_vsock_bytes_total` | Counter | Bytes successfully written to VSOCK. |
| `vsock_to_tcp_bytes_total` | Counter | Bytes successfully written to TCP. |

Byte totals update during forwarding and retain bytes written before an error.
A timed-out blocking connect still occupies a slot until the kernel call returns;
the active gauge and session duration reflect that lifetime. All metrics are
registered at startup, with descriptions derived from the `ProxyMetrics` struct.
No client addresses or error strings are used as labels.

## Why not `socat`?

Nitro Enclave connections must use the guest-to-host VSOCK transport. When a
host-to-guest VSOCK transport is also loaded, the transport must be selected by
setting `VMADDR_FLAG_TO_HOST` in the Linux `sockaddr_vm` address.

`socat`'s VSOCK address does not expose a way to set this flag, so it can select
the wrong transport or fail to connect in that configuration. This proxy opens
the VSOCK socket directly and sets `VMADDR_FLAG_TO_HOST` before connecting.

VSOCK support, including `VMADDR_FLAG_TO_HOST`, is Linux-only.
