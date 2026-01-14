# tempo-bootnode

Internal bootnode with dynamic peer registration for Kubernetes deployments.

The core logic is in the `tempo-bootnode` crate at `crates/bootnode/`.

## Overview

This binary runs a lightweight discv4 bootnode that:

1. **Maintains a stable identity** via a persistent node key
2. **Exposes an HTTP API** for dynamic peer registration/deregistration
3. **Advertises registered peers** to any connecting node via discv4

Designed for Kubernetes where nodes can call the bootnode API during startup (preStart hook) and shutdown (preStop hook).

## Usage

```bash
# Run with ephemeral key (for testing)
tempo-bootnode --discovery-addr 0.0.0.0:30303 --http-addr 0.0.0.0:8080

# Run with persistent key
tempo-bootnode --node-key /data/node.key --external-ip 10.0.0.1

# Full options
tempo-bootnode \
  --discovery-addr 0.0.0.0:30303 \
  --http-addr 0.0.0.0:8080 \
  --node-key /data/node.key \
  --external-ip 10.0.0.1 \
  --lookup-interval-secs 30
```

## HTTP API

### `GET /`

Returns bootnode info:

```json
{
  "enode": "enode://abcd...@10.0.0.1:30303",
  "peer_id": "0xabcd...",
  "discovery_addr": "10.0.0.1:30303",
  "http_addr": "0.0.0.0:8080",
  "registered_peers": 5,
  "discovered_peers": 12
}
```

### `GET /health`

Returns 200 OK if healthy.

### `GET /peers`

List all registered peers:

```json
[
  {
    "id": "0x1234...",
    "ip": "10.0.1.5",
    "tcp_port": 30303,
    "udp_port": 30303,
    "enode": "enode://1234...@10.0.1.5:30303"
  }
]
```

### `POST /peers`

Register a new peer:

```bash
curl -X POST http://bootnode:8080/peers \
  -H "Content-Type: application/json" \
  -d '{
    "secret_key": "0xabcd1234...",
    "ip": "10.0.1.5",
    "tcp_port": 30303,
    "udp_port": 30303
  }'
```

Response:

```json
{
  "id": "0x1234...",
  "ip": "10.0.1.5",
  "tcp_port": 30303,
  "udp_port": 30303,
  "enode": "enode://1234...@10.0.1.5:30303"
}
```

### `GET /peers/{peer_id}`

Get a specific peer by ID.

### `DELETE /peers/{peer_id}`

Deregister a peer:

```bash
curl -X DELETE http://bootnode:8080/peers/1234abcd...
```

### `GET /discovered`

List all peers discovered via discv4 (from network):

```json
[
  {
    "id": "0x5678...",
    "ip": "192.168.1.10",
    "tcp_port": 30303,
    "udp_port": 30303,
    "enode": "enode://5678...@192.168.1.10:30303"
  }
]
```

## Kubernetes Integration

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tempo-bootnode
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tempo-bootnode
  template:
    metadata:
      labels:
        app: tempo-bootnode
    spec:
      containers:
      - name: bootnode
        image: tempo-bootnode:latest
        args:
          - --node-key=/data/node.key
          - --external-ip=$(POD_IP)
          - --discovery-addr=0.0.0.0:30303
          - --http-addr=0.0.0.0:8080
        env:
          - name: POD_IP
            valueFrom:
              fieldRef:
                fieldPath: status.podIP
        ports:
          - containerPort: 30303
            protocol: UDP
            name: discovery
          - containerPort: 8080
            protocol: TCP
            name: http
        volumeMounts:
          - name: data
            mountPath: /data
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: bootnode-data
```

### Node Registration Hooks

In your tempo node deployment:

```yaml
spec:
  containers:
  - name: tempo
    lifecycle:
      postStart:
        exec:
          command:
            - /bin/sh
            - -c
            - |
              curl -X POST http://tempo-bootnode:8080/peers \
                -H "Content-Type: application/json" \
                -d "{\"secret_key\": \"$(cat /data/node.key)\", \"ip\": \"${POD_IP}\", \"tcp_port\": 30303}"
      preStop:
        exec:
          command:
            - /bin/sh
            - -c
            - |
              curl -X DELETE "http://tempo-bootnode:8080/peers/$(cat /data/peer_id)"
```

## Environment Variables

- `RUST_LOG` - Configure logging (e.g., `RUST_LOG=info,reth_discv4=debug`)
