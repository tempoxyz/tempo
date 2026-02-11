# TLS Email Ownership Precompile

Proves email ownership on-chain using TLSNotary attestations.

**Address:** `0x714E000000000000000000000000000000000000`

## How It Works

1. User authenticates with Google and gets an OAuth access token
2. The Notary fetches `https://www.googleapis.com/oauth2/v3/userinfo` using TLSNotary MPC, verifying the TLS session
3. The Notary signs a compact attestation binding the user's email to their Ethereum address
4. The user submits the attestation + response body on-chain
5. The precompile verifies the Notary's secp256k1 signature, extracts the email from the JSON, and stores the claim
6. Anyone can query `isVerified(address)` to check

## Quick Start

```bash
# Get a Google OAuth token
TOKEN=$(gcloud auth print-access-token --scopes=email)

# Run the full E2E (starts localnet, calls Google, submits on-chain)
./scripts/verify-email.sh "$TOKEN"
```

The script:
- Fetches your real email from Google's userinfo API
- Builds and starts a Tempo localnet (or reuses one already running)
- Creates a Notary-signed attestation over the response
- Submits it to the precompile on-chain
- Queries `isVerified()` and prints the result

## Attestation Digest

The Notary signs `keccak256(abi.encodePacked(...))` over:

| Field | Description |
|-------|-------------|
| `"TempoEmailAttestationV1"` | Domain separator |
| `subject` | User's Ethereum address (20 bytes) |
| `keccak256(serverName)` | `"www.googleapis.com"` |
| `keccak256(endpoint)` | `"/oauth2/v3/userinfo"` |
| `responseBodyHash` | `keccak256(responseBody)` |
| `emailHash` | `keccak256(email)` |
| `notaryKeyId` | 32 bytes identifying the Notary |

## Interface

```solidity
interface ITLSEmailOwnership {
    function verifyEmail(
        bytes32 notaryKeyId,
        address subject,
        string serverName,
        string endpoint,
        bytes responseBody,
        uint8 v, bytes32 r, bytes32 s
    ) external returns (string email);

    function getVerifiedEmail(address user) external view returns (EmailClaim);
    function isVerified(address user) external view returns (bool);
    function revokeMyEmail() external;

    // Admin (owner only)
    function setNotaryKey(bytes32 notaryKeyId, address notaryAddress) external;
    function removeNotaryKey(bytes32 notaryKeyId) external;
    function getNotaryKey(bytes32 notaryKeyId) external view returns (address);
    function changeOwner(address newOwner) external;
}
```

## Trust Model

The precompile uses a **trusted Notary** model:
- The chain owner registers Notary public keys (Ethereum addresses)
- Notaries verify TLSNotary proofs off-chain and sign attestations
- The precompile verifies Notary signatures on-chain using `ecrecover`
- Users can revoke their own claims at any time
- The owner can add/remove Notary keys

For the dev Notary (localnet), the well-known Hardhat account #0 is used:
- Address: `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
- Key ID: `0x0101...0101`
