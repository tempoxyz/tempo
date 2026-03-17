# tempo-ext

Extension dispatch and lifecycle management for the Tempo CLI.

When a user runs `tempo wallet`, this crate locates the `tempo-wallet` binary, auto-installs it if missing, and dispatches the command. Built-in subcommands (`add`, `update`, `remove`) manage extension installation with signature verification and downgrade prevention.

## Architecture

```
tempo <extension> [args...]     →  find or auto-install binary, then exec
tempo add <extension> [version] →  download, verify, install
tempo update <extension>        →  install only if manifest version is newer
tempo remove <extension>        →  delete binary and skill files
```

**Modules:**

- `launcher` — CLI entry point (clap). Routes to extension dispatch or management commands.
- `installer` — Download, verify, and install extension binaries and skill files.
- `registry` — Persistent registry at `$TEMPO_HOME/extensions.json` (installed versions, update check timestamps).

## Release Manifest

Extensions are published as a JSON manifest at a well-known URL:

```
https://cli.tempo.xyz/extensions/tempo-{name}/manifest.json         # latest
https://cli.tempo.xyz/extensions/tempo-{name}/v{version}/manifest.json  # pinned
```

Schema:

```json
{
  "version": "1.2.0",
  "binaries": {
    "tempo-wallet-darwin-arm64": {
      "url": "https://cdn.example.com/tempo-wallet-darwin-arm64",
      "sha256": "b94d27b9...",
      "signature": "untrusted comment: ...\nRWT..."
    }
  },
  "skill": "https://cdn.example.com/SKILL.md",
  "skill_sha256": "e3b0c442...",
  "skill_signature": "untrusted comment: ...\nRWT..."
}
```

Binary keys follow the `tempo-{name}-{os}-{arch}` convention (`darwin`/`linux`/`windows`, `arm64`/`amd64`). The `skill`, `skill_sha256`, and `skill_signature` fields are optional.

## Security

### Signature verification

Every binary and skill file must have a valid [minisign](https://jedisct1.github.io/minisign/) signature. The release public key is compiled into the binary and can only be overridden via `TEMPO_EXT_PUBLIC_KEY` in debug/test builds (`#[cfg(debug_assertions)]`).

### Trusted comment anti-substitution

After signature verification, the trusted comment is checked against the expected artifact identity:

- Binaries: `file:tempo-{name}-{os}-{arch}`
- Skills: `skill:tempo-{name}`

This prevents an attacker from taking a validly-signed binary for one extension and substituting it into another extension's manifest.

### Downgrade prevention

`tempo update` only installs if the manifest version is strictly newer (semver comparison). Non-semver versions fall back to string equality — skip if identical, reinstall if different.

### URL scheme enforcement

Binary and manifest download URLs must use `https://` or `file://`. Any other scheme (including `http://`) is rejected.

## Environment Variables

| Variable | Description |
|---|---|
| `TEMPO_EXT_BASE_URL` | Override the release manifest base URL. |
| `TEMPO_EXT_PUBLIC_KEY` | Override the release public key (debug/test builds only). |

## Testing

```bash
cargo test -p tempo-ext
```

Integration tests in `tests/lifecycle.rs` exercise the full add → update → remove lifecycle against locally-signed binaries using `file://` URLs. No network access required.
