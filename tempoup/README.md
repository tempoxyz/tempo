# tempoup

Official installer for [Tempo](https://tempo.xyz) - a blockchain for payments at scale.

## Quick Install

```bash
curl -L https://tempo.xyz/install | bash
```

## Usage

```bash
tempoup                  # Install latest release
tempoup -i v1.0.0        # Install specific version
tempoup -v               # Print installer version
tempoup --update         # Update tempoup itself
tempoup --help           # Show help
```

## Supported Platforms

- **Linux**: x86_64, arm64
- **macOS**: Apple Silicon (arm64)
- **Windows**: x86_64, arm64

## Install Dependencies

tempoup needs `curl` and `sha256sum` or `shasum`. It verifies each release with
GitHub attestations when `gh` is authenticated, and falls back to GPG
signatures otherwise, so it also needs an authenticated `gh` or `gpg`.

Without an authenticated `gh`, `tempoup` needs `jq` to select the latest
release. Pass a version with `tempoup -i <VERSION>` to skip release selection.

## Runtime Dependencies

On macOS, tempoup installs the `libusb` runtime dependency with Homebrew when
it is missing. If Homebrew is not installed, tempoup will stop with the exact
`brew install libusb` command to run before retrying.

## Installation Directory

Default: `~/.tempo/bin/`

Customize with `TEMPO_DIR` environment variable:
```bash
TEMPO_DIR=/custom/path tempoup
```

## Updating

### Update Tempo Binary

Simply run tempoup again:

```bash
tempoup
```

### Update Tempoup Itself

Use the built-in update command:

```bash
tempoup --update
```

This will:
1. Check the latest version available on GitHub
2. Download and replace the tempoup script if a newer version exists
3. Notify you of the version change

**Note:** Tempoup automatically checks for updates when you run it and will warn you if your version is outdated.

## Uninstalling

```bash
rm -rf ~/.tempo
```

Then remove the PATH export from your shell configuration file (`~/.zshenv`, `~/.bashrc`, `~/.config/fish/config.fish`, etc.).
