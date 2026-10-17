# tempoup

Official installer for [Tempo](https://tempo.xyz) - a blockchain for payments at scale.

## Quick Install

```bash
curl -L https://tempo.xyz/install | bash
```

## Usage

Commands copied from Tempo docs set `TEMPO_INSTALL_SOURCE` to a page label. After
the installed binary passes `tempo --version`, the bootstrap installer sends
that label, a random event ID, and whether an executable already existed to
Tempo's docs analytics endpoint. No wallet or persistent machine identifier is
sent. Reporting has a three-second timeout and failures do not fail installation.
Set `DO_NOT_TRACK=1` or `TEMPO_TELEMETRY_DISABLED=1` on the `bash` process to opt out.
Unattributed commands and direct `tempoup` updates do not report this event.

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
