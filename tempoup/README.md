# tempoup

Tempoup is the official installer for [Tempo](https://tempo.xyz) - a blockchain for payments at scale.

## Quick Install

```bash
curl -L https://tempo.xyz/install | bash
```

This will:
1. Download the `tempoup` installer script
2. Add `~/.tempo/bin` to your PATH
3. Install the latest `tempo` binary

## Manual Installation

If you prefer not to use the curl-to-bash method:

```bash
# Download tempoup
curl -L https://raw.githubusercontent.com/tempoxyz/tempo/main/tempoup/tempoup -o ~/.tempo/bin/tempoup
chmod +x ~/.tempo/bin/tempoup

# Add to PATH (add this to your ~/.zshenv, ~/.bashrc, or equivalent)
export PATH="$HOME/.tempo/bin:$PATH"

# Install tempo
tempoup
```

## Usage

### Help

```bash
tempoup --help
```

### Install Latest Release

```bash
tempoup
```

### Install Specific Version

```bash
tempoup --version v1.0.0
```

### Update Tempoup Installer

```bash
tempoup --update
```

Tempoup will automatically check for updates when you run it and warn you if a newer version is available.

## Supported Platforms

- **Linux**: x86_64, arm64
- **macOS**: Intel (x86_64), Apple Silicon (arm64)
- **Windows**: x86_64, arm64

The installer automatically detects your platform and architecture.

## Directory Structure

Tempoup installs files to `~/.tempo/` by default:

```
~/.tempo/
└── bin/
    ├── tempoup    # The installer script
    └── tempo      # The tempo binary
```

You can customize the installation directory by setting the `TEMPO_DIR` environment variable:

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

Alternatively, you can re-run the bootstrap installer:

```bash
curl -L https://tempo.xyz/install | bash
```

Or manually download the latest script:

```bash
curl -L https://raw.githubusercontent.com/tempoxyz/tempo/main/tempoup/tempoup -o ~/.tempo/bin/tempoup
chmod +x ~/.tempo/bin/tempoup
```

**Note:** Tempoup automatically checks for updates when you run it and will warn you if your version is outdated.

## Uninstalling

```bash
rm -rf ~/.tempo
```

Then remove the PATH export from your shell configuration file (`~/.zshenv`, `~/.bashrc`, etc.).