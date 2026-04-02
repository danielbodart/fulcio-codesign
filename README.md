# fulcio-codesign

Sign macOS binaries using [Fulcio](https://docs.sigstore.dev/certificate_authority/overview/) certificates. A single binary with no external dependencies beyond macOS system frameworks.

Replaces the typical shell-script approach of orchestrating `openssl`, `curl`, `jq`, `security`, and `codesign` with one tool that uses Security.framework directly.

## Usage

```bash
fulcio-codesign --identifier com.example.app \
                --entitlements entitlements.plist \
                dist/bin/myapp
```

In CI (GitHub Actions), the OIDC token is obtained automatically. Locally, use the included helper script:

```bash
# Pipe from the helper script (opens browser for Sigstore OAuth)
./scripts/sigstore-token.sh | fulcio-codesign --token - --identifier com.example.app dist/bin/myapp

# Or pass directly
fulcio-codesign --token "$TOKEN" --identifier com.example.app dist/bin/myapp
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--identifier <id>` | Code signing identifier (required) | |
| `--entitlements <path>` | Entitlements plist file | none |
| `--requirement <text>` | Designated requirement | `identifier "<id>"` |
| `--subject <text>` | CSR subject CN | identifier value |
| `--token <token \| ->` | OIDC token (`-` reads stdin) | auto-detect |
| `--fulcio-url <url>` | Fulcio server URL | `https://fulcio.sigstore.dev` |
| `--bundle <path>` | Write Sigstore bundle JSON | none |

### OIDC Token Resolution

The tool resolves the OIDC token in this order:

1. `--token` flag (use `-` to read from stdin)
2. `FULCIO_TOKEN` environment variable
3. GitHub Actions OIDC (automatic when `id-token: write` permission is granted)

## Install

### Via mise

```toml
# .mise.toml
[tools]
"github:danielbodart/fulcio-codesign" = "latest"
```

### From source

Requires [Zig](https://ziglang.org/) 0.15.2+ and macOS (Apple Silicon).

```bash
zig build -Doptimize=ReleaseFast
# Binary at zig-out/bin/fulcio-codesign
```

## How it Works

1. Creates a temporary keychain and adds it to the user keychain search list
2. Generates an ephemeral EC P-256 key pair directly in the temporary keychain via `SecKeyCreateRandomKey`
3. Builds a PKCS#10 CSR as raw ASN.1 DER
4. Exchanges an OIDC token + CSR for a short-lived certificate from [Fulcio](https://fulcio.sigstore.dev)
5. Imports the full certificate chain (leaf, intermediate, root) into the temporary keychain
6. Signs the binary using `SecCodeSignerCreate` + `SecCodeSignerAddSignatureWithErrors` (the same Security.framework SPI that `/usr/bin/codesign` uses internally)
7. Restores the original keychain search list and deletes the temporary keychain

The signature includes:
- **Hardened runtime** (`runtime` flag)
- **Secure timestamp** (Apple TSA, preserves validity after Fulcio cert expires)
- **Designated requirement** (identifier-based by default, for TCC persistence)
- **Entitlements** (optional, e.g., microphone access)

## Why Not Just Use codesign?

You can, and this tool produces the same output. The value is replacing a fragile multi-tool pipeline:

| Before (shell script) | After (this tool) |
|---|---|
| `openssl genpkey` + `openssl req` | `SecKeyCreateRandomKey` + ASN.1 DER |
| `curl` + `jq` | `std.http.Client` + `std.json` |
| `security create-keychain` + `security import` | `SecKeychainCreate` + `SecItemImport` |
| `codesign` CLI | `SecCodeSignerAddSignatureWithErrors` |

No dependency on `openssl`, `curl`, `jq`, or `python3` being installed at specific versions.

## GitHub Actions Example

```yaml
jobs:
  build:
    runs-on: macos-15
    permissions:
      id-token: write  # Required for Fulcio OIDC
    steps:
      - uses: actions/checkout@v4
      - run: |
          fulcio-codesign \
            --identifier com.example.app \
            --entitlements entitlements.plist \
            path/to/binary
```

## License

MIT
