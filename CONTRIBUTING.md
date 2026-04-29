# Contributing to credctl

Thank you for your interest in contributing to credctl.

## Prerequisites

One of the supported platforms:

- **macOS** with Secure Enclave (Apple Silicon or Intel with T2 chip), plus an Apple Developer account (free tier works for local development).
- **Linux** with TPM 2.0 (`/dev/tpmrm0` accessible; user in the `tss` group). Tested on Ubuntu 22.04+, Fedora 38+, Amazon Linux 2023.

Plus:

- Go 1.26+

## First-time setup (macOS)

The Secure Enclave requires the binary to be signed with an Apple Development certificate and a provisioning profile. This is a one-time setup.

### 1. Create a signing certificate

Open Xcode, go to **Settings > Accounts**, add your Apple ID, then **Manage Certificates > + > Apple Development**.

### 2. Install the Apple WWDR intermediate certificate

If `security find-identity -v -p codesigning` shows 0 valid identities:

```bash
curl -sO https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
security import AppleWWDRCAG3.cer -k ~/Library/Keychains/login.keychain-db
rm AppleWWDRCAG3.cer
```

### 3. Clone the signing artifacts

Signing files (Info.plist, entitlements, provisioning profile) live in a separate private repo:

```bash
gh repo clone credctl/apple-signing ../apple-signing
```

### 4. Update Makefile with your signing identity

```bash
# Find your identity
security find-identity -v -p codesigning
```

Update the `SIGNING_IDENTITY` when running `make build`.

## Build (macOS)

```bash
make build SIGNING_DIR=../apple-signing
```

This compiles the Go binary, wraps it in a signed `.app` bundle with the provisioning profile, and produces:

```
build/credctl.app/Contents/MacOS/credctl
```

For convenience, alias it:

```bash
alias credctl='./build/credctl.app/Contents/MacOS/credctl'
```

### Why the `.app` bundle?

macOS requires a provisioning profile for binaries that use the Secure Enclave. Provisioning profiles can only be embedded in `.app` bundles, not standalone CLI binaries. The `.app` wrapper is minimal — it contains the Go binary, an `Info.plist`, and the provisioning profile.

## Build (Linux)

No code signing or provisioning profile required:

```bash
make build-linux           # amd64
make build-linux-arm64     # arm64
```

Produces a static `CGO_ENABLED=0` binary at `build/credctl-linux-{amd64,arm64}`. Run it directly.

### Cross-compilation

The CLI cross-compiles for any supported platform from any host:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o credctl ./cmd/credctl
```

On platforms without a hardware enclave (anything other than macOS or Linux), the `Available()` check returns false and the enclave functions return stub errors.

## Project structure

```
credctl/
├── cmd/credctl/main.go              # Entry point
├── internal/
│   ├── cli/                         # Cobra commands
│   ├── enclave/                     # Hardware enclave abstraction
│   │   ├── enclave.go               # Public Enclave interface + DeviceKey
│   │   ├── backend.go               # keyBackend interface + enclaveImpl wrapper
│   │   ├── darwin.go                # macOS cgo implementation (Secure Enclave)
│   │   ├── linux.go                 # Linux implementation (TPM 2.0 via go-tpm)
│   │   └── other.go                 # Stub for unsupported platforms
│   └── config/
│       └── config.go                # Config read/write (~/.credctl/)
├── Makefile
├── go.mod
└── go.sum
```

## Reporting bugs

Open a [GitHub issue](https://github.com/credctl/credctl/issues) with:

- `credctl version` output
- OS and version (macOS: `sw_vers`; Linux: `lsb_release -a` or `cat /etc/os-release`)
- Hardware (e.g. Apple Silicon M3, Intel T2; or `lscpu` and TPM model on Linux)
- The full error message
- Steps to reproduce

## Pull requests

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `make build` and test manually
5. Open a pull request against `main`

### Code standards

- Follow existing code style
- All CLI commands use the Cobra framework in `internal/cli/`
- Error messages use `fmt.Errorf` with `%w` wrapping
- Progress and status messages go to stderr; data output goes to stdout
- Keep dependencies minimal

### What makes a good PR

- Focused on a single change
- Includes a clear description of what and why
- Tested on at least one supported platform (macOS with Secure Enclave or Linux with TPM 2.0)

## Security vulnerabilities

Do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the disclosure policy.

## Licence

By contributing, you agree that your contributions are licensed under the Apache 2.0 licence.
