# Contributing to credctl

Thank you for your interest in contributing to credctl.

## Prerequisites

- macOS with Secure Enclave (Apple Silicon or Intel with T2 chip)
- Go 1.22+
- Xcode (for code signing)
- Apple Developer account (free tier works)

## First-time setup

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

### 3. Generate the provisioning profile

Open the Xcode project and build once from the GUI:

```bash
open xcode/credctl.xcodeproj
```

Select the `credctl` target, ensure **Automatically manage signing** is checked with your team selected, then press Cmd+B. Xcode registers your Mac and creates the provisioning profile.

### 4. Update Makefile with your signing identity

```bash
# Find your identity
security find-identity -v -p codesigning
```

Update the `SIGNING_IDENTITY` in the Makefile and the team ID prefix in `entitlements.plist`.

## Build

```bash
make build
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

macOS requires a provisioning profile for binaries that use restricted entitlements like `keychain-access-groups`. Provisioning profiles can only be embedded in `.app` bundles, not standalone CLI binaries. The `.app` wrapper is minimal — it contains the Go binary, an `Info.plist`, and the provisioning profile.

### Cross-compilation

The CLI compiles on non-macOS platforms (Secure Enclave functions return stub errors):

```bash
GOOS=linux CGO_ENABLED=0 go build -o credctl ./cmd/credctl
```

## Project structure

```
credctl/
├── cmd/credctl/main.go              # Entry point
├── internal/
│   ├── cli/                         # Cobra commands
│   ├── enclave/                     # Secure Enclave abstraction
│   │   ├── enclave.go               # Interface + DeviceKey struct
│   │   ├── darwin.go                # macOS cgo implementation
│   │   └── other.go                 # Non-macOS stub
│   └── config/
│       └── config.go                # Config read/write (~/.credctl/)
├── xcode/                           # Xcode project (signing only)
├── entitlements.plist               # Keychain access entitlements
├── embedded.provisionprofile        # Apple provisioning profile
├── Makefile
├── go.mod
└── go.sum
```

## Reporting bugs

Open a [GitHub issue](https://github.com/credctl/credctl/issues) with:

- `credctl version` output
- macOS version (`sw_vers`)
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
- Tested on macOS with Secure Enclave access

## Security vulnerabilities

Do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the disclosure policy.

## Licence

By contributing, you agree that your contributions are licensed under the Apache 2.0 licence.
