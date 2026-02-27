# credctl

Manage credentials with machine identity.

credctl uses the macOS Secure Enclave to create hardware-bound ECDSA P-256 device identities. The private key never leaves the enclave — only the public key is exported for registration with cloud providers or a credential broker.

## Prerequisites

- macOS with Secure Enclave (Apple Silicon or Touch Bar Mac)
- Go 1.22+
- Xcode (for one-time signing setup)
- Apple Developer account (free tier works)

## First-time setup

The Secure Enclave requires the binary to be signed with an Apple Development certificate and a provisioning profile. This is a one-time setup:

1. **Create a signing certificate** — open Xcode, go to *Settings > Accounts*, add your Apple ID, then *Manage Certificates > + > Apple Development*.

2. **Install the Apple WWDR intermediate cert** (if `security find-identity -v -p codesigning` shows 0 valid identities):
   ```bash
   curl -sO https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
   security import AppleWWDRCAG3.cer -k ~/Library/Keychains/login.keychain-db
   rm AppleWWDRCAG3.cer
   ```

3. **Generate the provisioning profile** — open the Xcode project and build once from the GUI:
   ```bash
   open xcode/credctl.xcodeproj
   ```
   Select the `credctl` target, ensure *Automatically manage signing* is checked with your team selected, then press Cmd+B. Xcode will register your Mac and create the provisioning profile.

4. **Update `Makefile` and `entitlements.plist`** with your signing identity and team ID:
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

For convenience, you can alias it:

```bash
alias credctl='./build/credctl.app/Contents/MacOS/credctl'
```

### Cross-compilation

The CLI compiles on non-macOS platforms (Secure Enclave functions return stub errors):

```bash
GOOS=linux CGO_ENABLED=0 go build -o credctl ./cmd/credctl
```

## Usage

### `credctl init`

Generate a Secure Enclave key pair and create device identity:

```
$ credctl init
Generating Secure Enclave key pair...

✓ Device identity created (Secure Enclave)
  Fingerprint: SHA256:aBcDeFg...
  Public key:  /Users/you/.credctl/device.pub

  Next: Register this public key with your cloud provider or credctl broker.
```

Flags:
- `--force` — delete existing key and reinitialise
- `--key-tag <tag>` — override the default keychain application tag (default: `com.crzy.credctl.device-key`)

### `credctl status`

Show current device identity and verify key accessibility:

```
$ credctl status
Status: Initialised
  Fingerprint:  SHA256:aBcDeFg...
  Enclave type: secure_enclave
  Key tag:      com.crzy.credctl.device-key
  Created:      2026-02-27T12:00:00Z
  Public key:   ~/.credctl/device.pub
  Key accessible: yes
```

### `credctl version`

Print build version info:

```
$ credctl version
credctl dev (commit: none)
```

Set version at build time with ldflags:

```bash
go build -ldflags "-X github.com/matzhouse/credctl/internal/cli.Version=v0.1.0 -X github.com/matzhouse/credctl/internal/cli.Commit=$(git rev-parse --short HEAD)" ./cmd/credctl
```

## Project structure

```
credctl/
├── cmd/credctl/main.go              # Entry point
├── internal/
│   ├── cli/                         # Cobra commands
│   │   ├── root.go
│   │   ├── init.go
│   │   ├── status.go
│   │   └── version.go
│   ├── enclave/                     # Secure Enclave abstraction
│   │   ├── enclave.go               # Interface + DeviceKey struct
│   │   ├── darwin.go                # macOS cgo implementation
│   │   └── other.go                 # Non-macOS stub
│   └── config/
│       └── config.go                # Config read/write (~/.credctl/)
├── xcode/                           # Xcode project (signing only)
│   └── credctl.xcodeproj/
├── entitlements.plist               # Keychain access entitlements
├── embedded.provisionprofile        # Apple provisioning profile
├── Makefile
├── go.mod
└── go.sum
```

## How it works

The Secure Enclave generates and stores an ECDSA P-256 key pair in hardware. The private key is non-exportable — it can only be used for signing operations on the device where it was created. credctl exports the public key as a PEM file and computes a SHA-256 fingerprint for identification.

The cgo bridge in `internal/enclave/darwin.go` calls Apple's Security framework:

- `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` — generates the key pair
- `SecKeyCopyPublicKey` + `SecKeyCopyExternalRepresentation` — exports the public key
- `SecItemCopyMatching` — looks up an existing key by tag
- `SecItemDelete` — deletes a key (for `--force` reinitialisation)
- `SecKeyCreateSignature` — signs data with the enclave key

### Why the `.app` bundle?

macOS requires a provisioning profile for binaries that use restricted entitlements like `keychain-access-groups`. Provisioning profiles can only be embedded in `.app` bundles, not standalone CLI binaries. The `.app` wrapper is minimal — it just contains the Go binary, an `Info.plist`, and the provisioning profile.

## Config files

| File | Purpose |
|------|---------|
| `~/.credctl/config.json` | Device identity configuration |
| `~/.credctl/device.pub` | PEM-encoded ECDSA public key |
