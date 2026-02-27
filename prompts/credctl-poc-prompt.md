# credctl — macOS Secure Enclave PoC

## What you're building

A Go CLI called `credctl` using `spf13/cobra`. This is a proof of concept for the `init` command, which generates a hardware-bound ECDSA P-256 key pair inside the macOS Secure Enclave. The private key never leaves the enclave. The public key is exported for later registration with cloud providers or a credential broker.

## Project setup

- Module path: `github.com/matzhouse/credctl`
- Use `spf13/cobra` for the CLI framework. No `cobra-cli` scaffolding — just set up the command tree manually, it's cleaner.
- Go 1.22+ (for build consistency)
- The repo name is `credctl`

## Command structure

```
credctl
├── init          # Generate Secure Enclave key pair, store reference, export public key
├── status        # Show current device identity (key fingerprint, creation date, enclave type)
└── version       # Build version info
```

That's it for now. Don't build anything else.

## `credctl init` — what it must do

1. **Check if already initialised.** Look for an existing key reference in `~/.credctl/config.json`. If found, warn and exit (don't overwrite without `--force`).

2. **Check Secure Enclave availability.** Verify we're on macOS and that the Secure Enclave is accessible. If not available (Linux, or old Mac without SE), exit with a clear error explaining why. Don't fall back to software keys in this PoC — we want to prove the hardware path works.

3. **Generate the key pair inside the Secure Enclave.** Use Apple's Security framework via cgo. The key must be:
   - ECDSA P-256 (this is what Secure Enclave supports)
   - Created with `kSecAttrTokenIDSecureEnclave`
   - Tagged with a stable application tag (e.g., `com.crzy.credctl.device-key`) so we can retrieve it later
   - Stored in the keychain with the Secure Enclave protection flag
   - Access controlled with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — the key is only usable when the device is unlocked, and never migrates to other devices or backups

4. **Export the public key.** Extract the public key in a usable format. Export it as:
   - PEM-encoded ECDSA public key (written to `~/.credctl/device.pub`)
   - SHA-256 fingerprint of the public key (displayed to the user and stored in config)

5. **Write the config file.** Save to `~/.credctl/config.json`:
   ```json
   {
     "version": 1,
     "device_id": "<sha256 fingerprint of public key>",
     "key_tag": "com.crzy.credctl.device-key",
     "created_at": "2026-02-27T12:00:00Z",
     "enclave_type": "secure_enclave",
     "public_key_path": "~/.credctl/device.pub"
   }
   ```

6. **Print a summary** to the user:
   ```
   ✓ Device identity created (Secure Enclave)
     Fingerprint: SHA256:aBcDeFg...
     Public key:  ~/.credctl/device.pub
     
     Next: Register this public key with your cloud provider or credctl broker.
   ```

## `credctl status`

Read `~/.credctl/config.json` and display the device identity info. Also verify the key still exists in the keychain (it could have been deleted). Show a clear status:
- Initialised / Not initialised
- Key fingerprint
- Enclave type
- Key accessible: yes/no (can we actually use it right now?)

## Secure Enclave interaction via cgo

This is the core technical challenge. You'll need to call Apple's Security framework from Go using cgo. Here's the approach:

Create an `internal/enclave/` package with a `darwin.go` file (build-tagged `//go:build darwin`) that wraps the Security framework calls. The C code interacts with:

- `SecKeyCreateRandomKey` — to generate the key pair in the enclave
- `SecKeyCopyPublicKey` — to extract the public key
- `SecKeyCopyExternalRepresentation` — to export the public key bytes
- `SecItemCopyMatching` — to look up an existing key by tag
- `SecItemDelete` — for the `--force` reinitialisation path

The cgo bridge should link against `-framework Security -framework CoreFoundation`.

Key attributes dictionary for key generation:
```
kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom
kSecAttrKeySizeInBits: 256
kSecAttrTokenID: kSecAttrTokenIDSecureEnclave
kSecAttrIsPermanent: true
kSecAttrApplicationTag: "com.crzy.credctl.device-key"
kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
```

The public key export from `SecKeyCopyExternalRepresentation` gives you the raw EC point (uncompressed, 65 bytes: 0x04 || x || y). You'll need to wrap this into proper ASN.1/DER to produce a PEM. Use Go's `crypto/elliptic`, `crypto/x509`, and `encoding/pem` packages to convert the raw point into a standard PEM public key.

Also provide a stub `other.go` (build-tagged `//go:build !darwin`) that returns clear errors like "Secure Enclave is only available on macOS" for all functions. This keeps the CLI compilable on other platforms even though the enclave won't work.

## Project layout

```
credctl/
├── main.go
├── cmd/
│   ├── root.go           # Root cobra command, global flags
│   ├── init.go           # init subcommand
│   ├── status.go         # status subcommand
│   └── version.go        # version subcommand
├── internal/
│   ├── enclave/
│   │   ├── enclave.go    # Interface definition
│   │   ├── darwin.go     # macOS Secure Enclave implementation (cgo)
│   │   └── other.go      # Stub for non-macOS platforms
│   └── config/
│       └── config.go     # Config file read/write (~/.credctl/config.json)
├── go.mod
└── go.sum
```

## Interface for the enclave package

```go
package enclave

type DeviceKey struct {
    Fingerprint string    // SHA256 fingerprint
    PublicKey   []byte    // PEM-encoded public key
    Tag         string    // Keychain application tag
    CreatedAt   time.Time
}

type Enclave interface {
    Available() bool
    GenerateKey(tag string) (*DeviceKey, error)
    LoadKey(tag string) (*DeviceKey, error)
    DeleteKey(tag string) error
    Sign(tag string, data []byte) ([]byte, error)
}
```

Include `Sign` in the interface now even though `init` doesn't use it — `auth` will need it shortly and this avoids a refactor.

## Flags

- `credctl init --force` — delete existing key and reinitialise
- `credctl init --key-tag <tag>` — override the default application tag (useful for testing)

## What NOT to build

- No cloud provider integration yet (no AWS/GCP/Azure)
- No broker communication
- No credential caching
- No `auth` command
- No CI/CD detection
- No TPM support (Linux)

## Testing approach

The Secure Enclave calls can't be unit tested in CI (no enclave available). Structure the code so that:
1. The `Enclave` interface can be mocked for testing command logic
2. The actual cgo integration is manually testable on a real Mac
3. Write unit tests for everything that doesn't touch the enclave: config parsing, PEM encoding, fingerprint generation, cobra command wiring

## Build

```bash
# macOS only (Secure Enclave requires cgo + Apple frameworks)
CGO_ENABLED=1 go build -o credctl .

# Cross-compile for linux (compiles but enclave functions return errors)
GOOS=linux CGO_ENABLED=0 go build -o credctl .
```
