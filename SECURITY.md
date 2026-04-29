# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in credctl, please report it responsibly.

**Email:** [security@credctl.com](mailto:security@credctl.com)

Please include:
- A description of the vulnerability
- Steps to reproduce
- The potential impact
- Any suggested mitigations

**Do not** open a public GitHub issue for security vulnerabilities.

## Response timeline

| Step | Target |
|------|--------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 days |
| Fix released | Within 7 days (critical), 30 days (non-critical) |

## Scope

The following are in scope:

- The `credctl` CLI binary
- Hardware-bound key generation and signing operations (Secure Enclave on macOS, TPM 2.0 on Linux)
- OIDC document generation and publishing
- JWT construction and STS credential exchange
- Configuration file handling (`~/.credctl/`)
- CloudFormation template security

The following are out of scope:

- AWS service vulnerabilities (report to [AWS Security](https://aws.amazon.com/security/vulnerability-reporting/))
- macOS Secure Enclave hardware vulnerabilities (report to [Apple Security](https://support.apple.com/en-gb/102549))
- TPM 2.0 firmware vulnerabilities (report to your TPM vendor or platform OEM)
- Social engineering attacks
- Denial-of-service attacks against AWS infrastructure

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor release | Security fixes only |
| Older versions | No |

## Security design

credctl is a machine identity tool. Security is not a feature — it is the product. Key design principles:

- **Hardware-bound keys:** Private keys are generated and stored in the hardware enclave (Secure Enclave on macOS, TPM 2.0 on Linux) and are non-exportable.
- **Short-lived credentials:** AWS STS credentials expire in one hour. There are no long-lived secrets on disk.
- **No secret storage:** credctl does not store, cache, or log credentials. They are output to stdout and discarded.
- **Minimal attack surface:** Single binary, no network listeners, no background processes, no daemon.

## Acknowledgements

We appreciate responsible disclosure and will acknowledge reporters in release notes (unless you prefer to remain anonymous).
