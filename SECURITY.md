# Security Policy: lh-wireguard-mesh-agent

Logihertz Systems (OPC) Private Limited maintains high assurance security standards for sovereign and air-gapped industrial infrastructure.

## Supported Versions

| Version | Supported          | Security Maintenance Status |
|---------|--------------------|-----------------------------|
| 0.1.x   | :white_check_mark: | Active Current Release      |
| < 0.1.0 | :x:                | Unsupported                 |

## Threat Model & Scope

The `lh-wireguard-mesh-agent` (`lh-wg-mesh`) coordinates peer-to-peer WireGuard tunnels in mission-critical environments. Key areas of concern include:
- **Noise_IKpsk2 PSK Derivation**: Ensuring pairwise post-quantum pre-shared keys are cryptographically strong and unique per peer link.
- **AllowedIPs Route Hijacking**: Preventing unauthorized default routes (`0.0.0.0/0`, `::/0`) or overlapping CIDRs from intercepting mesh traffic.
- **Discovery Replay & Tampering**: Enforcing Ed25519 signature verification, anti-replay timestamps (<= 30s skew), and monotonic sequence checks.
- **Filesystem Permissions**: Ensuring generated WireGuard private keys and configuration files are restricted to mode `0600`.

## Reporting a Vulnerability

If you discover a vulnerability in `lh-wireguard-mesh-agent`, please contact the Logihertz security team:

- **Email**: `security@logihertz.com` (cc: `ops@logihertz.com`)
- **PGP Encryption**: Available upon request for confidential reports.
- **Information Required**:
  - Detailed description of the issue
  - Affected components (`crypto_keys`, `topology`, `auditor`, etc.)
  - Reproduction manifest or steps
  - Estimated impact on air-gapped mesh deployments

## Response Timeline

- **Initial Acknowledgement**: Within 24 business hours.
- **Triage & Assessment**: Within 72 business hours.
- **Remediation & Advisory**: Coordinated disclosure within 30 calendar days.
