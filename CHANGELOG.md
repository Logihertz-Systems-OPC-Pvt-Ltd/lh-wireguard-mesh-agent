# Changelog

All notable changes to `lh-wireguard-mesh-agent` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- Pure Go RFC 7748 Curve25519 private key clamping (`ClampCurve25519PrivateKey`).
- Symmetric pairwise Post-Quantum Pre-Shared Key derivation (`Noise_IKpsk2`) using HMAC-SHA256 with lexicographical public key sorting and epoch rotation.
- Ed25519-signed air-gapped LAN discovery beacons with anti-replay timestamp skew windows and monotonic sequence tracking.
- Full-mesh $N(N-1)/2$ WireGuard configuration synthesis generating per-node `wg0.conf` with dedicated pairwise PSKs.
- Cryptographic routing table (`AllowedIPs`) disjointness and route-hijack guard detecting `0.0.0.0/0` wildcard captures and CIDR overlaps.
- 10-rule deterministic WireGuard mesh posture auditor (`LH-WGM-001` through `LH-WGM-010`) scoring out of 100.
- Multi-format exporters: ANSI Box Tables, Canonical JSON, and OASIS SARIF v2.1.0.
- Command-line interface (`lh-wg-mesh`) supporting `scan`, `gen-mesh`, `check-routes`, `verify-beacon`, `--version`, and `--help`.
- Comprehensive test suite in `pkg/wgmesh/wgmesh_test.go` with 85+ deterministic assertions.
