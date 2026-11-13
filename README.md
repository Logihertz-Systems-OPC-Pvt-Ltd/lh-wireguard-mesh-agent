# lh-wireguard-mesh-agent

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-wireguard-mesh-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-wireguard-mesh-agent/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://go.dev)
[![Protocol](https://img.shields.io/badge/Protocol-WireGuard%20Noise__IKpsk2-orange.svg)](https://www.wireguard.com)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(std%20only)-brightgreen.svg)](#dependencies)

**Production-grade, zero-dependency Go Air-Gapped Peer-to-Peer WireGuard Mesh Network Coordinator, Pairwise Post-Quantum PSK Deriver, Ed25519 Discovery Verifier, AllowedIPs Route-Hijack Guard, and 10-Rule Sovereign Mesh Posture Auditor.**

`lh-wireguard-mesh-agent` (`lh-wg-mesh`) is an industrial-strength mesh coordinator and security posture auditor engineered for sovereign enclaves, robotics swarms, SCADA/ICS field networks, and air-gapped data centers. Built exclusively with the Go Standard Library, it guarantees zero external supply-chain dependencies while delivering automated full-mesh topology synthesis, symmetric pairwise post-quantum pre-shared key (`PresharedKey`) derivation, cryptographic `AllowedIPs` route-hijack defense, and deterministic 10-rule posture evaluation.

---

## Key Capabilities

- **Pairwise Post-Quantum PSK Derivation (`Noise_IKpsk2`)**: Derives unique 256-bit symmetric pre-shared keys for every peer pair $(A, B)$ using keyed HMAC-SHA256 with lexicographically sorted public keys, guaranteeing $\text{PSK}_{A,B} == \text{PSK}_{B,A}$ and complete forward security across rotation epochs.
- **RFC 7748 Curve25519 Private Key Clamping**: Implements pure Go scalar clamping clearing bits $0, 1, 2, 255$ and asserting bit $254$ for Curve25519 Diffie-Hellman secret keys.
- **Full-Mesh $N(N-1)/2$ Topology Synthesizer**: Given an enclave manifest of $N$ nodes, computes all $L = \frac{N(N-1)}{2}$ undirected tunnels and generates production-ready `/etc/wireguard/wg0.conf` configurations (file mode `0600`) with dedicated pairwise PSKs and strict `/32` host routes.
- **Cryptographic Routing Table (`AllowedIPs`) Hijack Guard**: Performs exhaustive CIDR intersection analysis across all peer definitions, catching unauthorized default route takeovers (`0.0.0.0/0`, `::/0`), broad non-host subnets, and overlapping IP assignments before deployment.
- **Ed25519-Signed LAN Discovery Beacons**: Cryptographically signs and verifies air-gapped peer discovery announcements, rejecting replayed or skewed packets ($|T_{\text{now}} - T_{\text{beacon}}| > 30\text{ s}$) and strictly enforcing monotonic sequence counters.
- **10-Rule Sovereign Mesh Posture Auditor**: Audits mesh deployment policies against normative rules (`LH-WGM-001` through `LH-WGM-010`), computing a standardized score out of 100 with ANSI Table, Canonical JSON, and OASIS SARIF v2.1.0 exports.
- **100% Zero External Dependencies**: Powered strictly by Go's standard library packages (`crypto/ed25519`, `crypto/hmac`, `crypto/sha256`, `net`, `encoding/json`, `os`, etc.). Zero third-party packages, zero vulnerabilities.

---

## Architectural Block Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                    lh-wg-mesh Coordinator                                          |
+----------------------------------------------------------------------------------------------------+
                                                  |
  +-----------------------------------------------+-----------------------------------------------+
  |                               |                               |                               |
  v                               v                               v                               v
[Crypto & PQ-PSK]         [Topology & Synthesis]        [AllowedIPs Route Guard]        [Mesh Posture Auditor]
  * RFC 7748 Clamping       * Full-Mesh N(N-1)/2          * CIDR Overlap Analysis         * 10 Security Rules
  * HMAC-SHA256 Commutative * Strict /32 Host Routing     * 0.0.0.0/0 Hijack Defense      * Weight Deductions
  * Epoch Key Rotation      * wg0.conf Generation         * Host-Route Disjointness       * Posture Score (0-100)
  * Ed25519 Signed Beacons  * PersistentKeepalive = 25    * Multi-Peer Subnet Conflicts   * Table/JSON/SARIF
```

---

## Mathematical Formulations

### 1. Symmetric Pairwise Post-Quantum Pre-Shared Key Derivation

WireGuard's 1-RTT handshake is based on `Noise_IKpsk2`. In a mesh of $N$ peers, using a single shared PSK across all links exposes the entire mesh if any node is compromised. Conversely, deriving unique pairwise keys provides defense-in-depth against harvest-now-decrypt-later quantum attacks.

For any two distinct peers $A$ and $B$ with Base64 WireGuard public keys $\text{Pub}_A \neq \text{Pub}_B$, the public keys are ordered lexicographically:

$$K_{\min} = \min(\text{Pub}_A, \text{Pub}_B), \qquad K_{\max} = \max(\text{Pub}_A, \text{Pub}_B)$$

Given a 32-byte enclave master secret $S_{\text{enclave}}$ and rotation epoch $E \in \mathbb{Z}_{\ge 0}$:

$$\text{PSK}_{A,B}^{(E)} = \text{Base64}\left(\text{HMAC-SHA256}\left(S_{\text{enclave}}, \; \texttt{"LH\_WG\_PSK\_V1:"} \parallel K_{\min} \parallel \texttt{":"} \parallel K_{\max} \parallel \texttt{":"} \parallel \text{uint64\_be}(E)\right)\right)$$

- **Commutativity**: Because $\min(A, B) = \min(B, A)$ and $\max(A, B) = \max(B, A)$, both nodes independently derive identical 256-bit PSKs without negotiation: $\text{DerivePairwisePSK}(A, B) \equiv \text{DerivePairwisePSK}(B, A)$.
- **Link Isolation**: Compromising the derived PSK for link $(A, B)$ provides zero cryptographic advantage against link $(A, C)$ or $(B, C)$.

### 2. Full-Mesh Undirected Graph Topology

In an enclave with $N$ nodes, the total number of bidirectional peer tunnels $L$ is:

$$L = \binom{N}{2} = \frac{N(N - 1)}{2}$$

Each node $i$ configures $N - 1$ distinct `[Peer]` entries in its local `/etc/wireguard/wg0.conf`.

---

## 10-Rule WireGuard Mesh Posture Audit Matrix

| Rule ID | Severity | Weight | CWE | Title | Condition Triggered | Remediation |
|:---|:---:|:---:|:---:|:---|:---|:---|
| `LH-WGM-001` | CRITICAL | 25 | CWE-284 | Strict Host-Route Isolation & Wildcard Route Guard | `enforce_slash32_peer_routes == false` or `allow_wildcard_default_route == true` | Enforce strict `/32` (IPv4) or `/128` (IPv6) peer AllowedIPs and prohibit default wildcard routes. |
| `LH-WGM-002` | CRITICAL | 25 | CWE-326 | Post-Quantum Pairwise Noise_IKpsk2 Pre-Shared Key Enforcement | `preshared_key_enabled == false` or `unique_pairwise_psk == false` | Mandate symmetric 256-bit PresharedKey derivation with unique keys per peer pair. |
| `LH-WGM-003` | CRITICAL | 25 | CWE-306 | Cryptographic Ed25519 Peer Discovery Beacon Authentication | `ed25519_signed_discovery == false` or `allow_unverified_peer_join == true` | Enforce cryptographic Ed25519 digital signatures on all LAN discovery beacons and reject unverified peers. |
| `LH-WGM-004` | HIGH | 10 | CWE-294 | Anti-Replay Timestamp Window & Monotonic Sequence Number Guard | `max_beacon_skew_seconds > 30` or `monotonic_sequence_guard == false` | Restrict beacon timestamp skew to $\le 30\text{ s}$ and enforce strictly monotonic sequence counters. |
| `LH-WGM-005` | HIGH | 10 | CWE-319 | Air-Gapped Sovereign Enclave Isolation Against External Relay Leaks | `allow_external_stun_derp == true` or `airgap_local_endpoints_only == false` | Disable external STUN/TURN/DERP relays and bind exclusively to verified air-gapped local endpoints. |
| `LH-WGM-006` | HIGH | 10 | CWE-276 | Strict WireGuard Configuration & Private Key Filesystem Permissions | `config_file_mode_octal != 600` or `private_key_via_cli_argv == true` | Restrict WireGuard configuration file permissions to mode `0600` and never expose private keys in process arguments. |
| `LH-WGM-007` | HIGH | 10 | CWE-324 | Periodic Pairwise PSK Rotation & Stale Peer Eviction Thresholds | `psk_rotation_interval_hours > 168` or `evict_stale_peers_seconds > 600` | Schedule pairwise PSK rotation intervals $\le 168\text{ h}$ (7 days) and evict inactive peers within 600 seconds. |
| `LH-WGM-008` | MEDIUM | 4 | CWE-400 | Optimal Tunnel MTU & Persistent Keepalive Tuning | `tunnel_mtu < 1280` or `> 1420`, or `persistent_keepalive_seconds < 15` or `> 60` | Configure tunnel MTU within 1280-1420 bytes and set persistent keepalive interval between 15-60 seconds. |
| `LH-WGM-009` | MEDIUM | 4 | CWE-200 | Loopback-Only Control Socket & nftables Interface Zone Isolation | `control_socket_loopback_only == false` or `enforce_nftables_wg_zone == false` | Bind mesh control sockets strictly to `127.0.0.1` and enforce dedicated nftables interface zone filtering. |
| `LH-WGM-010` | LOW | 1 | CWE-778 | AllowedIPs Overlap Pre-Flight Validation & Handshake Failure SIEM Logging | `detect_allowed_ips_overlap == false` or `log_handshake_failures == false` | Enable automated AllowedIPs routing conflict pre-checks and stream handshake failure telemetry to SIEM. |

The posture score is computed monotonically:

$$S_{\text{posture}} = \max\left(0, 100 - \sum_{\text{findings}} W_i\right)$$

- $S_{\text{posture}} \ge 90$: **HARDENED** (Air-gapped mesh resilient; zero critical/high findings).
- $70 \le S_{\text{posture}} < 90$: **ADEQUATE** (Minor operational findings).
- $50 \le S_{\text{posture}} < 70$: **VULNERABLE** (Elevated routing or cryptographic risk).
- $S_{\text{posture}} < 50$: **CRITICAL** (Severe exploitation vulnerabilities detected).

---

## Building and Installation

### Prerequisites

- Go 1.22+ installed.
- Linux, macOS, or BSD operating system.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-wireguard-mesh-agent.git
cd lh-wireguard-mesh-agent

# Build binary
go build -v -o bin/lh-wg-mesh ./cmd/lh-wg-mesh

# Run verification suite with race detector
go test -v -race ./...

# Verify installed binary
./bin/lh-wg-mesh --version
```

---

## CLI Command Reference

### 1. Security Posture Audit (`scan`)

Audits a WireGuard mesh deployment policy manifest against all 10 security rules:

```bash
# ANSI Terminal Box Table format (default)
./bin/lh-wg-mesh scan fixtures/hardened_wgmesh_policy.json --format table

# Machine-readable Canonical JSON format
./bin/lh-wg-mesh scan fixtures/hardened_wgmesh_policy.json --format json

# OASIS SARIF v2.1.0 format for GitHub Security integration
./bin/lh-wg-mesh scan fixtures/vulnerable_wgmesh_policy.json --format sarif --output audit.sarif
```

### 2. Full-Mesh Configuration Generator (`gen-mesh`)

Synthesizes production WireGuard configuration files (`wg0.conf`) with unique pairwise post-quantum PSKs:

```bash
# Display generated mesh summary and sample configs:
./bin/lh-wg-mesh gen-mesh fixtures/sample_enclave_nodes.json --epoch 1

# Write individual node configs (mode 0600) to an output directory:
./bin/lh-wg-mesh gen-mesh fixtures/sample_enclave_nodes.json --epoch 1 --output-dir /tmp/wg-configs
```

### 3. Route Hijack & Overlap Verification (`check-routes`)

Validates peer AllowedIPs disjointness and detects wildcard default routes or conflicting subnets:

```bash
./bin/lh-wg-mesh check-routes fixtures/sample_enclave_nodes.json
```

### 4. Ed25519 Discovery Beacon Verification (`verify-beacon`)

Cryptographically signs and verifies peer discovery advertisements:

```bash
./bin/lh-wg-mesh verify-beacon --node-id node-alpha --wg-pub "2V5q0d6f4Rp5...=" --cidr 10.99.0.1/32 --endpoint 192.168.10.11:51820 --seq 1
```

---

## Policy Configuration Format

Receiver policies are written in standard JSON:

```json
{
  "policy_id": "HARDENED-ENCLAVE-POL-01",
  "enclave_id": "AIRGAP-FACTORY-ZONE-A",
  "enforce_slash32_peer_routes": true,
  "allow_wildcard_default_route": false,
  "preshared_key_enabled": true,
  "unique_pairwise_psk": true,
  "ed25519_signed_discovery": true,
  "allow_unverified_peer_join": false,
  "max_beacon_skew_seconds": 30,
  "monotonic_sequence_guard": true,
  "allow_external_stun_derp": false,
  "airgap_local_endpoints_only": true,
  "config_file_mode_octal": 600,
  "private_key_via_cli_argv": false,
  "psk_rotation_interval_hours": 168,
  "evict_stale_peers_seconds": 600,
  "tunnel_mtu": 1420,
  "persistent_keepalive_seconds": 25,
  "control_socket_loopback_only": true,
  "enforce_nftables_wg_zone": true,
  "detect_allowed_ips_overlap": true,
  "log_handshake_failures": true
}
```

---

## Security Disclosure

For security vulnerabilities, refer to [SECURITY.md](SECURITY.md). Please report issues to `security@logihertz.com`.

---

## Contributing

Review [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for coding standards, pull request procedures, and community guidelines.

---

## License & Attribution

Copyright (c) 2026 Logihertz Systems (OPC) Private Limited & Sameer Tawade.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0).
