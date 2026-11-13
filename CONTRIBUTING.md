# Contributing to lh-wireguard-mesh-agent

Thank you for your interest in contributing to `lh-wireguard-mesh-agent` (`lh-wg-mesh`), the zero-dependency Go air-gapped WireGuard mesh coordinator.

## Core Governance Mandates

1. **Zero External Dependencies**:
   `go.mod` must contain zero `require` blocks. Use only the Go Standard Library (`crypto/*`, `encoding/*`, `net`, `os`, `fmt`, etc.).
2. **Deterministic Security**:
   All cryptographic operations (RFC 7748 clamping, HMAC-SHA256 pairwise PSK derivation, Ed25519 signatures) must be strictly constant-time or use verified standard library primitives.
3. **Quality Gates**:
   All contributions must pass:
   ```bash
   test -z "$(gofmt -s -l .)"
   go vet ./...
   go test -v -race ./...
   ```

## Development Workflow

1. Fork or clone the repository:
   ```bash
   git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-wireguard-mesh-agent.git
   cd lh-wireguard-mesh-agent
   ```

2. Implement changes in `pkg/wgmesh` or `cmd/lh-wg-mesh`.

3. Add comprehensive unit tests in `pkg/wgmesh/wgmesh_test.go`.

4. Verify formatting and test execution:
   ```bash
   gofmt -s -w .
   go vet ./...
   go test -v -race ./...
   ```

5. Submit pull requests with descriptive conventional commit titles (`feat:`, `fix:`, `docs:`, `test:`).
