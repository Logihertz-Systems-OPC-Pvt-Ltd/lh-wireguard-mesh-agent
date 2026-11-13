package wgmesh_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-wireguard-mesh-agent/pkg/wgmesh"
)

// ============================================================================
// 1. CRYPTO KEYS, RFC 7748 CLAMPING & SYMMETRIC PAIRWISE PSK TESTS
// ============================================================================

func TestClampCurve25519PrivateKey(t *testing.T) {
	// All 0xFF input
	var allOnes [32]byte
	for i := range allOnes {
		allOnes[i] = 0xFF
	}
	clamped := wgmesh.ClampCurve25519PrivateKey(allOnes)

	// k[0] &= 248 -> lower 3 bits cleared (0b11111000 = 248)
	if clamped[0] != 248 {
		t.Fatalf("expected clamped[0] == 248, got %d", clamped[0])
	}
	if clamped[0]&0x07 != 0 {
		t.Fatalf("expected bits 0, 1, 2 cleared in byte 0, got %08b", clamped[0])
	}
	// k[31] &= 127, |= 64 -> bit 255 cleared, bit 254 set (0b01000000 | (0xFF & 0x7F) = 0x7F = 127)
	if clamped[31] != 127 {
		t.Fatalf("expected clamped[31] == 127 for all-ones, got %d", clamped[31])
	}

	// All 0x00 input
	var allZeros [32]byte
	clampedZero := wgmesh.ClampCurve25519PrivateKey(allZeros)
	if clampedZero[0] != 0 {
		t.Fatalf("expected clampedZero[0] == 0, got %d", clampedZero[0])
	}
	if clampedZero[31] != 64 {
		t.Fatalf("expected clampedZero[31] == 64 (bit 254 set), got %d", clampedZero[31])
	}

	// Arbitrary input
	var custom [32]byte
	custom[0] = 0xAF  // 10101111 -> &= 248 -> 10101000 = 0xA8 = 168
	custom[31] = 0x03 // 00000011 -> &= 127 -> 00000011, |= 64 -> 01000011 = 0x43 = 67
	clampedCustom := wgmesh.ClampCurve25519PrivateKey(custom)
	if clampedCustom[0] != 168 {
		t.Fatalf("expected clampedCustom[0] == 168, got %d", clampedCustom[0])
	}
	if clampedCustom[31] != 67 {
		t.Fatalf("expected clampedCustom[31] == 67, got %d", clampedCustom[31])
	}
}

func TestIsValidWireGuardKeyBase64(t *testing.T) {
	// Valid key (44 chars base64, 32 non-zero bytes)
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	validB64 := base64.StdEncoding.EncodeToString(raw)
	if !wgmesh.IsValidWireGuardKeyBase64(validB64) {
		t.Fatalf("expected valid key for %s", validB64)
	}

	// Invalid lengths
	if wgmesh.IsValidWireGuardKeyBase64("") {
		t.Fatal("expected empty string to be invalid")
	}
	if wgmesh.IsValidWireGuardKeyBase64("abc") {
		t.Fatal("expected short string to be invalid")
	}
	if wgmesh.IsValidWireGuardKeyBase64(validB64 + "a") {
		t.Fatal("expected 45-char string to be invalid")
	}

	// Invalid characters
	invalidChars := validB64[:43] + "!"
	if wgmesh.IsValidWireGuardKeyBase64(invalidChars) {
		t.Fatal("expected non-base64 characters to be invalid")
	}

	// All zeros (32 zero bytes)
	zeroRaw := make([]byte, 32)
	zeroB64 := base64.StdEncoding.EncodeToString(zeroRaw)
	if wgmesh.IsValidWireGuardKeyBase64(zeroB64) {
		t.Fatal("expected all-zero key to be rejected")
	}
}

func TestDerivePairwisePSK(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	rawA := make([]byte, 32)
	rawB := make([]byte, 32)
	rawC := make([]byte, 32)
	for i := range rawA {
		rawA[i] = byte(i + 1)
		rawB[i] = byte(i + 10)
		rawC[i] = byte(i + 20)
	}
	pubA := base64.StdEncoding.EncodeToString(rawA)
	pubB := base64.StdEncoding.EncodeToString(rawB)
	pubC := base64.StdEncoding.EncodeToString(rawC)

	// 1. Commutativity: Derive(A, B) == Derive(B, A)
	pskAB, err := wgmesh.DerivePairwisePSK(pubA, pubB, secret, 1)
	if err != nil {
		t.Fatalf("unexpected error deriving PSK(A, B): %v", err)
	}
	pskBA, err := wgmesh.DerivePairwisePSK(pubB, pubA, secret, 1)
	if err != nil {
		t.Fatalf("unexpected error deriving PSK(B, A): %v", err)
	}
	if pskAB != pskBA {
		t.Fatalf("pairwise PSK symmetry failed: PSK(A,B) %s != PSK(B,A) %s", pskAB, pskBA)
	}

	// 2. Format validation: must be valid 44-char base64 key
	if !wgmesh.IsValidWireGuardKeyBase64(pskAB) {
		t.Fatalf("derived PSK is not a valid 32-byte Base64 key: %s", pskAB)
	}

	// 3. Epoch sensitivity: PSK(epoch 1) != PSK(epoch 2)
	pskABEpoch2, err := wgmesh.DerivePairwisePSK(pubA, pubB, secret, 2)
	if err != nil {
		t.Fatalf("unexpected error deriving PSK for epoch 2: %v", err)
	}
	if pskAB == pskABEpoch2 {
		t.Fatal("expected PSK to change across epochs")
	}

	// 4. Pair uniqueness: PSK(A, B) != PSK(A, C)
	pskAC, err := wgmesh.DerivePairwisePSK(pubA, pubC, secret, 1)
	if err != nil {
		t.Fatalf("unexpected error deriving PSK(A, C): %v", err)
	}
	if pskAB == pskAC {
		t.Fatal("expected distinct pairwise PSK for distinct peer links")
	}

	// 5. Error conditions
	// Identical public keys
	if _, err := wgmesh.DerivePairwisePSK(pubA, pubA, secret, 1); err == nil {
		t.Fatal("expected error deriving PSK for identical peer public keys")
	}
	// Short secret
	if _, err := wgmesh.DerivePairwisePSK(pubA, pubB, []byte("short"), 1); err == nil {
		t.Fatal("expected error for short master secret")
	}
	// Invalid public key
	if _, err := wgmesh.DerivePairwisePSK("invalid", pubB, secret, 1); err == nil {
		t.Fatal("expected error for invalid pubKeyA")
	}
	if _, err := wgmesh.DerivePairwisePSK(pubA, "invalid", secret, 1); err == nil {
		t.Fatal("expected error for invalid pubKeyB")
	}
}

func TestDiscoveryBeacon(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating Ed25519 keypair: %v", err)
	}

	now := time.Now().Unix()
	beacon := wgmesh.DiscoveryBeacon{
		NodeID:        "node-test-01",
		WGPublicKey:   "x58/r8oWkG55o6uD4F1M02n8mK1Lq9s6v8b1x3z5y7w=",
		TunnelIPCIDR:  "10.99.0.1/32",
		LANEndpoint:   "192.168.10.11:51820",
		SequenceNum:   10,
		TimestampUnix: now,
	}

	// Sign beacon
	if err := wgmesh.SignDiscoveryBeacon(&beacon, privKey); err != nil {
		t.Fatalf("failed signing discovery beacon: %v", err)
	}
	if beacon.Signature == "" {
		t.Fatal("expected signature to be populated")
	}

	// Verify authentic beacon
	if err := wgmesh.VerifyDiscoveryBeacon(beacon, pubKey, 30, 5); err != nil {
		t.Fatalf("failed verifying authentic discovery beacon: %v", err)
	}

	// Tampered NodeID
	tamperedNode := beacon
	tamperedNode.NodeID = "node-attacker"
	if err := wgmesh.VerifyDiscoveryBeacon(tamperedNode, pubKey, 30, 5); err == nil {
		t.Fatal("expected verification failure on tampered NodeID")
	}

	// Tampered TunnelIPCIDR
	tamperedCIDR := beacon
	tamperedCIDR.TunnelIPCIDR = "10.99.0.99/32"
	if err := wgmesh.VerifyDiscoveryBeacon(tamperedCIDR, pubKey, 30, 5); err == nil {
		t.Fatal("expected verification failure on tampered TunnelIPCIDR")
	}

	// Tampered Endpoint
	tamperedEndpoint := beacon
	tamperedEndpoint.LANEndpoint = "192.168.10.99:51820"
	if err := wgmesh.VerifyDiscoveryBeacon(tamperedEndpoint, pubKey, 30, 5); err == nil {
		t.Fatal("expected verification failure on tampered LANEndpoint")
	}

	// Sequence replay check (sequence <= lastSeq)
	if err := wgmesh.VerifyDiscoveryBeacon(beacon, pubKey, 30, 10); err == nil {
		t.Fatal("expected sequence replay failure when sequence <= lastSeq")
	}
	if err := wgmesh.VerifyDiscoveryBeacon(beacon, pubKey, 30, 15); err == nil {
		t.Fatal("expected sequence replay failure when sequence < lastSeq")
	}

	// Timestamp skew check (exceeds maxSkewSeconds)
	staleBeacon := beacon
	staleBeacon.TimestampUnix = now - 60 // 60s ago
	_ = wgmesh.SignDiscoveryBeacon(&staleBeacon, privKey)
	if err := wgmesh.VerifyDiscoveryBeacon(staleBeacon, pubKey, 30, 5); err == nil {
		t.Fatal("expected failure on expired timestamp skew")
	}

	// Missing / invalid signature
	missingSigBeacon := beacon
	missingSigBeacon.Signature = ""
	if err := wgmesh.VerifyDiscoveryBeacon(missingSigBeacon, pubKey, 30, 5); err == nil {
		t.Fatal("expected failure on missing signature")
	}

	invalidSigBeacon := beacon
	invalidSigBeacon.Signature = "not-a-valid-base64-signature"
	if err := wgmesh.VerifyDiscoveryBeacon(invalidSigBeacon, pubKey, 30, 5); err == nil {
		t.Fatal("expected failure on invalid base64 signature")
	}

	// Invalid public key size
	if err := wgmesh.VerifyDiscoveryBeacon(beacon, []byte("short"), 30, 5); err == nil {
		t.Fatal("expected failure on invalid public key size")
	}

	// Invalid private key size on signing
	if err := wgmesh.SignDiscoveryBeacon(&beacon, []byte("short")); err == nil {
		t.Fatal("expected failure on invalid private key size")
	}
}

// ============================================================================
// 2. TOPOLOGY GENERATION & ALLOWED-IPS ROUTE HIJACK TESTS
// ============================================================================

func TestValidateAllowedIPs(t *testing.T) {
	// Clean disjoint nodes
	cleanNodes := []wgmesh.MeshNode{
		{ID: "node-1", TunnelIP: "10.99.0.1/32", AllowedIPs: []string{"10.99.0.1/32"}},
		{ID: "node-2", TunnelIP: "10.99.0.2/32", AllowedIPs: []string{"10.99.0.2/32"}},
		{ID: "node-3", TunnelIP: "10.99.0.3/32", AllowedIPs: []string{"10.99.0.3/32"}},
	}
	violationsClean := wgmesh.ValidateAllowedIPs(cleanNodes)
	if len(violationsClean) != 0 {
		t.Fatalf("expected 0 violations for clean nodes, got %d", len(violationsClean))
	}

	// Wildcard default route 0.0.0.0/0
	wildcardNodes := []wgmesh.MeshNode{
		{ID: "node-1", TunnelIP: "10.99.0.1/32", AllowedIPs: []string{"10.99.0.1/32"}},
		{ID: "node-hijacker", TunnelIP: "10.99.0.2/32", AllowedIPs: []string{"0.0.0.0/0"}},
	}
	violationsWildcard := wgmesh.ValidateAllowedIPs(wildcardNodes)
	hasWildcard := false
	for _, v := range violationsWildcard {
		if v.ViolationType == "WILDCARD_ROUTE_HIJACK" && v.NodeA == "node-hijacker" {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard {
		t.Fatal("expected WILDCARD_ROUTE_HIJACK for 0.0.0.0/0")
	}

	// IPv6 default route ::/0
	wildcardIPv6 := []wgmesh.MeshNode{
		{ID: "node-1", TunnelIP: "fd00::1/128", AllowedIPs: []string{"::/0"}},
	}
	violationsIPv6 := wgmesh.ValidateAllowedIPs(wildcardIPv6)
	if len(violationsIPv6) == 0 || violationsIPv6[0].ViolationType != "WILDCARD_ROUTE_HIJACK" {
		t.Fatal("expected WILDCARD_ROUTE_HIJACK for ::/0")
	}

	// Broader subnet (e.g. 10.99.0.0/24)
	broadSubnetNodes := []wgmesh.MeshNode{
		{ID: "node-1", TunnelIP: "10.99.0.1/32", AllowedIPs: []string{"10.99.0.0/24"}},
	}
	violationsBroad := wgmesh.ValidateAllowedIPs(broadSubnetNodes)
	if len(violationsBroad) == 0 || violationsBroad[0].ViolationType != "WILDCARD_ROUTE_HIJACK" {
		t.Fatal("expected WILDCARD_ROUTE_HIJACK for /24 in peer mesh")
	}

	// Overlapping AllowedIPs between two peers
	overlapNodes := []wgmesh.MeshNode{
		{ID: "node-1", TunnelIP: "10.99.0.1/32", AllowedIPs: []string{"10.99.0.1/32"}},
		{ID: "node-2", TunnelIP: "10.99.0.1/32", AllowedIPs: []string{"10.99.0.1/32"}}, // Duplicate IP
	}
	violationsOverlap := wgmesh.ValidateAllowedIPs(overlapNodes)
	hasOverlap := false
	for _, v := range violationsOverlap {
		if v.ViolationType == "OVERLAPPING_ALLOWED_IPS" {
			hasOverlap = true
			break
		}
	}
	if !hasOverlap {
		t.Fatal("expected OVERLAPPING_ALLOWED_IPS for conflicting IPs")
	}

	// Malformed CIDR
	malformedNodes := []wgmesh.MeshNode{
		{ID: "node-1", TunnelIP: "invalid-cidr", AllowedIPs: []string{"invalid-cidr"}},
	}
	violationsMalformed := wgmesh.ValidateAllowedIPs(malformedNodes)
	if len(violationsMalformed) == 0 || violationsMalformed[0].ViolationType != "INVALID_CIDR" {
		t.Fatal("expected INVALID_CIDR for malformed IP")
	}
}

func TestCheckCIDROverlap(t *testing.T) {
	_, net1, _ := net.ParseCIDR("10.99.0.0/24")
	_, net2, _ := net.ParseCIDR("10.99.0.5/32")
	_, net3, _ := net.ParseCIDR("10.99.1.0/24")

	if !wgmesh.CheckCIDROverlap(net1, net2) {
		t.Fatal("expected 10.99.0.0/24 to overlap with 10.99.0.5/32")
	}
	if !wgmesh.CheckCIDROverlap(net2, net1) {
		t.Fatal("expected overlap to be commutative")
	}
	if wgmesh.CheckCIDROverlap(net1, net3) {
		t.Fatal("did not expect 10.99.0.0/24 to overlap with 10.99.1.0/24")
	}
}

func TestGenerateMeshConfigs(t *testing.T) {
	manifest := wgmesh.EnclaveManifest{
		EnclaveID:    "TEST-ENCLAVE-01",
		MasterSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Epoch:        1,
		MTU:          1420,
		Nodes: []wgmesh.MeshNode{
			{
				ID:           "node-alpha",
				WGPublicKey:  "x58/r8oWkG55o6uD4F1M02n8mK1Lq9s6v8b1x3z5y7w=",
				WGPrivateKey: "u43/q7nVjF44n5tC3E0L91m7lJ0Kp8r5u7a0w2y4x6v=",
				TunnelIP:     "10.99.0.1/32",
				LANEndpoint:  "192.168.10.11:51820",
				ListenPort:   51820,
			},
			{
				ID:           "node-beta",
				WGPublicKey:  "y69/s9pXlH66p7vE5G2N13o9nL2Mr0t7w9c2y4z6z8x=",
				WGPrivateKey: "v54/r8oWkG55o6uD4F1M02n8mK1Lq9s6v8b1x3z5y7w=",
				TunnelIP:     "10.99.0.2/32",
				LANEndpoint:  "192.168.10.12:51820",
				ListenPort:   51820,
			},
			{
				ID:           "node-gamma",
				WGPublicKey:  "z70/t0qYmI77q8wF6H3O24p0oM3Ns1u8x0d3z5a7a9y=",
				WGPrivateKey: "w65/s9pXlH66p7vE5G2N13o9nL2Mr0t7w9c2y4z6z8x=",
				TunnelIP:     "10.99.0.3/32",
				LANEndpoint:  "192.168.10.13:51820",
				ListenPort:   51820,
			},
			{
				ID:           "node-delta",
				WGPublicKey:  "a81/u1rZnJ88r9xG7I4P35q1pN4Ot2v9y1e4a6b8b0z=",
				WGPrivateKey: "x76/t0qYmI77q8wF6H3O24p0oM3Ns1u8x0d3z5a7a9y=",
				TunnelIP:     "10.99.0.4/32",
				LANEndpoint:  "192.168.10.14:51820",
				ListenPort:   51820,
			},
		},
	}

	summary, err := wgmesh.GenerateMeshConfigs(manifest)
	if err != nil {
		t.Fatalf("unexpected error generating mesh configs: %v", err)
	}

	// 4 nodes -> 4 * 3 / 2 = 6 unique tunnels
	if summary.TotalNodes != 4 {
		t.Fatalf("expected 4 nodes, got %d", summary.TotalNodes)
	}
	if summary.TotalTunnels != 6 {
		t.Fatalf("expected 6 tunnels, got %d", summary.TotalTunnels)
	}
	if len(summary.PairwisePSKMap) != 6 {
		t.Fatalf("expected 6 pairwise PSKs, got %d", len(summary.PairwisePSKMap))
	}
	if len(summary.Configs) != 4 {
		t.Fatalf("expected 4 generated configs, got %d", len(summary.Configs))
	}

	// Check config structure for node-alpha
	alphaCfg := summary.Configs["node-alpha"]
	if !strings.Contains(alphaCfg, "[Interface]") {
		t.Fatal("alpha config missing [Interface]")
	}
	if !strings.Contains(alphaCfg, "Address = 10.99.0.1/32") {
		t.Fatal("alpha config missing tunnel address")
	}
	if !strings.Contains(alphaCfg, "ListenPort = 51820") {
		t.Fatal("alpha config missing listen port")
	}
	if !strings.Contains(alphaCfg, "MTU = 1420") {
		t.Fatal("alpha config missing MTU")
	}

	// Alpha should contain 3 peer sections (beta, gamma, delta)
	if strings.Count(alphaCfg, "[Peer]") != 3 {
		t.Fatalf("expected 3 [Peer] blocks in alpha config, got %d", strings.Count(alphaCfg, "[Peer]"))
	}

	// Verify that pairwise PSK between alpha and beta matches in both configs
	betaCfg := summary.Configs["node-beta"]
	pskAlphaBeta := summary.PairwisePSKMap["node-alpha<->node-beta"]
	if pskAlphaBeta == "" {
		pskAlphaBeta = summary.PairwisePSKMap["node-beta<->node-alpha"]
	}
	if pskAlphaBeta == "" {
		t.Fatal("missing pairwise PSK for alpha<->beta")
	}

	if !strings.Contains(alphaCfg, pskAlphaBeta) {
		t.Fatal("alpha config does not contain alpha<->beta PSK")
	}
	if !strings.Contains(betaCfg, pskAlphaBeta) {
		t.Fatal("beta config does not contain alpha<->beta PSK")
	}

	// Error condition: fewer than 2 nodes
	oneNodeManifest := manifest
	oneNodeManifest.Nodes = manifest.Nodes[:1]
	if _, err := wgmesh.GenerateMeshConfigs(oneNodeManifest); err == nil {
		t.Fatal("expected error generating mesh with < 2 nodes")
	}

	// Error condition: invalid master secret
	invalidSecretManifest := manifest
	invalidSecretManifest.MasterSecret = "invalid-hex"
	if _, err := wgmesh.GenerateMeshConfigs(invalidSecretManifest); err == nil {
		t.Fatal("expected error with invalid master secret")
	}

	// Error condition: duplicate node ID
	dupIDManifest := manifest
	dupIDManifest.Nodes[1].ID = dupIDManifest.Nodes[0].ID
	if _, err := wgmesh.GenerateMeshConfigs(dupIDManifest); err == nil {
		t.Fatal("expected error with duplicate node ID")
	}

	// Error condition: duplicate public key
	dupKeyManifest := manifest
	dupKeyManifest.Nodes[1].WGPublicKey = dupKeyManifest.Nodes[0].WGPublicKey
	if _, err := wgmesh.GenerateMeshConfigs(dupKeyManifest); err == nil {
		t.Fatal("expected error with duplicate public key")
	}
}

// ============================================================================
// 3. 10-RULE AUDITOR & POSTURE SCORE MATH TESTS
// ============================================================================

func TestAuditMeshPolicy_Hardened(t *testing.T) {
	policy := &wgmesh.MeshPolicy{
		PolicyID:                   "HARDENED-TEST-01",
		EnclaveID:                  "ENCLAVE-01",
		EnforceSlash32PeerRoutes:   true,
		AllowWildcardDefaultRoute:  false,
		PresharedKeyEnabled:        true,
		UniquePairwisePSK:          true,
		Ed25519SignedDiscovery:     true,
		AllowUnverifiedPeerJoin:    false,
		MaxBeaconSkewSeconds:       30,
		MonotonicSequenceGuard:     true,
		AllowExternalSTUNDERP:      false,
		AirgapLocalEndpointsOnly:   true,
		ConfigFileModeOctal:        600,
		PrivateKeyViaCLIArgv:       false,
		PSKRotationIntervalHours:   168,
		EvictStalePeersSeconds:     600,
		TunnelMTU:                  1420,
		PersistentKeepaliveSeconds: 25,
		ControlSocketLoopbackOnly:  true,
		EnforceNftablesWGZone:      true,
		DetectAllowedIPsOverlap:    true,
		LogHandshakeFailures:       true,
	}

	report := wgmesh.AuditMeshPolicy(policy)
	if report.Score != 100 {
		t.Fatalf("expected hardened score 100, got %d", report.Score)
	}
	if report.PassedCount != 10 {
		t.Fatalf("expected 10 passed rules, got %d", report.PassedCount)
	}
	if report.FailedCount != 0 {
		t.Fatalf("expected 0 failed rules, got %d", report.FailedCount)
	}
	if report.TotalDeductions != 0 {
		t.Fatalf("expected 0 deductions, got %d", report.TotalDeductions)
	}
	if !strings.Contains(report.Verdict, "HARDENED") {
		t.Fatalf("expected verdict HARDENED, got %s", report.Verdict)
	}
}

func TestAuditMeshPolicy_Vulnerable(t *testing.T) {
	vulnerable := &wgmesh.MeshPolicy{
		PolicyID:                   "VULNERABLE-TEST-01",
		EnclaveID:                  "ENCLAVE-01",
		EnforceSlash32PeerRoutes:   false, // Rule 1: -25
		AllowWildcardDefaultRoute:  true,
		PresharedKeyEnabled:        false, // Rule 2: -25
		UniquePairwisePSK:          false,
		Ed25519SignedDiscovery:     false, // Rule 3: -25
		AllowUnverifiedPeerJoin:    true,
		MaxBeaconSkewSeconds:       120, // Rule 4: -10
		MonotonicSequenceGuard:     false,
		AllowExternalSTUNDERP:      true, // Rule 5: -10
		AirgapLocalEndpointsOnly:   false,
		ConfigFileModeOctal:        644, // Rule 6: -10
		PrivateKeyViaCLIArgv:       true,
		PSKRotationIntervalHours:   720, // Rule 7: -10
		EvictStalePeersSeconds:     3600,
		TunnelMTU:                  1500, // Rule 8: -4
		PersistentKeepaliveSeconds: 120,
		ControlSocketLoopbackOnly:  false, // Rule 9: -4
		EnforceNftablesWGZone:      false,
		DetectAllowedIPsOverlap:    false, // Rule 10: -1
		LogHandshakeFailures:       false,
	}

	report := wgmesh.AuditMeshPolicy(vulnerable)
	if report.Score != 0 {
		t.Fatalf("expected score 0, got %d", report.Score)
	}
	if report.PassedCount != 0 {
		t.Fatalf("expected 0 passed, got %d", report.PassedCount)
	}
	if report.FailedCount != 10 {
		t.Fatalf("expected 10 failed, got %d", report.FailedCount)
	}
	// 25*3 + 10*4 + 4*2 + 1 = 75 + 40 + 8 + 1 = 124
	if report.TotalDeductions != 124 {
		t.Fatalf("expected 124 total deductions, got %d", report.TotalDeductions)
	}
	if !strings.Contains(report.Verdict, "CRITICAL") {
		t.Fatalf("expected verdict CRITICAL, got %s", report.Verdict)
	}
}

func getBaseHardenedPolicy() *wgmesh.MeshPolicy {
	return &wgmesh.MeshPolicy{
		PolicyID:                   "BASE-HARDENED",
		EnclaveID:                  "ENCLAVE-BASE",
		EnforceSlash32PeerRoutes:   true,
		AllowWildcardDefaultRoute:  false,
		PresharedKeyEnabled:        true,
		UniquePairwisePSK:          true,
		Ed25519SignedDiscovery:     true,
		AllowUnverifiedPeerJoin:    false,
		MaxBeaconSkewSeconds:       30,
		MonotonicSequenceGuard:     true,
		AllowExternalSTUNDERP:      false,
		AirgapLocalEndpointsOnly:   true,
		ConfigFileModeOctal:        600,
		PrivateKeyViaCLIArgv:       false,
		PSKRotationIntervalHours:   168,
		EvictStalePeersSeconds:     600,
		TunnelMTU:                  1420,
		PersistentKeepaliveSeconds: 25,
		ControlSocketLoopbackOnly:  true,
		EnforceNftablesWGZone:      true,
		DetectAllowedIPsOverlap:    true,
		LogHandshakeFailures:       true,
	}
}

func TestAuditIndividualRules(t *testing.T) {
	// Rule 1: LH-WGM-001 (CRITICAL, 25)
	{
		p := getBaseHardenedPolicy()
		p.EnforceSlash32PeerRoutes = false
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 75 || r.Findings[0].Passed || r.Findings[0].Deduction != 25 {
			t.Fatalf("Rule 1 check failed: score %d, passed %v", r.Score, r.Findings[0].Passed)
		}
	}
	// Rule 2: LH-WGM-002 (CRITICAL, 25)
	{
		p := getBaseHardenedPolicy()
		p.PresharedKeyEnabled = false
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 75 || r.Findings[1].Passed || r.Findings[1].Deduction != 25 {
			t.Fatalf("Rule 2 check failed: score %d, passed %v", r.Score, r.Findings[1].Passed)
		}
	}
	// Rule 3: LH-WGM-003 (CRITICAL, 25)
	{
		p := getBaseHardenedPolicy()
		p.Ed25519SignedDiscovery = false
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 75 || r.Findings[2].Passed || r.Findings[2].Deduction != 25 {
			t.Fatalf("Rule 3 check failed: score %d, passed %v", r.Score, r.Findings[2].Passed)
		}
	}
	// Rule 4: LH-WGM-004 (HIGH, 10)
	{
		p := getBaseHardenedPolicy()
		p.MaxBeaconSkewSeconds = 60
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 90 || r.Findings[3].Passed || r.Findings[3].Deduction != 10 {
			t.Fatalf("Rule 4 check failed: score %d, passed %v", r.Score, r.Findings[3].Passed)
		}
	}
	// Rule 5: LH-WGM-005 (HIGH, 10)
	{
		p := getBaseHardenedPolicy()
		p.AllowExternalSTUNDERP = true
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 90 || r.Findings[4].Passed || r.Findings[4].Deduction != 10 {
			t.Fatalf("Rule 5 check failed: score %d, passed %v", r.Score, r.Findings[4].Passed)
		}
	}
	// Rule 6: LH-WGM-006 (HIGH, 10)
	{
		p := getBaseHardenedPolicy()
		p.ConfigFileModeOctal = 644
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 90 || r.Findings[5].Passed || r.Findings[5].Deduction != 10 {
			t.Fatalf("Rule 6 check failed: score %d, passed %v", r.Score, r.Findings[5].Passed)
		}
	}
	// Rule 7: LH-WGM-007 (HIGH, 10)
	{
		p := getBaseHardenedPolicy()
		p.PSKRotationIntervalHours = 300
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 90 || r.Findings[6].Passed || r.Findings[6].Deduction != 10 {
			t.Fatalf("Rule 7 check failed: score %d, passed %v", r.Score, r.Findings[6].Passed)
		}
	}
	// Rule 8: LH-WGM-008 (MEDIUM, 4)
	{
		p := getBaseHardenedPolicy()
		p.TunnelMTU = 1500
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 96 || r.Findings[7].Passed || r.Findings[7].Deduction != 4 {
			t.Fatalf("Rule 8 check failed: score %d, passed %v", r.Score, r.Findings[7].Passed)
		}
	}
	// Rule 9: LH-WGM-009 (MEDIUM, 4)
	{
		p := getBaseHardenedPolicy()
		p.ControlSocketLoopbackOnly = false
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 96 || r.Findings[8].Passed || r.Findings[8].Deduction != 4 {
			t.Fatalf("Rule 9 check failed: score %d, passed %v", r.Score, r.Findings[8].Passed)
		}
	}
	// Rule 10: LH-WGM-010 (LOW, 1)
	{
		p := getBaseHardenedPolicy()
		p.DetectAllowedIPsOverlap = false
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 99 || r.Findings[9].Passed || r.Findings[9].Deduction != 1 {
			t.Fatalf("Rule 10 check failed: score %d, passed %v", r.Score, r.Findings[9].Passed)
		}
	}

	// Partial combined check: Rule 1 (25) + Rule 4 (10) = 100 - 35 = 65 (VULNERABLE)
	{
		p := getBaseHardenedPolicy()
		p.AllowWildcardDefaultRoute = true
		p.MonotonicSequenceGuard = false
		r := wgmesh.AuditMeshPolicy(p)
		if r.Score != 65 {
			t.Fatalf("expected score 65, got %d", r.Score)
		}
		if !strings.Contains(r.Verdict, "VULNERABLE") {
			t.Fatalf("expected verdict VULNERABLE for score 65, got %s", r.Verdict)
		}
	}
}

// ============================================================================
// 4. EXPORTERS & FIXTURES LOAD TESTS
// ============================================================================

func TestExporters(t *testing.T) {
	p := getBaseHardenedPolicy()
	report := wgmesh.AuditMeshPolicy(p)

	// 1. Table
	var tableBuf bytes.Buffer
	wgmesh.RenderTable(&tableBuf, report)
	tableStr := tableBuf.String()
	if !strings.Contains(tableStr, "HARDENED") || !strings.Contains(tableStr, "LH-WGM-001") {
		t.Fatalf("table output missing expected content: %s", tableStr)
	}

	// 2. JSON
	var jsonBuf bytes.Buffer
	if err := wgmesh.RenderJSON(&jsonBuf, report); err != nil {
		t.Fatalf("failed rendering JSON: %v", err)
	}
	var decodedPost PostureReportTestStruct
	if err := json.Unmarshal(jsonBuf.Bytes(), &decodedPost); err != nil {
		t.Fatalf("failed decoding JSON output: %v", err)
	}
	if decodedPost.Score != 100 || decodedPost.PassedCount != 10 {
		t.Fatalf("decoded JSON mismatch: score %d, passed %d", decodedPost.Score, decodedPost.PassedCount)
	}

	// 3. SARIF
	var sarifBuf bytes.Buffer
	if err := wgmesh.RenderSARIF(&sarifBuf, report); err != nil {
		t.Fatalf("failed rendering SARIF: %v", err)
	}
	var sarifDoc map[string]interface{}
	if err := json.Unmarshal(sarifBuf.Bytes(), &sarifDoc); err != nil {
		t.Fatalf("failed decoding SARIF output: %v", err)
	}
	if sarifDoc["version"] != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %v", sarifDoc["version"])
	}
}

type PostureReportTestStruct struct {
	Score       int `json:"score"`
	PassedCount int `json:"passed_count"`
	FailedCount int `json:"failed_count"`
}

func TestFixturesEndToEnd(t *testing.T) {
	rootPath, err := filepath.Abs("../../fixtures")
	if err != nil {
		t.Fatalf("failed finding fixtures path: %v", err)
	}

	// Test hardened policy fixture
	hardenedPath := filepath.Join(rootPath, "hardened_wgmesh_policy.json")
	hardPolicy, err := wgmesh.LoadPolicyFromFile(hardenedPath)
	if err != nil {
		t.Fatalf("failed loading hardened fixture: %v", err)
	}
	hardReport := wgmesh.AuditMeshPolicy(hardPolicy)
	if hardReport.Score != 100 || hardReport.FailedCount != 0 {
		t.Fatalf("hardened fixture failed audit: score %d, failed %d", hardReport.Score, hardReport.FailedCount)
	}

	// Test vulnerable policy fixture
	vulnPath := filepath.Join(rootPath, "vulnerable_wgmesh_policy.json")
	vulnPolicy, err := wgmesh.LoadPolicyFromFile(vulnPath)
	if err != nil {
		t.Fatalf("failed loading vulnerable fixture: %v", err)
	}
	vulnReport := wgmesh.AuditMeshPolicy(vulnPolicy)
	if vulnReport.Score != 0 || vulnReport.FailedCount != 10 {
		t.Fatalf("vulnerable fixture should fail all rules: score %d, failed %d", vulnReport.Score, vulnReport.FailedCount)
	}

	// Test sample enclave nodes fixture
	enclavePath := filepath.Join(rootPath, "sample_enclave_nodes.json")
	data, err := os.ReadFile(enclavePath)
	if err != nil {
		t.Fatalf("failed reading enclave fixture: %v", err)
	}
	var enclave wgmesh.EnclaveManifest
	if err := json.Unmarshal(data, &enclave); err != nil {
		t.Fatalf("failed decoding enclave fixture: %v", err)
	}

	// Route verification on sample nodes
	routeViolations := wgmesh.ValidateAllowedIPs(enclave.Nodes)
	if len(routeViolations) != 0 {
		t.Fatalf("sample enclave should have 0 route violations, got %d", len(routeViolations))
	}

	// Mesh config generation
	summary, err := wgmesh.GenerateMeshConfigs(enclave)
	if err != nil {
		t.Fatalf("failed generating mesh configs from fixture: %v", err)
	}
	if summary.TotalNodes != 4 || summary.TotalTunnels != 6 {
		t.Fatalf("sample enclave mesh mismatch: nodes %d, tunnels %d", summary.TotalNodes, summary.TotalTunnels)
	}
}

// ============================================================================
// 5. CLI SUBPROCESS TESTS
// ============================================================================

func TestCLISubprocess(t *testing.T) {
	// Build binary to temporary path
	tmpDir, err := os.MkdirTemp("", "lh-wg-mesh-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	binPath := filepath.Join(tmpDir, "lh-wg-mesh")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../cmd/lh-wg-mesh/main.go")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed building CLI binary: %v, output: %s", err, string(out))
	}

	fixturesDir, _ := filepath.Abs("../../fixtures")
	hardenedPath := filepath.Join(fixturesDir, "hardened_wgmesh_policy.json")
	vulnPath := filepath.Join(fixturesDir, "vulnerable_wgmesh_policy.json")
	nodesPath := filepath.Join(fixturesDir, "sample_enclave_nodes.json")

	// 1. --version (exit 0)
	{
		cmd := exec.Command(binPath, "--version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("--version failed: %v, output: %s", err, string(out))
		}
		if !strings.Contains(string(out), "lh-wg-mesh 0.1.0") {
			t.Fatalf("--version output missing version: %s", string(out))
		}
	}

	// 2. --help (exit 0)
	{
		cmd := exec.Command(binPath, "--help")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("--help failed: %v, output: %s", err, string(out))
		}
		if !strings.Contains(string(out), "USAGE:") {
			t.Fatalf("--help output missing USAGE: %s", string(out))
		}
	}

	// 3. scan hardened (exit 0)
	{
		cmd := exec.Command(binPath, "scan", hardenedPath, "--format", "table")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("scan hardened failed: %v, output: %s", err, string(out))
		}
		if !strings.Contains(string(out), "HARDENED") {
			t.Fatalf("scan hardened missing verdict: %s", string(out))
		}
	}

	// 4. scan hardened json (exit 0)
	{
		cmd := exec.Command(binPath, "scan", hardenedPath, "--format", "json")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("scan hardened json failed: %v, output: %s", err, string(out))
		}
		if !strings.Contains(string(out), `"score": 100`) {
			t.Fatalf("scan json missing score 100: %s", string(out))
		}
	}

	// 5. scan hardened sarif (exit 0)
	{
		cmd := exec.Command(binPath, "scan", hardenedPath, "--format", "sarif")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("scan hardened sarif failed: %v, output: %s", err, string(out))
		}
		if !strings.Contains(string(out), `"version": "2.1.0"`) {
			t.Fatalf("scan sarif missing version 2.1.0: %s", string(out))
		}
	}

	// 6. scan vulnerable (exit 1)
	{
		cmd := exec.Command(binPath, "scan", vulnPath, "--format", "table")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected exit 1 for vulnerable policy, got exit 0")
		}
		if !strings.Contains(string(out), "CRITICAL") && !strings.Contains(string(out), "VULNERABLE") {
			t.Fatalf("scan vulnerable missing critical verdict: %s", string(out))
		}
	}

	// 7. gen-mesh (exit 0)
	{
		cmd := exec.Command(binPath, "gen-mesh", nodesPath, "--epoch", "1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("gen-mesh failed: %v, output: %s", err, string(out))
		}
		if !strings.Contains(string(out), "Total P2P Tunnels: 6") {
			t.Fatalf("gen-mesh missing 6 tunnels: %s", string(out))
		}
	}

	// 8. check-routes clean (exit 0)
	{
		cmd := exec.Command(binPath, "check-routes", nodesPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("check-routes failed: %v, output: %s", err, string(out))
		}
		if !strings.Contains(string(out), "[CLEAN]") {
			t.Fatalf("check-routes missing [CLEAN]: %s", string(out))
		}
	}

	// 9. verify-beacon authentic (exit 0)
	{
		cmd := exec.Command(binPath, "verify-beacon", "--node-id", "node-alpha", "--seq", "1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("verify-beacon failed: %v, output: %s", err, string(out))
		}
		if !strings.Contains(string(out), "VERIFIED_AUTHENTIC") {
			t.Fatalf("verify-beacon missing VERIFIED_AUTHENTIC: %s", string(out))
		}
	}

	// 10. unknown subcommand (exit 2)
	{
		cmd := exec.Command(binPath, "invalid-subcmd")
		_, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected exit 2 for unknown subcommand, got exit 0")
		}
	}
}
