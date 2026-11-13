package wgmesh

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// ClampCurve25519PrivateKey applies RFC 7748 scalar clamping to a 32-byte secret key:
// k[0] &= 248 (clears bits 0, 1, 2)
// k[31] &= 127 (clears bit 255)
// k[31] |= 64 (sets bit 254)
func ClampCurve25519PrivateKey(raw [32]byte) [32]byte {
	clamped := raw
	clamped[0] &= 248
	clamped[31] &= 127
	clamped[31] |= 64
	return clamped
}

// IsValidWireGuardKeyBase64 checks if a string is a valid standard Base64-encoded 32-byte WireGuard key.
// Standard WireGuard keys are exactly 44 Base64 characters long and decode to 32 non-all-zero bytes.
func IsValidWireGuardKeyBase64(b64 string) bool {
	if len(b64) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return false
	}
	// Check non-all-zero
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	return !allZero
}

// DerivePairwisePSK computes a symmetric, pairwise 256-bit Post-Quantum Pre-Shared Key (Noise_IKpsk2)
// for two WireGuard mesh peers given an enclave master secret and epoch.
// The public keys are lexicographically ordered so that:
// DerivePairwisePSK(A, B, secret, epoch) == DerivePairwisePSK(B, A, secret, epoch)
func DerivePairwisePSK(pubKeyA, pubKeyB string, masterSecret []byte, epoch uint64) (string, error) {
	if !IsValidWireGuardKeyBase64(pubKeyA) {
		return "", fmt.Errorf("invalid public key A: %q", pubKeyA)
	}
	if !IsValidWireGuardKeyBase64(pubKeyB) {
		return "", fmt.Errorf("invalid public key B: %q", pubKeyB)
	}
	if pubKeyA == pubKeyB {
		return "", errors.New("cannot derive pairwise PSK for identical peer public keys")
	}
	if len(masterSecret) < 16 {
		return "", errors.New("enclave master secret must be at least 16 bytes")
	}

	// Lexicographical ordering ensures commutativity
	kMin := pubKeyA
	kMax := pubKeyB
	if strings.Compare(pubKeyA, pubKeyB) > 0 {
		kMin = pubKeyB
		kMax = pubKeyA
	}

	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, epoch)

	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte("LH_WG_PSK_V1:"))
	mac.Write([]byte(kMin))
	mac.Write([]byte(":"))
	mac.Write([]byte(kMax))
	mac.Write([]byte(":"))
	mac.Write(epochBytes)

	pskBytes := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(pskBytes), nil
}

// DiscoveryBeacon represents an Ed25519-signed air-gapped peer discovery advertisement.
type DiscoveryBeacon struct {
	NodeID        string `json:"node_id"`
	WGPublicKey   string `json:"wg_public_key"`
	TunnelIPCIDR  string `json:"tunnel_ip_cidr"`
	LANEndpoint   string `json:"lan_endpoint"`
	SequenceNum   uint64 `json:"sequence_num"`
	TimestampUnix int64  `json:"timestamp_unix"`
	Signature     string `json:"signature,omitempty"`
}

// CanonicalBytes returns the canonical byte representation of a beacon for signing/verification.
func (b *DiscoveryBeacon) CanonicalBytes() []byte {
	return []byte(fmt.Sprintf("BEACON_V1:%s:%s:%s:%s:%d:%d",
		b.NodeID, b.WGPublicKey, b.TunnelIPCIDR, b.LANEndpoint, b.SequenceNum, b.TimestampUnix))
}

// SignDiscoveryBeacon signs the beacon using the node's Ed25519 private key.
func SignDiscoveryBeacon(b *DiscoveryBeacon, privKey ed25519.PrivateKey) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key length")
	}
	msg := b.CanonicalBytes()
	sig := ed25519.Sign(privKey, msg)
	b.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyDiscoveryBeacon verifies the Ed25519 signature, timestamp skew, and sequence number of a beacon.
func VerifyDiscoveryBeacon(b DiscoveryBeacon, pubKey ed25519.PublicKey, maxSkewSeconds int64, lastSeq uint64) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key length")
	}
	if b.Signature == "" {
		return errors.New("missing signature in discovery beacon")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("invalid or malformed Base64 Ed25519 signature")
	}

	msg := b.CanonicalBytes()
	if !ed25519.Verify(pubKey, msg, sigBytes) {
		return errors.New("Ed25519 signature verification failed: tampered beacon payload")
	}

	// Sequence number monotonicity check (if lastSeq is provided)
	if lastSeq > 0 && b.SequenceNum <= lastSeq {
		return fmt.Errorf("replay detected: beacon sequence %d <= last seen %d", b.SequenceNum, lastSeq)
	}

	// Timestamp anti-replay skew window
	if maxSkewSeconds > 0 {
		now := time.Now().Unix()
		diff := int64(math.Abs(float64(now - b.TimestampUnix)))
		if diff > maxSkewSeconds {
			return fmt.Errorf("beacon timestamp expired or skewed: %d seconds skew exceeds maximum %d seconds", diff, maxSkewSeconds)
		}
	}

	return nil
}
