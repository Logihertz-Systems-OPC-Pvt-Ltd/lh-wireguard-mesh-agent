package wgmesh

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

// MeshNode represents a single WireGuard peer within the air-gapped enclave.
type MeshNode struct {
	ID           string   `json:"id"`
	WGPublicKey  string   `json:"wg_public_key"`
	WGPrivateKey string   `json:"wg_private_key,omitempty"`
	TunnelIP     string   `json:"tunnel_ip"`    // e.g. "10.99.0.1/32"
	LANEndpoint  string   `json:"lan_endpoint"` // e.g. "192.168.10.11:51820"
	ListenPort   int      `json:"listen_port"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"` // CIDRs routed via this node
}

// EnclaveManifest describes the entire air-gapped industrial enclave network.
type EnclaveManifest struct {
	EnclaveID    string     `json:"enclave_id"`
	MasterSecret string     `json:"master_secret_hex"` // 32-byte hex-encoded enclave secret
	Epoch        uint64     `json:"epoch"`
	MTU          int        `json:"mtu"` // Recommended default: 1420
	Nodes        []MeshNode `json:"nodes"`
}

// RouteViolation records an AllowedIPs routing anomaly or security hazard.
type RouteViolation struct {
	ViolationType string `json:"violation_type"` // WILDCARD_ROUTE_HIJACK, OVERLAPPING_ALLOWED_IPS, INVALID_CIDR
	NodeA         string `json:"node_a"`
	NodeB         string `json:"node_b,omitempty"`
	CIDRA         string `json:"cidr_a"`
	CIDRB         string `json:"cidr_b,omitempty"`
	Description   string `json:"description"`
}

// CheckCIDROverlap checks if two IP networks overlap.
func CheckCIDROverlap(net1, net2 *net.IPNet) bool {
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

// ValidateAllowedIPs inspects peer AllowedIPs and tunnel definitions for route hijacking and overlaps.
func ValidateAllowedIPs(nodes []MeshNode) []RouteViolation {
	var violations []RouteViolation

	type cidrEntry struct {
		nodeID string
		raw    string
		ipNet  *net.IPNet
	}
	var allEntries []cidrEntry

	for _, node := range nodes {
		cidrsToCheck := node.AllowedIPs
		if len(cidrsToCheck) == 0 && node.TunnelIP != "" {
			cidrsToCheck = []string{node.TunnelIP}
		}

		for _, rawCIDR := range cidrsToCheck {
			_, ipNet, err := net.ParseCIDR(rawCIDR)
			if err != nil {
				violations = append(violations, RouteViolation{
					ViolationType: "INVALID_CIDR",
					NodeA:         node.ID,
					CIDRA:         rawCIDR,
					Description:   fmt.Sprintf("Node %s advertises invalid CIDR %q: %v", node.ID, rawCIDR, err),
				})
				continue
			}

			// Check for Wildcard route hijacking (0.0.0.0/0 or ::/0)
			ones, bits := ipNet.Mask.Size()
			if ones == 0 {
				violations = append(violations, RouteViolation{
					ViolationType: "WILDCARD_ROUTE_HIJACK",
					NodeA:         node.ID,
					CIDRA:         rawCIDR,
					Description:   fmt.Sprintf("Node %s attempts default wildcard route capture (%s)", node.ID, rawCIDR),
				})
			} else if (bits == 32 && ones < 32) || (bits == 128 && ones < 128) {
				// Subnet broader than /32 or /128 in strict host-routed peer mesh
				violations = append(violations, RouteViolation{
					ViolationType: "WILDCARD_ROUTE_HIJACK",
					NodeA:         node.ID,
					CIDRA:         rawCIDR,
					Description:   fmt.Sprintf("Node %s advertises non-host CIDR %s (prefix /%d broader than host route /%d)", node.ID, rawCIDR, ones, bits),
				})
			}

			allEntries = append(allEntries, cidrEntry{
				nodeID: node.ID,
				raw:    rawCIDR,
				ipNet:  ipNet,
			})
		}
	}

	// Pairwise overlap check
	for i := 0; i < len(allEntries); i++ {
		for j := i + 1; j < len(allEntries); j++ {
			if allEntries[i].nodeID == allEntries[j].nodeID {
				continue // same node multiple CIDRs is permissible
			}
			if CheckCIDROverlap(allEntries[i].ipNet, allEntries[j].ipNet) {
				violations = append(violations, RouteViolation{
					ViolationType: "OVERLAPPING_ALLOWED_IPS",
					NodeA:         allEntries[i].nodeID,
					NodeB:         allEntries[j].nodeID,
					CIDRA:         allEntries[i].raw,
					CIDRB:         allEntries[j].raw,
					Description: fmt.Sprintf("Routing conflict: %s (Node %s) overlaps with %s (Node %s)",
						allEntries[i].raw, allEntries[i].nodeID, allEntries[j].raw, allEntries[j].nodeID),
				})
			}
		}
	}

	return violations
}

// MeshTopologySummary provides statistical metrics for the generated mesh.
type MeshTopologySummary struct {
	EnclaveID      string            `json:"enclave_id"`
	TotalNodes     int               `json:"total_nodes"`
	TotalTunnels   int               `json:"total_tunnels"`
	Epoch          uint64            `json:"epoch"`
	Configs        map[string]string `json:"configs"`          // NodeID -> wg0.conf
	PairwisePSKMap map[string]string `json:"pairwise_psk_map"` // "NodeA<->NodeB" -> PSK
}

// GenerateMeshConfigs synthesizes full-mesh N(N-1)/2 WireGuard configurations for all enclave nodes.
func GenerateMeshConfigs(manifest EnclaveManifest) (*MeshTopologySummary, error) {
	if len(manifest.Nodes) < 2 {
		return nil, fmt.Errorf("mesh requires at least 2 nodes, got %d", len(manifest.Nodes))
	}

	secret, err := hex.DecodeString(manifest.MasterSecret)
	if err != nil || len(secret) < 16 {
		return nil, fmt.Errorf("invalid enclave master secret: must be hex encoded and at least 16 bytes (got %d bytes)", len(secret))
	}

	mtu := manifest.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	// Verify uniqueness of node IDs and public keys
	seenIDs := make(map[string]bool)
	seenPubKeys := make(map[string]bool)
	for _, n := range manifest.Nodes {
		if seenIDs[n.ID] {
			return nil, fmt.Errorf("duplicate node ID: %s", n.ID)
		}
		seenIDs[n.ID] = true
		if seenPubKeys[n.WGPublicKey] {
			return nil, fmt.Errorf("duplicate WireGuard public key for node: %s", n.ID)
		}
		seenPubKeys[n.WGPublicKey] = true
	}

	n := len(manifest.Nodes)
	totalTunnels := n * (n - 1) / 2
	configs := make(map[string]string)
	pskMap := make(map[string]string)

	// Pre-compute pairwise PSKs
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			nodeA := manifest.Nodes[i]
			nodeB := manifest.Nodes[j]
			psk, pskErr := DerivePairwisePSK(nodeA.WGPublicKey, nodeB.WGPublicKey, secret, manifest.Epoch)
			if pskErr != nil {
				return nil, fmt.Errorf("failed deriving PSK for %s <-> %s: %w", nodeA.ID, nodeB.ID, pskErr)
			}
			key := fmt.Sprintf("%s<->%s", nodeA.ID, nodeB.ID)
			pskMap[key] = psk
		}
	}

	// Generate per-node configuration
	for i := 0; i < n; i++ {
		node := manifest.Nodes[i]
		var sb strings.Builder

		sb.WriteString(fmt.Sprintf("# WireGuard Mesh Configuration for Node %s (Enclave: %s)\n", node.ID, manifest.EnclaveID))
		sb.WriteString("# Auto-generated by lh-wg-mesh v0.1.0\n\n")
		sb.WriteString("[Interface]\n")
		if node.WGPrivateKey != "" {
			sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", node.WGPrivateKey))
		}
		sb.WriteString(fmt.Sprintf("Address = %s\n", node.TunnelIP))
		listenPort := node.ListenPort
		if listenPort <= 0 {
			listenPort = 51820
		}
		sb.WriteString(fmt.Sprintf("ListenPort = %d\n", listenPort))
		sb.WriteString(fmt.Sprintf("MTU = %d\n\n", mtu))

		// Sort other peers alphabetically for deterministic config output
		otherPeers := make([]MeshNode, 0, n-1)
		for j := 0; j < n; j++ {
			if i != j {
				otherPeers = append(otherPeers, manifest.Nodes[j])
			}
		}
		sort.Slice(otherPeers, func(a, b int) bool {
			return otherPeers[a].ID < otherPeers[b].ID
		})

		for _, peer := range otherPeers {
			pairKey1 := fmt.Sprintf("%s<->%s", node.ID, peer.ID)
			pairKey2 := fmt.Sprintf("%s<->%s", peer.ID, node.ID)
			psk := pskMap[pairKey1]
			if psk == "" {
				psk = pskMap[pairKey2]
			}

			allowedIPs := peer.TunnelIP
			if len(peer.AllowedIPs) > 0 {
				allowedIPs = strings.Join(peer.AllowedIPs, ", ")
			}

			sb.WriteString(fmt.Sprintf("# Peer: %s\n", peer.ID))
			sb.WriteString("[Peer]\n")
			sb.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.WGPublicKey))
			sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", psk))
			sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowedIPs))
			if peer.LANEndpoint != "" {
				sb.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.LANEndpoint))
			}
			sb.WriteString("PersistentKeepalive = 25\n\n")
		}

		configs[node.ID] = sb.String()
	}

	return &MeshTopologySummary{
		EnclaveID:      manifest.EnclaveID,
		TotalNodes:     n,
		TotalTunnels:   totalTunnels,
		Epoch:          manifest.Epoch,
		Configs:        configs,
		PairwisePSKMap: pskMap,
	}, nil
}
