package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-wireguard-mesh-agent/pkg/wgmesh"
)

const (
	ToolVersion = "0.1.0"
	ToolName    = "lh-wg-mesh"
)

func printVersion() {
	fmt.Printf("%s %s (Logihertz Air-Gapped WireGuard Mesh Coordinator)\n", ToolName, ToolVersion)
}

func printHelp() {
	printVersion()
	fmt.Print(`
USAGE:
    lh-wg-mesh <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    scan <policy.json>                Audit WireGuard mesh security posture against 10 rules
    gen-mesh <enclave_nodes.json>     Synthesize full-mesh N(N-1)/2 configs with pairwise PQ-PSKs
    check-routes <enclave_nodes.json> Verify strict /32 AllowedIPs disjointness & detect route hijacking
    verify-beacon [OPTIONS]           Sign and verify an air-gapped Ed25519 peer discovery beacon

OPTIONS:
    --format <table|json|sarif>       Output format for scan results (default: table)
    --output <file>                   Write output to file instead of stdout
    --output-dir <dir>                Directory to write generated .conf files in gen-mesh
    --epoch <uint>                    Epoch number for pairwise PSK rotation (default: 0)
    -h, --help                        Display this help text
    -V, --version                     Display version information

BEACON VERIFICATION OPTIONS:
    --node-id <id>                    Peer Node ID
    --wg-pub <base64>                 WireGuard 32-byte Base64 Public Key
    --cidr <ip/mask>                  Tunnel IP CIDR (e.g. 10.99.0.1/32)
    --endpoint <ip:port>              Local LAN Endpoint (e.g. 192.168.10.11:51820)
    --seq <uint64>                    Beacon sequence number
    --timestamp <unix>                Beacon timestamp (defaults to current time)

EXAMPLES:
    # Audit mesh policy manifest:
    lh-wg-mesh scan fixtures/hardened_wgmesh_policy.json --format table

    # Export SARIF report for CI/CD security integration:
    lh-wg-mesh scan fixtures/vulnerable_wgmesh_policy.json --format sarif --output report.sarif

    # Generate full-mesh WireGuard configurations:
    lh-wg-mesh gen-mesh fixtures/sample_enclave_nodes.json --epoch 1

    # Check for AllowedIPs overlaps or default wildcard hijacking:
    lh-wg-mesh check-routes fixtures/sample_enclave_nodes.json

    # Verify discovery beacon:
    lh-wg-mesh verify-beacon --node-id node-alpha --wg-pub "2V5q0d6f4R...=" --cidr 10.99.0.1/32 --endpoint 192.168.10.11:51820 --seq 1
`)
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(2)
	}

	arg1 := os.Args[1]
	if arg1 == "-V" || arg1 == "--version" {
		printVersion()
		os.Exit(0)
	}
	if arg1 == "-h" || arg1 == "--help" {
		printHelp()
		os.Exit(0)
	}

	switch arg1 {
	case "scan":
		runScan(os.Args[2:])
	case "gen-mesh":
		runGenMesh(os.Args[2:])
	case "check-routes":
		runCheckRoutes(os.Args[2:])
	case "verify-beacon":
		runVerifyBeacon(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown subcommand %q\n\n", arg1)
		printHelp()
		os.Exit(2)
	}
}

func partitionArgs(args []string, flagsWithVal map[string]bool) ([]string, []string) {
	var flagArgs, posArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			name := strings.TrimLeft(arg, "-")
			if strings.Contains(name, "=") {
				continue
			}
			if flagsWithVal != nil && flagsWithVal[name] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	return flagArgs, posArgs
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "table", "Output format (table, json, sarif)")
	output := fs.String("output", "", "Output file path")

	flagArgs, posArgs := partitionArgs(args, map[string]bool{"format": true, "output": true})
	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(2)
	}

	if len(posArgs) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing policy JSON file path")
		os.Exit(2)
	}
	policyFile := posArgs[0]

	policy, err := wgmesh.LoadPolicyFromFile(policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading policy: %v\n", err)
		os.Exit(2)
	}

	report := wgmesh.AuditMeshPolicy(policy)

	var dest io.Writer = os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(2)
		}
		defer f.Close()
		dest = f
	}

	switch strings.ToLower(*format) {
	case "table":
		wgmesh.RenderTable(dest, report)
	case "json":
		if err := wgmesh.RenderJSON(dest, report); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(2)
		}
	case "sarif":
		if err := wgmesh.RenderSARIF(dest, report); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding SARIF: %v\n", err)
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid format %q. Expected table, json, or sarif\n", *format)
		os.Exit(2)
	}

	if report.FailedCount > 0 || report.Score < 100 {
		os.Exit(1)
	}
	os.Exit(0)
}

func runGenMesh(args []string) {
	fs := flag.NewFlagSet("gen-mesh", flag.ContinueOnError)
	epochFlag := fs.Uint64("epoch", 0, "Rotation epoch for pairwise PSK derivation")
	outputDir := fs.String("output-dir", "", "Directory to write .conf files")

	flagArgs, posArgs := partitionArgs(args, map[string]bool{"epoch": true, "output-dir": true})
	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(2)
	}

	if len(posArgs) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing enclave manifest JSON file path")
		os.Exit(2)
	}
	manifestFile := posArgs[0]

	data, err := os.ReadFile(manifestFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading manifest: %v\n", err)
		os.Exit(2)
	}

	var manifest wgmesh.EnclaveManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing manifest JSON: %v\n", err)
		os.Exit(2)
	}

	if *epochFlag > 0 {
		manifest.Epoch = *epochFlag
	}

	summary, err := wgmesh.GenerateMeshConfigs(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating mesh configs: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("========================================================================================")
	fmt.Println("  LOGIHERTZ FULL-MESH WIREGUARD SYNTHESIS REPORT")
	fmt.Println("========================================================================================")
	fmt.Fprintf(wLine("Enclave ID:        %s\n", summary.EnclaveID))
	fmt.Fprintf(wLine("Total Mesh Nodes:  %d\n", summary.TotalNodes))
	fmt.Fprintf(wLine("Total P2P Tunnels: %d (N*(N-1)/2)\n", summary.TotalTunnels))
	fmt.Fprintf(wLine("PSK Epoch:         %d\n", summary.Epoch))
	fmt.Println()
	fmt.Println("Pairwise Symmetric Post-Quantum Pre-Shared Keys (Noise_IKpsk2):")
	for pair, psk := range summary.PairwisePSKMap {
		fmt.Printf("  • %-25s -> PSK: %s\n", pair, psk)
	}
	fmt.Println()

	if *outputDir != "" {
		if err := os.MkdirAll(*outputDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
			os.Exit(2)
		}
		for nodeID, cfg := range summary.Configs {
			fileName := filepath.Join(*outputDir, fmt.Sprintf("%s.conf", nodeID))
			if err := os.WriteFile(fileName, []byte(cfg), 0600); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing config %s: %v\n", fileName, err)
				os.Exit(2)
			}
			fmt.Printf("Wrote node config (mode 0600): %s\n", fileName)
		}
	} else {
		fmt.Println("Generated Configuration Samples:")
		for nodeID, cfg := range summary.Configs {
			fmt.Println("----------------------------------------------------------------------------------------")
			fmt.Printf("Node Configuration: %s (/etc/wireguard/wg0.conf)\n", nodeID)
			fmt.Println("----------------------------------------------------------------------------------------")
			fmt.Println(cfg)
		}
	}

	os.Exit(0)
}

func wLine(format string, a ...interface{}) (io.Writer, string) {
	return os.Stdout, fmt.Sprintf(format, a...)
}

func runCheckRoutes(args []string) {
	fs := flag.NewFlagSet("check-routes", flag.ContinueOnError)
	flagArgs, posArgs := partitionArgs(args, nil)
	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(2)
	}

	if len(posArgs) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing enclave manifest JSON file path")
		os.Exit(2)
	}
	manifestFile := posArgs[0]

	data, err := os.ReadFile(manifestFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading manifest: %v\n", err)
		os.Exit(2)
	}

	var manifest wgmesh.EnclaveManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing manifest JSON: %v\n", err)
		os.Exit(2)
	}

	violations := wgmesh.ValidateAllowedIPs(manifest.Nodes)

	fmt.Println()
	fmt.Println("========================================================================================")
	fmt.Println("  LOGIHERTZ ALLOWED-IPS ROUTE HIJACK & OVERLAP INSPECTION REPORT")
	fmt.Println("========================================================================================")
	fmt.Printf("  Inspected Nodes: %d | Route Violations Found: %d\n\n", len(manifest.Nodes), len(violations))

	if len(violations) > 0 {
		for i, v := range violations {
			fmt.Printf("[%d] VIOLATION: %s\n", i+1, v.ViolationType)
			fmt.Printf("    Node:        %s\n", v.NodeA)
			if v.NodeB != "" {
				fmt.Printf("    Conflicting: %s\n", v.NodeB)
			}
			fmt.Printf("    CIDR A:      %s\n", v.CIDRA)
			if v.CIDRB != "" {
				fmt.Printf("    CIDR B:      %s\n", v.CIDRB)
			}
			fmt.Printf("    Description: %s\n\n", v.Description)
		}
		os.Exit(1)
	}

	fmt.Println("  [CLEAN] All peer AllowedIPs are strictly disjoint host routes (/32 or /128).")
	fmt.Println("  [CLEAN] Zero wildcard route captures (0.0.0.0/0) detected.")
	fmt.Println("========================================================================================")
	os.Exit(0)
}

func runVerifyBeacon(args []string) {
	fs := flag.NewFlagSet("verify-beacon", flag.ContinueOnError)
	nodeID := fs.String("node-id", "node-alpha", "Node ID")
	wgPub := fs.String("wg-pub", "", "WireGuard public key")
	cidr := fs.String("cidr", "10.99.0.1/32", "Tunnel IP CIDR")
	endpoint := fs.String("endpoint", "192.168.10.11:51820", "LAN endpoint")
	seq := fs.Uint64("seq", 1, "Sequence number")
	tsFlag := fs.String("timestamp", "", "Unix timestamp (empty for now)")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if *wgPub == "" {
		// Generate an ephemeral WireGuard-like key for testing if omitted
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		*wgPub = base64.StdEncoding.EncodeToString(raw)
	}

	ts := time.Now().Unix()
	if *tsFlag != "" {
		parsedTS, err := strconv.ParseInt(*tsFlag, 10, 64)
		if err == nil {
			ts = parsedTS
		}
	}

	// Create Ed25519 keypair for beacon signing and verification
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating Ed25519 keypair: %v\n", err)
		os.Exit(2)
	}

	beacon := wgmesh.DiscoveryBeacon{
		NodeID:        *nodeID,
		WGPublicKey:   *wgPub,
		TunnelIPCIDR:  *cidr,
		LANEndpoint:   *endpoint,
		SequenceNum:   *seq,
		TimestampUnix: ts,
	}

	if err := wgmesh.SignDiscoveryBeacon(&beacon, privKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error signing beacon: %v\n", err)
		os.Exit(2)
	}

	// Verify beacon
	if err := wgmesh.VerifyDiscoveryBeacon(beacon, pubKey, 30, 0); err != nil {
		fmt.Println("========================================================================================")
		fmt.Println("  ED25519 DISCOVERY BEACON VERIFICATION FAILED")
		fmt.Println("========================================================================================")
		fmt.Printf("  Failure Reason: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("========================================================================================")
	fmt.Println("  ED25519 AIR-GAPPED DISCOVERY BEACON VERIFIED AUTHENTIC")
	fmt.Println("========================================================================================")
	fmt.Printf("  Node ID:         %s\n", beacon.NodeID)
	fmt.Printf("  WG Public Key:   %s\n", beacon.WGPublicKey)
	fmt.Printf("  Tunnel CIDR:     %s\n", beacon.TunnelIPCIDR)
	fmt.Printf("  LAN Endpoint:    %s\n", beacon.LANEndpoint)
	fmt.Printf("  Sequence Number: %d\n", beacon.SequenceNum)
	fmt.Printf("  Timestamp Unix:  %d (%s)\n", beacon.TimestampUnix, time.Unix(beacon.TimestampUnix, 0).UTC().Format(time.RFC3339))
	fmt.Printf("  Ed25519 Sig:     %s\n", beacon.Signature)
	fmt.Println("  Status:          VERIFIED_AUTHENTIC (Integrity & Nonce Valid)")
	fmt.Println("========================================================================================")
	os.Exit(0)
}
