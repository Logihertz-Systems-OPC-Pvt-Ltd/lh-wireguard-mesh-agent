package wgmesh

import (
	"encoding/json"
	"fmt"
	"os"
)

// MeshPolicy encapsulates runtime and configuration settings for a WireGuard mesh deployment.
type MeshPolicy struct {
	PolicyID                   string `json:"policy_id"`
	EnclaveID                  string `json:"enclave_id"`
	EnforceSlash32PeerRoutes   bool   `json:"enforce_slash32_peer_routes"`
	AllowWildcardDefaultRoute  bool   `json:"allow_wildcard_default_route"`
	PresharedKeyEnabled        bool   `json:"preshared_key_enabled"`
	UniquePairwisePSK          bool   `json:"unique_pairwise_psk"`
	Ed25519SignedDiscovery     bool   `json:"ed25519_signed_discovery"`
	AllowUnverifiedPeerJoin    bool   `json:"allow_unverified_peer_join"`
	MaxBeaconSkewSeconds       int64  `json:"max_beacon_skew_seconds"`
	MonotonicSequenceGuard     bool   `json:"monotonic_sequence_guard"`
	AllowExternalSTUNDERP      bool   `json:"allow_external_stun_derp"`
	AirgapLocalEndpointsOnly   bool   `json:"airgap_local_endpoints_only"`
	ConfigFileModeOctal        int    `json:"config_file_mode_octal"`
	PrivateKeyViaCLIArgv       bool   `json:"private_key_via_cli_argv"`
	PSKRotationIntervalHours   int    `json:"psk_rotation_interval_hours"`
	EvictStalePeersSeconds     int    `json:"evict_stale_peers_seconds"`
	TunnelMTU                  int    `json:"tunnel_mtu"`
	PersistentKeepaliveSeconds int    `json:"persistent_keepalive_seconds"`
	ControlSocketLoopbackOnly  bool   `json:"control_socket_loopback_only"`
	EnforceNftablesWGZone      bool   `json:"enforce_nftables_wg_zone"`
	DetectAllowedIPsOverlap    bool   `json:"detect_allowed_ips_overlap"`
	LogHandshakeFailures       bool   `json:"log_handshake_failures"`
}

// PostureFinding represents the evaluation result of an individual security rule.
type PostureFinding struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Deduction   int    `json:"deduction"`
	CWE         string `json:"cwe"`
	Passed      bool   `json:"passed"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// PostureReport aggregates the complete audit results across all 10 normative rules.
type PostureReport struct {
	PolicyID        string           `json:"policy_id"`
	EnclaveID       string           `json:"enclave_id"`
	Score           int              `json:"score"`
	Verdict         string           `json:"verdict"` // HARDENED, ADEQUATE, VULNERABLE, CRITICAL
	TotalDeductions int              `json:"total_deductions"`
	PassedCount     int              `json:"passed_count"`
	FailedCount     int              `json:"failed_count"`
	Findings        []PostureFinding `json:"findings"`
}

// LoadPolicyFromFile loads and decodes a MeshPolicy from a JSON file.
func LoadPolicyFromFile(path string) (*MeshPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading policy file: %w", err)
	}
	var policy MeshPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed parsing policy JSON: %w", err)
	}
	return &policy, nil
}

// AuditMeshPolicy audits a MeshPolicy against all 10 normative security rules.
func AuditMeshPolicy(policy *MeshPolicy) *PostureReport {
	report := &PostureReport{
		PolicyID:  policy.PolicyID,
		EnclaveID: policy.EnclaveID,
		Findings:  make([]PostureFinding, 0, 10),
	}

	totalDeductions := 0

	// Rule 1: LH-WGM-001 (CRITICAL, 25, CWE-284)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-001",
			Title:       "Strict Host-Route Isolation & Wildcard Route Guard",
			Severity:    "CRITICAL",
			Deduction:   25,
			CWE:         "CWE-284",
			Remediation: "Enforce strict /32 (IPv4) or /128 (IPv6) peer AllowedIPs and prohibit default wildcard routes.",
		}
		if policy.EnforceSlash32PeerRoutes && !policy.AllowWildcardDefaultRoute {
			f.Passed = true
			f.Message = "Strict /32 host routing active; default wildcard route capture prohibited."
		} else {
			f.Passed = false
			f.Message = "Wildcard route capture permitted or /32 peer route restriction disabled; risk of total network hijack."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 2: LH-WGM-002 (CRITICAL, 25, CWE-326)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-002",
			Title:       "Post-Quantum Pairwise Noise_IKpsk2 Pre-Shared Key Enforcement",
			Severity:    "CRITICAL",
			Deduction:   25,
			CWE:         "CWE-326",
			Remediation: "Mandate symmetric 256-bit PresharedKey derivation with unique keys per peer pair.",
		}
		if policy.PresharedKeyEnabled && policy.UniquePairwisePSK {
			f.Passed = true
			f.Message = "Pairwise post-quantum Noise_IKpsk2 symmetric pre-shared keys enforced across all peer links."
		} else {
			f.Passed = false
			f.Message = "Pre-shared keys disabled or static shared PSK reused across peers; vulnerable to harvest-now-decrypt-later."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 3: LH-WGM-003 (CRITICAL, 25, CWE-306)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-003",
			Title:       "Cryptographic Ed25519 Peer Discovery Beacon Authentication",
			Severity:    "CRITICAL",
			Deduction:   25,
			CWE:         "CWE-306",
			Remediation: "Enforce cryptographic Ed25519 digital signatures on all LAN discovery beacons and reject unverified peers.",
		}
		if policy.Ed25519SignedDiscovery && !policy.AllowUnverifiedPeerJoin {
			f.Passed = true
			f.Message = "Ed25519 signed discovery beacons active; unverified peer join strictly rejected."
		} else {
			f.Passed = false
			f.Message = "Unauthenticated discovery active or rogue nodes permitted to join mesh without signature verification."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 4: LH-WGM-004 (HIGH, 10, CWE-294)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-004",
			Title:       "Anti-Replay Timestamp Window & Monotonic Sequence Number Guard",
			Severity:    "HIGH",
			Deduction:   10,
			CWE:         "CWE-294",
			Remediation: "Restrict beacon timestamp skew to <= 30 seconds and enforce strictly monotonic sequence counters.",
		}
		if policy.MaxBeaconSkewSeconds <= 30 && policy.MonotonicSequenceGuard {
			f.Passed = true
			f.Message = "Anti-replay protection active: timestamp skew bounded to <= 30s with monotonic sequence tracking."
		} else {
			f.Passed = false
			f.Message = "Excessive beacon timestamp skew (> 30s) or monotonic sequence guard disabled; vulnerable to topology replay."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 5: LH-WGM-005 (HIGH, 10, CWE-319)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-005",
			Title:       "Air-Gapped Sovereign Enclave Isolation Against External Relay Leaks",
			Severity:    "HIGH",
			Deduction:   10,
			CWE:         "CWE-319",
			Remediation: "Disable external STUN/TURN/DERP relays and bind exclusively to verified air-gapped local endpoints.",
		}
		if !policy.AllowExternalSTUNDERP && policy.AirgapLocalEndpointsOnly {
			f.Passed = true
			f.Message = "Air-gapped enclave isolated: external STUN/TURN/DERP coordination disabled."
		} else {
			f.Passed = false
			f.Message = "External cloud relay coordination enabled or non-local endpoints permitted in air-gapped network."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 6: LH-WGM-006 (HIGH, 10, CWE-276)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-006",
			Title:       "Strict WireGuard Configuration & Private Key Filesystem Permissions",
			Severity:    "HIGH",
			Deduction:   10,
			CWE:         "CWE-276",
			Remediation: "Restrict WireGuard configuration file permissions to mode 0600 and never expose private keys in process arguments.",
		}
		if policy.ConfigFileModeOctal == 600 && !policy.PrivateKeyViaCLIArgv {
			f.Passed = true
			f.Message = "Strict file mode 0600 enforced for wg0.conf; private keys safeguarded from process table inspection."
		} else {
			f.Passed = false
			f.Message = "Permissive configuration file permissions (not 0600) or private keys passed via CLI arguments."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 7: LH-WGM-007 (HIGH, 10, CWE-324)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-007",
			Title:       "Periodic Pairwise PSK Rotation & Stale Peer Eviction Thresholds",
			Severity:    "HIGH",
			Deduction:   10,
			CWE:         "CWE-324",
			Remediation: "Schedule pairwise PSK rotation intervals <= 168 hours (7 days) and evict inactive peers within 600 seconds.",
		}
		if policy.PSKRotationIntervalHours <= 168 && policy.EvictStalePeersSeconds <= 600 {
			f.Passed = true
			f.Message = "Periodic PSK rotation (<= 168h) and stale peer eviction (<= 600s) actively configured."
		} else {
			f.Passed = false
			f.Message = "Excessive PSK rotation interval (> 168h) or inactive peers retained longer than 600 seconds."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 8: LH-WGM-008 (MEDIUM, 4, CWE-400)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-008",
			Title:       "Optimal Tunnel MTU & Persistent Keepalive Tuning",
			Severity:    "MEDIUM",
			Deduction:   4,
			CWE:         "CWE-400",
			Remediation: "Configure tunnel MTU within 1280-1420 bytes and set persistent keepalive interval between 15-60 seconds.",
		}
		if policy.TunnelMTU >= 1280 && policy.TunnelMTU <= 1420 &&
			policy.PersistentKeepaliveSeconds >= 15 && policy.PersistentKeepaliveSeconds <= 60 {
			f.Passed = true
			f.Message = "Optimal WireGuard tunnel MTU (1280-1420) and persistent keepalive (15-60s) configured."
		} else {
			f.Passed = false
			f.Message = "Non-optimal tunnel MTU (< 1280 or > 1420) or keepalive interval outside 15-60 second bounds."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 9: LH-WGM-009 (MEDIUM, 4, CWE-200)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-009",
			Title:       "Loopback-Only Control Socket & nftables Interface Zone Isolation",
			Severity:    "MEDIUM",
			Deduction:   4,
			CWE:         "CWE-200",
			Remediation: "Bind mesh control sockets strictly to 127.0.0.1 and enforce dedicated nftables interface zone filtering.",
		}
		if policy.ControlSocketLoopbackOnly && policy.EnforceNftablesWGZone {
			f.Passed = true
			f.Message = "Control socket bound strictly to loopback (127.0.0.1) with nftables interface zone isolation enforced."
		} else {
			f.Passed = false
			f.Message = "Control socket exposed on non-loopback interface or nftables interface zone isolation missing."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 10: LH-WGM-010 (LOW, 1, CWE-778)
	{
		f := PostureFinding{
			RuleID:      "LH-WGM-010",
			Title:       "AllowedIPs Overlap Pre-Flight Validation & Handshake Failure SIEM Logging",
			Severity:    "LOW",
			Deduction:   1,
			CWE:         "CWE-778",
			Remediation: "Enable automated AllowedIPs routing conflict pre-checks and stream handshake failure telemetry to SIEM.",
		}
		if policy.DetectAllowedIPsOverlap && policy.LogHandshakeFailures {
			f.Passed = true
			f.Message = "AllowedIPs route conflict pre-flight validation and SIEM handshake failure telemetry active."
		} else {
			f.Passed = false
			f.Message = "AllowedIPs overlap pre-check disabled or handshake failure telemetry not logged to SIEM."
			totalDeductions += f.Deduction
		}
		report.Findings = append(report.Findings, f)
	}

	report.TotalDeductions = totalDeductions
	score := 100 - totalDeductions
	if score < 0 {
		score = 0
	}
	report.Score = score

	passedCount := 0
	for _, f := range report.Findings {
		if f.Passed {
			passedCount++
		}
	}
	report.PassedCount = passedCount
	report.FailedCount = len(report.Findings) - passedCount

	if score >= 90 {
		report.Verdict = "HARDENED (Sovereign Air-Gapped Mesh Resilient)"
	} else if score >= 70 {
		report.Verdict = "ADEQUATE (Minor Operational Vulnerabilities Present)"
	} else if score >= 50 {
		report.Verdict = "VULNERABLE (Elevated Routing or Cryptographic Risk)"
	} else {
		report.Verdict = "CRITICAL (Severe Mesh Exploitation Vulnerabilities Detected)"
	}

	return report
}
