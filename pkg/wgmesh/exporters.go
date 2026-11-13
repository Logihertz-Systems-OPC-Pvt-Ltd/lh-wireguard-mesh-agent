package wgmesh

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// RenderTable emits an ANSI terminal box table representing the audit report.
func RenderTable(w io.Writer, report *PostureReport) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "========================================================================================")
	fmt.Fprintln(w, "  LOGIHERTZ WIREGUARD AIR-GAPPED MESH AUDITOR (lh-wg-mesh v0.1.0)")
	fmt.Fprintln(w, "========================================================================================")
	fmt.Fprintf(w, "  Policy ID: %-20s  Enclave: %s\n", report.PolicyID, report.EnclaveID)
	fmt.Fprintf(w, "  Overall Posture Score:  %d / 100    Verdict: %s\n", report.Score, report.Verdict)
	fmt.Fprintf(w, "  Rules Passed: %d/10  |  Rules Failed: %d/10  |  Total Deductions: -%d\n\n",
		report.PassedCount, report.FailedCount, report.TotalDeductions)

	fmt.Fprintln(w, "┌──────────────┬──────────┬────────┬───────┬─────────────────────────────────────────────┐")
	fmt.Fprintln(w, "│ Rule ID      │ Severity │ Status │ Deduct│ Rule Title & Description                    │")
	fmt.Fprintln(w, "├──────────────┼──────────┼────────┼───────┼─────────────────────────────────────────────┤")

	for _, f := range report.Findings {
		status := " PASS "
		deductStr := "-0   "
		if !f.Passed {
			status = " FAIL "
			deductStr = fmt.Sprintf("-%-4d", f.Deduction)
		}

		titleTrunc := f.Title
		if len(titleTrunc) > 43 {
			titleTrunc = titleTrunc[:40] + "..."
		}

		fmt.Fprintf(w, "│ %-12s │ %-8s │ %s │ %s │ %-43s │\n",
			f.RuleID, f.Severity, status, deductStr, titleTrunc)

		if !f.Passed {
			remedTrunc := f.Remediation
			if len(remedTrunc) > 70 {
				remedTrunc = remedTrunc[:67] + "..."
			}
			fmt.Fprintf(w, "│              └─► Remediation: %-59s │\n", remedTrunc)
		}
	}

	fmt.Fprintln(w, "└──────────────┴──────────┴────────┴───────┴─────────────────────────────────────────────┘")
	fmt.Fprintln(w)
}

// RenderJSON serializes the PostureReport to formatted JSON.
func RenderJSON(w io.Writer, report *PostureReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// SARIF Structures for OASIS SARIF v2.1.0
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	ShortDescription sarifMultiformatText `json:"shortDescription"`
	Help             sarifMultiformatText `json:"help"`
}

type sarifMultiformatText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string               `json:"ruleId"`
	Level   string               `json:"level"` // error, warning, note
	Message sarifMultiformatText `json:"message"`
}

// RenderSARIF serializes the audit report to OASIS SARIF v2.1.0 format.
func RenderSARIF(w io.Writer, report *PostureReport) error {
	rules := make([]sarifRule, 0, len(report.Findings))
	results := make([]sarifResult, 0, report.FailedCount)

	for _, f := range report.Findings {
		rules = append(rules, sarifRule{
			ID:               f.RuleID,
			Name:             f.Title,
			ShortDescription: sarifMultiformatText{Text: f.Title},
			Help:             sarifMultiformatText{Text: fmt.Sprintf("CWE: %s. Remediation: %s", f.CWE, f.Remediation)},
		})

		if !f.Passed {
			level := "warning"
			switch strings.ToUpper(f.Severity) {
			case "CRITICAL", "HIGH":
				level = "error"
			case "MEDIUM":
				level = "warning"
			case "LOW":
				level = "note"
			}

			results = append(results, sarifResult{
				RuleID:  f.RuleID,
				Level:   level,
				Message: sarifMultiformatText{Text: f.Message},
			})
		}
	}

	doc := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "lh-wg-mesh",
						Version:        "0.1.0",
						InformationURI: "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-wireguard-mesh-agent",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}
