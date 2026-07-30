package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

func createTestResult() *types.ScanResult {
	return &types.ScanResult{
		Target:         "example.com",
		Host:           "example.com",
		Port:           443,
		IP:             "93.184.216.34",
		Timestamp:      time.Now(),
		ScannerVersion: "0.1.0",
		Duration:       types.Duration{Duration: 500 * time.Millisecond},
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true, Preferred: true},
			{Version: "TLS 1.2", Supported: true},
			{Version: "TLS 1.1", Supported: false},
			{Version: "TLS 1.0", Supported: false},
		},
		CipherSuites: []types.CipherSuite{
			{
				ID:             0x1301,
				Name:           "TLS_AES_128_GCM_SHA256",
				Protocol:       "TLS 1.3",
				ForwardSecrecy: true,
				Bits:           128,
				Encryption:     "AES-GCM",
			},
		},
		Certificate: &types.Certificate{
			Subject:            "CN=example.com",
			Issuer:             "CN=DigiCert TLS RSA SHA256 2020 CA1",
			NotBefore:          time.Now().AddDate(0, -6, 0),
			NotAfter:           time.Now().AddDate(0, 6, 0),
			SignatureAlgorithm: "SHA256WithRSA",
			PublicKeyAlgorithm: "RSA",
			PublicKeyBits:      2048,
			DaysUntilExpiry:    180,
		},
		QuantumRisk: types.QuantumRiskAssessment{
			Score:           0,
			Level:           types.RiskCritical,
			KeyExchangeRisk: "CRITICAL",
			CertificateRisk: "HIGH",
			HNDLRisk:        "HIGH",
			TimeToAction:    "IMMEDIATE",
		},
		Grade: types.Grade{
			Letter:       "B",
			Score:        78,
			QuantumGrade: "QV",
			Factors: []types.GradeFactor{
				{Category: "Protocol", Score: 20, MaxScore: 25},
				{Category: "Cipher", Score: 20, MaxScore: 25},
				{Category: "Certificate", Score: 20, MaxScore: 25},
				{Category: "Quantum", Score: 0, MaxScore: 25},
			},
		},
		Vulnerabilities: []types.Vulnerability{
			{
				ID:          "NO_TLS13",
				Name:        "TLS 1.3 Not Supported",
				Severity:    types.SeverityMedium,
				Description: "TLS 1.3 provides improved security.",
				Remediation: "Enable TLS 1.3",
			},
		},
		Recommendations: []types.Recommendation{
			{
				Priority:    1,
				Category:    "quantum",
				Title:       "Enable Hybrid PQC",
				Description: "Enable X25519MLKEM768",
				Impact:      "Quantum protection",
				Effort:      "medium",
			},
		},
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		format   Format
		wantType string
	}{
		{FormatJSON, "json"},
		{FormatText, "text"},
		{FormatSARIF, "sarif"},
		{FormatCBOM, "cbom"},
		{FormatHTML, "html"},
		{Format("unknown"), "text"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			r := New(tt.format)
			if r.Format() != tt.wantType {
				t.Errorf("New(%s).Format() = %s, want %s", tt.format, r.Format(), tt.wantType)
			}
		})
	}
}

func TestValidFormats(t *testing.T) {
	formats := ValidFormats()
	expected := []string{"json", "text", "sarif", "cbom", "html"}

	if len(formats) != len(expected) {
		t.Errorf("ValidFormats() returned %d formats, want %d", len(formats), len(expected))
	}

	for _, exp := range expected {
		found := false
		for _, f := range formats {
			if f == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected format %s not found in ValidFormats()", exp)
		}
	}
}

func TestJSONReporter(t *testing.T) {
	result := createTestResult()
	var buf bytes.Buffer

	r := &JSONReporter{}
	err := r.Report(&buf, result)
	if err != nil {
		t.Fatalf("JSONReporter.Report() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check key fields
	if parsed["target"] != "example.com" {
		t.Error("expected target to be example.com")
	}
	if parsed["host"] != "example.com" {
		t.Error("expected host to be example.com")
	}
}

func TestJSONReporterCompact(t *testing.T) {
	result := createTestResult()
	var buf bytes.Buffer

	r := &JSONReporter{Compact: true}
	err := r.Report(&buf, result)
	if err != nil {
		t.Fatalf("JSONReporter.Report() error = %v", err)
	}

	// Compact JSON should not have newlines except at the end
	output := strings.TrimSpace(buf.String())
	if strings.Count(output, "\n") > 0 {
		t.Error("compact JSON should not have internal newlines")
	}
}

func TestTextReporter(t *testing.T) {
	result := createTestResult()
	var buf bytes.Buffer

	r := &TextReporter{NoColor: true}
	err := r.Report(&buf, result)
	if err != nil {
		t.Fatalf("TextReporter.Report() error = %v", err)
	}

	output := buf.String()

	// Check key sections are present
	sections := []string{
		"QRAMM TLS Analyzer",
		"OVERALL GRADE",
		"PROTOCOL SUPPORT",
		"CIPHER SUITES",
		"CERTIFICATE",
		"QUANTUM RISK ASSESSMENT",
	}

	for _, section := range sections {
		if !strings.Contains(output, section) {
			t.Errorf("output missing section: %s", section)
		}
	}

	// Check target is displayed
	if !strings.Contains(output, "example.com") {
		t.Error("output missing target")
	}
}

func TestTextReporterWithColor(t *testing.T) {
	result := createTestResult()
	var buf bytes.Buffer

	r := &TextReporter{NoColor: false}
	err := r.Report(&buf, result)
	if err != nil {
		t.Fatalf("TextReporter.Report() error = %v", err)
	}

	output := buf.String()

	// Should contain ANSI escape codes
	if !strings.Contains(output, "\033[") {
		t.Error("expected ANSI color codes in output")
	}
}

func TestSARIFReporter(t *testing.T) {
	result := createTestResult()
	var buf bytes.Buffer

	r := &SARIFReporter{}
	err := r.Report(&buf, result)
	if err != nil {
		t.Fatalf("SARIFReporter.Report() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check SARIF schema
	if parsed["$schema"] == nil {
		t.Error("SARIF output missing $schema")
	}
	if parsed["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", parsed["version"])
	}

	// Check runs
	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Error("SARIF output missing runs")
	}

	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})

	if driver["name"] != "qramm-tls-analyzer" {
		t.Errorf("expected tool name qramm-tls-analyzer, got %v", driver["name"])
	}
}

func TestSeverityToSARIF(t *testing.T) {
	tests := []struct {
		severity types.Severity
		want     string
	}{
		{types.SeverityCritical, "error"},
		{types.SeverityHigh, "error"},
		{types.SeverityMedium, "warning"},
		{types.SeverityLow, "note"},
		{types.Severity("unknown"), "none"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if got := severityToSARIF(tt.severity); got != tt.want {
				t.Errorf("severityToSARIF(%s) = %s, want %s", tt.severity, got, tt.want)
			}
		})
	}
}

func TestCBOMReporter(t *testing.T) {
	result := createTestResult()
	var buf bytes.Buffer

	r := &CBOMReporter{}
	err := r.Report(&buf, result)
	if err != nil {
		t.Fatalf("CBOMReporter.Report() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("CBOM output is not valid JSON: %v", err)
	}

	// Check CycloneDX structure
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat CycloneDX, got %v", parsed["bomFormat"])
	}
	if parsed["specVersion"] != "1.6" {
		t.Errorf("expected specVersion 1.6, got %v", parsed["specVersion"])
	}

	// Check serial number format
	serialNum, ok := parsed["serialNumber"].(string)
	if !ok || !strings.HasPrefix(serialNum, "urn:uuid:") {
		t.Error("CBOM should have urn:uuid serial number")
	}

	// Check components exist
	components, ok := parsed["components"].([]interface{})
	if !ok {
		t.Error("CBOM output missing components")
	}
	if len(components) == 0 {
		t.Error("CBOM should have at least one component")
	}

	// Check services exist
	services, ok := parsed["services"].([]interface{})
	if !ok || len(services) == 0 {
		t.Error("CBOM output should have services")
	}
}

func TestCBOMReporterFormat(t *testing.T) {
	r := &CBOMReporter{}
	if r.Format() != "cbom" {
		t.Errorf("CBOMReporter.Format() = %s, want cbom", r.Format())
	}
}

func TestHTMLReporter(t *testing.T) {
	result := createTestResult()
	var buf bytes.Buffer

	r := &HTMLReporter{IncludeCSS: true}
	err := r.Report(&buf, result)
	if err != nil {
		t.Fatalf("HTMLReporter.Report() error = %v", err)
	}

	output := buf.String()

	// Check HTML structure
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}
	if !strings.Contains(output, "<html") {
		t.Error("HTML output missing html tag")
	}
	if !strings.Contains(output, "</html>") {
		t.Error("HTML output missing closing html tag")
	}

	// Check key sections
	sections := []string{
		"QRAMM TLS Analysis Report",
		"example.com",
		"Quantum Risk",
		"Protocol Support",
	}
	for _, section := range sections {
		if !strings.Contains(output, section) {
			t.Errorf("HTML output missing section: %s", section)
		}
	}

	// Check CSS is included
	if !strings.Contains(output, "<style>") {
		t.Error("HTML output missing embedded CSS")
	}
}

func TestHTMLReporterFormat(t *testing.T) {
	r := &HTMLReporter{}
	if r.Format() != "html" {
		t.Errorf("HTMLReporter.Format() = %s, want html", r.Format())
	}
}

// TestTextReporterDoesNotGradeAnUnscannedTarget guards the defect where batch
// mode rendered a host it never reached as a finished assessment.
//
// The error travels on the result rather than as a returned error, so the grade
// block ran on a zero-valued Grade and printed "TLS Security: (0/100)" with a
// blank letter, a quantum score of 0 and an unticked hybrid PQC line, for a host
// that did not resolve. In a --targets sweep every typo or DNS blip became a
// confident failing row. JSON carried the reason all along; text, the default
// format, discarded it.
func TestTextReporterDoesNotGradeAnUnscannedTarget(t *testing.T) {
	result := &types.ScanResult{
		Target:    "nonexistent.invalid",
		Host:      "nonexistent.invalid",
		Timestamp: time.Now(),
		Error:     "cannot resolve nonexistent.invalid: no such host",
	}

	var buf bytes.Buffer
	if err := (&TextReporter{NoColor: true}).Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}
	out := buf.String()

	// The reason must reach the default format.
	if !strings.Contains(out, "cannot resolve nonexistent.invalid") {
		t.Error("the text report does not state why the target was not scanned, so a " +
			"reader of the default format cannot tell a failure from a finding")
	}

	// And nothing that reads as a measurement may appear.
	for _, forbidden := range []string{
		"TLS Security:",
		"Score Breakdown",
		"Dimension subtotal",
		"Quantum Score",
		"OVERALL GRADE",
	} {
		if strings.Contains(out, forbidden) {
			t.Errorf("a target that was never reached still prints %q, which presents an "+
				"unmeasured host as a graded one", forbidden)
		}
	}

	// Specifically: the skipped-checks label must not appear. A zero-valued Grade
	// leaves VulnerabilitiesAssessed false, which made an error row claim
	// "upper bound, vulnerability checks skipped" when no such flag was passed.
	if strings.Contains(strings.ToLower(out), "upper bound") {
		t.Error("an unscanned target is labelled an upper bound, which describes a flag " +
			"the user never passed")
	}

	// Acceptance control: a real result must still be graded, or the guard above
	// is satisfied by never printing a grade at all.
	scanned := &types.ScanResult{
		Target:    "example.com",
		Timestamp: time.Now(),
		Protocols: []types.Protocol{{Version: "TLS 1.3", Supported: true}},
		Grade: types.Grade{
			Letter: "A", Score: 91, QuantumGrade: "Q",
			DimensionScore: 91, DimensionPoints: 91, DimensionMaxPoints: 100,
			VulnerabilitiesAssessed: true,
		},
	}
	var scannedBuf bytes.Buffer
	if err := (&TextReporter{NoColor: true}).Report(&scannedBuf, scanned); err != nil {
		t.Fatalf("report: %v", err)
	}
	if !strings.Contains(scannedBuf.String(), "TLS Security:") {
		t.Error("a scanned target no longer prints a grade, so the error-path guard is too broad")
	}
}
