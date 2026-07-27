package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// TextReporter outputs human-readable text.
type TextReporter struct {
	NoColor bool
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// Report writes the scan result as formatted text.
func (r *TextReporter) Report(w io.Writer, result *types.ScanResult) error {
	// Header
	r.printHeader(w, result)

	// Grade summary
	r.printGrade(w, result.Grade)

	// Policy result (if evaluated)
	if result.PolicyResult != nil {
		r.printPolicyResult(w, result.PolicyResult)
	}

	// CNSA 2.0 Timeline (if analyzed)
	if result.CNSA2Timeline != nil {
		r.printCNSA2Timeline(w, result.CNSA2Timeline)
	}

	// Protocols
	r.printProtocols(w, result.Protocols)

	// Cipher suites
	r.printCipherSuites(w, result.CipherSuites)

	// Certificate
	if result.Certificate != nil {
		r.printCertificate(w, result.Certificate)
	}

	// Quantum risk assessment. Omitted entirely when it was not run, rather
	// than rendered from a zero-valued assessment, which reported a server with
	// hybrid ML-KEM key exchange as quantum vulnerable.
	if result.Grade.QuantumGrade != "not assessed" {
		r.printQuantumRisk(w, result.QuantumRisk)
	}

	// Vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		r.printVulnerabilities(w, result.Vulnerabilities)
	}

	// Recommendations
	if len(result.Recommendations) > 0 {
		r.printRecommendations(w, result.Recommendations)
	}

	// Scan coverage limits. Text is the default format, so warnings that exist
	// only in JSON are invisible to most users, which is precisely where a
	// caveat is needed to stop an unmeasured value being read as a measured one.
	if len(result.ScanWarnings) > 0 {
		r.printScanWarnings(w, result.ScanWarnings)
	}

	return nil
}

// printScanWarnings renders the limits on what this scan could observe.
func (r *TextReporter) printScanWarnings(w io.Writer, warnings []string) {
	fmt.Fprintf(w, "\n%s\n", r.color(colorBold, strings.Repeat("─", 63)))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold+colorYellow, "SCAN COVERAGE"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, strings.Repeat("─", 63)))

	for _, warning := range warnings {
		fmt.Fprintf(w, "    - %s\n", warning)
	}
	fmt.Fprintln(w)
}

// Format returns the format name.
func (r *TextReporter) Format() string {
	return string(FormatText)
}

func (r *TextReporter) color(c, text string) string {
	if r.NoColor {
		return text
	}
	return c + text + colorReset
}

func (r *TextReporter) printHeader(w io.Writer, result *types.ScanResult) {
	fmt.Fprintf(w, "\n%s\n", r.color(colorBold, "═══════════════════════════════════════════════════════════════"))
	fmt.Fprintf(w, "%s\n", r.color(colorBold+colorCyan, "  QRAMM TLS Analyzer - Quantum-Ready Security Assessment"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "═══════════════════════════════════════════════════════════════"))

	fmt.Fprintf(w, "  %s %s\n", r.color(colorDim, "Target:"), result.Target)
	if result.IP != "" {
		fmt.Fprintf(w, "  %s %s\n", r.color(colorDim, "IP:"), result.IP)
	}
	fmt.Fprintf(w, "  %s %s\n", r.color(colorDim, "Scanned:"), result.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "  %s %s\n\n", r.color(colorDim, "Duration:"), result.Duration.String())
}

func (r *TextReporter) printGrade(w io.Writer, grade types.Grade) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold, "OVERALL GRADE"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	// Main grades
	letterColor := r.gradeColor(grade.Letter)
	quantumColor := r.quantumGradeColor(grade.QuantumGrade)

	fmt.Fprintf(w, "  TLS Security:     %s  (%d/100)\n",
		r.color(letterColor+colorBold, fmt.Sprintf("%-3s", grade.Letter)),
		grade.Score)
	fmt.Fprintf(w, "  Quantum Ready:    %s\n\n",
		r.color(quantumColor+colorBold, grade.QuantumGrade))

	// Factors breakdown
	fmt.Fprintf(w, "  %s\n", r.color(colorDim, "Score Breakdown:"))
	for _, f := range grade.Factors {
		bar := r.progressBar(f.Score, f.MaxScore, 20)
		fmt.Fprintf(w, "    %-20s %s %d/%d\n", f.Category, bar, f.Score, f.MaxScore)
	}
	fmt.Fprintln(w)
}

func (r *TextReporter) gradeColor(letter string) string {
	switch {
	case strings.HasPrefix(letter, "A"):
		return colorGreen
	case letter == "B":
		return colorGreen
	case letter == "C":
		return colorYellow
	case letter == "D":
		return colorYellow
	default:
		return colorRed
	}
}

func (r *TextReporter) quantumGradeColor(grade string) string {
	switch grade {
	case "Q+":
		return colorGreen
	case "Q":
		return colorGreen
	case "Q-":
		return colorYellow
	default:
		return colorRed
	}
}

func (r *TextReporter) progressBar(value, max, width int) string {
	if max == 0 {
		return strings.Repeat("░", width)
	}
	filled := (value * width) / max
	if filled > width {
		filled = width
	}
	empty := width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	if r.NoColor {
		return "[" + bar + "]"
	}

	color := colorGreen
	pct := (value * 100) / max
	if pct < 50 {
		color = colorRed
	} else if pct < 75 {
		color = colorYellow
	}

	return "[" + r.color(color, bar) + "]"
}

func (r *TextReporter) printProtocols(w io.Writer, protocols []types.Protocol) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold, "PROTOCOL SUPPORT"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	for _, p := range protocols {
		status := r.color(colorRed, "✗ Not Supported")
		if p.Supported {
			if p.Version == "TLS 1.0" || p.Version == "TLS 1.1" {
				status = r.color(colorYellow, "⚠ Supported (Deprecated)")
			} else {
				status = r.color(colorGreen, "✓ Supported")
			}
		}

		preferred := ""
		if p.Preferred {
			preferred = r.color(colorCyan, " [preferred]")
		}

		fmt.Fprintf(w, "    %-12s %s%s\n", p.Version, status, preferred)
	}
	fmt.Fprintln(w)
}

func (r *TextReporter) printCipherSuites(w io.Writer, ciphers []types.CipherSuite) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold, "CIPHER SUITES"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	if len(ciphers) == 0 {
		fmt.Fprintf(w, "    %s\n\n", r.color(colorDim, "No cipher information available"))
		return
	}

	for _, cs := range ciphers {
		status := r.color(colorGreen, "✓")
		if cs.Deprecated {
			status = r.color(colorRed, "✗")
		}

		pfs := ""
		if cs.ForwardSecrecy {
			pfs = r.color(colorGreen, " [PFS]")
		}

		quantum := ""
		if cs.QuantumSafe {
			quantum = r.color(colorPurple, " [PQC]")
		}

		fmt.Fprintf(w, "    %s %-50s %d-bit%s%s\n",
			status, cs.Name, cs.Bits, pfs, quantum)

		if cs.Deprecated {
			fmt.Fprintf(w, "      %s\n", r.color(colorRed+colorDim, "└─ "+cs.DeprecatedReason))
		}
	}
	fmt.Fprintln(w)
}

func (r *TextReporter) printCertificate(w io.Writer, cert *types.Certificate) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold, "CERTIFICATE"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	// Status
	status := r.color(colorGreen, "✓ Valid")
	if cert.Expired {
		status = r.color(colorRed, "✗ EXPIRED")
	} else if cert.DaysUntilExpiry < 30 {
		status = r.color(colorYellow, fmt.Sprintf("⚠ Expiring in %d days", cert.DaysUntilExpiry))
	}

	fmt.Fprintf(w, "    Status:      %s\n", status)
	fmt.Fprintf(w, "    Subject:     %s\n", cert.Subject)
	fmt.Fprintf(w, "    Issuer:      %s\n", cert.Issuer)
	fmt.Fprintf(w, "    Valid:       %s to %s\n",
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(w, "    Key:         %s %d-bit\n", cert.PublicKeyAlgorithm, cert.PublicKeyBits)
	fmt.Fprintf(w, "    Signature:   %s\n", cert.SignatureAlgorithm)

	if len(cert.SANs) > 0 {
		fmt.Fprintf(w, "    SANs:        %s\n", strings.Join(cert.SANs, ", "))
	}

	if cert.IsSelfSigned {
		fmt.Fprintf(w, "    %s\n", r.color(colorYellow, "    ⚠ Self-signed certificate"))
	}

	// Quantum safety
	quantumStatus := r.color(colorRed, "✗ Quantum Vulnerable")
	if cert.QuantumSafe {
		quantumStatus = r.color(colorGreen, "✓ Quantum Safe")
	}
	fmt.Fprintf(w, "    Quantum:     %s\n\n", quantumStatus)
}

func (r *TextReporter) printQuantumRisk(w io.Writer, qr types.QuantumRiskAssessment) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold+colorPurple, "QUANTUM RISK ASSESSMENT"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	// Risk level with color
	levelColor := colorRed
	switch qr.Level {
	case types.RiskLow:
		levelColor = colorGreen
	case types.RiskMedium:
		levelColor = colorYellow
	}

	fmt.Fprintf(w, "    Risk Level:         %s\n", r.color(levelColor+colorBold, string(qr.Level)))
	fmt.Fprintf(w, "    Quantum Score:      %d/100\n\n", qr.Score)

	fmt.Fprintf(w, "    Key Exchange Risk:  %s\n", qr.KeyExchangeRisk)
	fmt.Fprintf(w, "    Certificate Risk:   %s\n", qr.CertificateRisk)
	fmt.Fprintf(w, "    HNDL Attack Risk:   %s\n\n", qr.HNDLRisk)

	// PQC readiness
	hybridStatus := r.color(colorRed, "✗")
	if qr.HybridPQCReady {
		hybridStatus = r.color(colorGreen, "✓")
	}
	fullStatus := r.color(colorRed, "✗")
	if qr.FullPQCReady {
		fullStatus = r.color(colorGreen, "✓")
	}

	fmt.Fprintf(w, "    %s Hybrid PQC Key Exchange (e.g., X25519MLKEM768)\n", hybridStatus)
	fmt.Fprintf(w, "    %s Full PQC (ML-KEM key exchange + ML-DSA certificates)\n\n", fullStatus)

	fmt.Fprintf(w, "    %s %s\n\n", r.color(colorCyan, "Recommended Action:"), qr.TimeToAction)

	// Details
	if len(qr.Details) > 0 {
		fmt.Fprintf(w, "    %s\n", r.color(colorDim, "Details:"))
		for _, detail := range qr.Details {
			fmt.Fprintf(w, "      • %s\n", detail)
		}
		fmt.Fprintln(w)
	}
}

func (r *TextReporter) printVulnerabilities(w io.Writer, vulns []types.Vulnerability) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold+colorRed, "VULNERABILITIES"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	for _, v := range vulns {
		sevColor := colorYellow
		switch v.Severity {
		case types.SeverityCritical:
			sevColor = colorRed + colorBold
		case types.SeverityHigh:
			sevColor = colorRed
		case types.SeverityMedium:
			sevColor = colorYellow
		case types.SeverityLow:
			sevColor = colorBlue
		}

		fmt.Fprintf(w, "    %s %s\n",
			r.color(sevColor, fmt.Sprintf("[%-8s]", v.Severity)),
			r.color(colorBold, v.Name))
		fmt.Fprintf(w, "              %s\n", v.Description)
		if v.CVE != "" {
			fmt.Fprintf(w, "              CVE: %s\n", v.CVE)
		}
		fmt.Fprintf(w, "              Fix: %s\n\n", v.Remediation)
	}
}

func (r *TextReporter) printRecommendations(w io.Writer, recs []types.Recommendation) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold+colorGreen, "RECOMMENDATIONS"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	for i, rec := range recs {
		priority := fmt.Sprintf("#%d", i+1)
		fmt.Fprintf(w, "    %s %s\n",
			r.color(colorCyan+colorBold, priority),
			r.color(colorBold, rec.Title))
		fmt.Fprintf(w, "       %s\n", rec.Description)
		fmt.Fprintf(w, "       %s %s | %s %s\n\n",
			r.color(colorDim, "Impact:"), rec.Impact,
			r.color(colorDim, "Effort:"), rec.Effort)
	}
}

func (r *TextReporter) printPolicyResult(w io.Writer, pr *types.PolicyResult) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold+colorCyan, "POLICY EVALUATION"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	// Policy name and compliance status
	complianceStatus := r.color(colorGreen+colorBold, "✓ COMPLIANT")
	if !pr.Compliant {
		complianceStatus = r.color(colorRed+colorBold, "✗ NON-COMPLIANT")
	}

	fmt.Fprintf(w, "    Policy:     %s\n", r.color(colorBold, pr.PolicyName))
	fmt.Fprintf(w, "    Status:     %s\n", complianceStatus)
	fmt.Fprintf(w, "    Score:      %d/100\n\n", pr.Score)

	// Violations
	if len(pr.Violations) > 0 {
		fmt.Fprintf(w, "    %s (%d)\n", r.color(colorRed+colorBold, "Violations"), len(pr.Violations))
		for _, v := range pr.Violations {
			fmt.Fprintf(w, "      • [%s] %s\n", v.Severity, v.Description)
			fmt.Fprintf(w, "        Expected: %s | Actual: %s\n", v.Expected, v.Actual)
		}
		fmt.Fprintln(w)
	}

	// Warnings
	if len(pr.Warnings) > 0 {
		fmt.Fprintf(w, "    %s (%d)\n", r.color(colorYellow+colorBold, "Warnings"), len(pr.Warnings))
		for _, v := range pr.Warnings {
			fmt.Fprintf(w, "      • [%s] %s\n", v.Severity, v.Description)
		}
		fmt.Fprintln(w)
	}
}

func (r *TextReporter) printCNSA2Timeline(w io.Writer, timeline *types.CNSA2Timeline) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold+colorPurple, "CNSA 2.0 COMPLIANCE TIMELINE"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	// Current phase and score
	fmt.Fprintf(w, "    Current Phase:      %s\n", r.color(colorCyan, timeline.CurrentPhase))
	fmt.Fprintf(w, "    Timeline Score:     %d/100\n", timeline.TimelineScore)
	fmt.Fprintf(w, "    Days to Deadline:   %d\n", timeline.DaysToNextDeadline)
	fmt.Fprintf(w, "    Next Action:        %s\n\n", timeline.NextAction)

	// Milestones
	fmt.Fprintf(w, "    %s\n", r.color(colorBold, "Milestones:"))
	for _, m := range timeline.Milestones {
		statusIcon := r.color(colorGreen, "✓")
		statusColor := colorGreen
		switch m.Status {
		case "compliant":
			statusIcon = r.color(colorGreen, "✓")
			statusColor = colorGreen
		case "partial":
			statusIcon = r.color(colorYellow, "◐")
			statusColor = colorYellow
		case "in-progress":
			statusIcon = r.color(colorBlue, "○")
			statusColor = colorBlue
		case "non-compliant":
			statusIcon = r.color(colorRed, "✗")
			statusColor = colorRed
		case "not-applicable":
			statusIcon = r.color(colorDim, "—")
			statusColor = colorDim
		}

		fmt.Fprintf(w, "      %s %s (%s)\n",
			statusIcon,
			r.color(statusColor, m.Name),
			m.Deadline.Format("2006-01-02"))

		if len(m.Gap) > 0 {
			for _, gap := range m.Gap {
				fmt.Fprintf(w, "         %s %s\n", r.color(colorRed, "└─"), gap)
			}
		}
	}
	fmt.Fprintln(w)

	// Key findings
	if len(timeline.Findings) > 0 {
		fmt.Fprintf(w, "    %s\n", r.color(colorBold, "Algorithm Status:"))
		for _, f := range timeline.Findings {
			statusColor := colorDim
			switch f.Status {
			case "approved":
				statusColor = colorGreen
			case "transitional":
				statusColor = colorYellow
			case "deprecated":
				statusColor = colorRed
			case "prohibited":
				statusColor = colorRed + colorBold
			}

			fmt.Fprintf(w, "      [%s] %s: %s\n",
				r.color(statusColor, fmt.Sprintf("%-12s", f.Status)),
				f.Category,
				f.Algorithm)

			if f.Replacement != "" && (f.Status == "deprecated" || f.Status == "prohibited") {
				fmt.Fprintf(w, "               Replace with: %s\n", f.Replacement)
			}
		}
		fmt.Fprintln(w)
	}
}
