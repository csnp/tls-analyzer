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
	// Whether the scan failed is decided on the RAW result and the report is
	// rendered from the scrubbed copy. Those must not be the same value: scrubbing
	// collapses control characters and trims, so an Error consisting only of them
	// scrubs to empty, and deciding on the copy would send a target that was never
	// reached down the fully-graded path. That is the inverse of the defect the
	// branch below exists to prevent, introduced by the scrubbing that fixed a
	// different one. No real value reaches it today because the error is built
	// from err.Error() and always carries prose, but a decision taken on a
	// transformed value is a decision about a different value.
	scanFailed := result.Error != ""

	// Scrub once, at the door. Every print site below renders text that cannot
	// move a terminal cursor, whether or not whoever wrote it thought about
	// forgery. See sanitizedForText for why this is not done per print site.
	result = sanitizedForText(result)

	// A target that could not be scanned has no measurements, so it gets no
	// report. Batch mode records the failure on the result and carried on to the
	// grade block, which rendered a zero-valued assessment as a finished
	// assessment: "TLS Security: (0/100)" with a blank letter, "Quantum Score:
	// 0/100" and an unticked "Hybrid PQC Key Exchange", for a host that was never
	// reached. In a --targets sweep every typo or DNS blip became a confident
	// failing row, which is the same defect 0.3.0 fixed for the single-target
	// path and which survived in batch because the error travels on the result
	// rather than as a returned error. JSON carried the reason all along; text,
	// the default format, discarded it.
	if scanFailed {
		r.printHeader(w, result)
		r.printScanError(w, result.Error)
		return nil
	}

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
	if result.Grade.QuantumGrade != types.QuantumGradeNotAssessed {
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

// printScanError renders the reason a target produced no measurements.
func (r *TextReporter) printScanError(w io.Writer, message string) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, strings.Repeat("─", 63)))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold+colorRed, "NOT SCANNED"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, strings.Repeat("─", 63)))

	// The message quotes the target back, so it carries whatever a --targets file
	// put there, and in a batch sweep this block is printed between two scanned
	// targets, which puts a full report above it to overprint. It is safe here
	// because Report scrubbed the whole result on the way in, not because of
	// anything this function does.
	for _, line := range wrapText(message, 59) {
		fmt.Fprintf(w, "    %s\n", line)
	}
	fmt.Fprintf(w, "\n    %s\n\n", r.color(colorDim,
		"No grade is reported for this target, because nothing was measured."))
}

// printScope renders a wrapped scope note under a section heading.
//
// Scope text is prose rather than a field value, so it is wrapped with a hanging
// indent instead of printed as one long line. The indent is per-caller so the
// note lines up with the value column of the section it belongs to.
func (r *TextReporter) printScope(w io.Writer, label, text string, indent int) {
	const width = 60

	for i, line := range wrapText(text, width) {
		if i == 0 {
			fmt.Fprintf(w, "    %-*s%s\n", indent-4, label, r.color(colorDim, line))
			continue
		}
		fmt.Fprintf(w, "%*s%s\n", indent, "", r.color(colorDim, line))
	}
}

// wrapText breaks text into lines of at most width characters on word
// boundaries. A word longer than width is left whole on its own line rather than
// split, so an algorithm name or URL is never broken.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	lines := make([]string, 0, len(words)/8+1)
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = word
			continue
		}
		line += " " + word
	}

	return append(lines, line)
}

// milestoneLegend keys the milestone status glyphs, which appeared with no
// explanation anywhere in the output or in --help.
func (r *TextReporter) milestoneLegend() string {
	return fmt.Sprintf("%s met, %s partial, %s in progress, %s not met, %s not yet required",
		r.color(colorGreen, "✓"),
		r.color(colorYellow, "◐"),
		r.color(colorBlue, "○"),
		r.color(colorRed, "✗"),
		r.color(colorDim, "—"),
	)
}

// printScanWarnings renders the limits on what this scan could observe.
func (r *TextReporter) printScanWarnings(w io.Writer, warnings []string) {
	fmt.Fprintf(w, "\n%s\n", r.color(colorBold, strings.Repeat("─", 63)))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold+colorYellow, "SCAN COVERAGE"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, strings.Repeat("─", 63)))

	// Warnings are tool prose with untrusted values interpolated into them: the
	// --sni warning carries the SNI value and the target. This is the LAST block
	// of the report, so a cursor-up sequence here would rewrite any line above it,
	// including the grade. Report scrubs the whole result before any of this
	// runs, so a warning added later is covered without anyone remembering to
	// wrap it.
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

	// The target is untrusted text. It is usually typed by the person reading the
	// report, but --targets reads it from a file that may have been written by
	// someone else, and this line is the FIRST in the report, so an escape
	// sequence here rewrites nothing above it but sets up the terminal for
	// everything below.
	fmt.Fprintf(w, "  %s %s\n", r.color(colorDim, "Target:"),
		result.Target)
	if result.IP != "" {
		// Production fills this from net.IP.String(), so it cannot be hostile
		// there. It is scrubbed at the door regardless, because deciding per field
		// which values are "already safe by provenance" is the judgement that let
		// three of the four earlier sanitiser fixes ship incomplete, and it was
		// wrong twice in the review that produced this design.
		fmt.Fprintf(w, "  %s %s\n", r.color(colorDim, "IP:"),
			result.IP)
	}
	fmt.Fprintf(w, "  %s %s\n", r.color(colorDim, "Scanned:"), result.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "  %s %s\n\n", r.color(colorDim, "Duration:"), result.Duration.String())
}

// quantumGradeLegend explains the quantum readiness letters, which appeared in
// the report and in --help with no key anywhere, so a reader could not tell
// whether Q was a good result.
const quantumGradeLegend = "Q+ ready, Q partial, Q- limited, QV vulnerable"

func (r *TextReporter) printGrade(w io.Writer, grade types.Grade) {
	fmt.Fprintf(w, "%s\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s\n", r.color(colorBold, "OVERALL GRADE"))
	fmt.Fprintf(w, "%s\n\n", r.color(colorBold, "───────────────────────────────────────────────────────────────"))

	// Main grades
	letterColor := r.gradeColor(grade.Letter)
	quantumColor := r.quantumGradeColor(grade.QuantumGrade)

	// Say beside the number what it does not account for. A score computed
	// without the vulnerability checks is an upper bound rather than a better
	// result, and a score normalized over fewer dimensions is not comparable in
	// either direction: dropping quantum readiness, the dimension most servers
	// score worst on, RAISED the reported grade as far as A+ (100/100).
	basis := ""
	switch {
	case len(grade.SkippedDimensions) > 0 && !grade.VulnerabilitiesAssessed:
		basis = r.color(colorYellow, fmt.Sprintf("  not comparable: %s and the vulnerability checks were skipped",
			strings.Join(grade.SkippedDimensions, " and ")))
	case len(grade.SkippedDimensions) > 0:
		basis = r.color(colorYellow, fmt.Sprintf("  not comparable: %s was not assessed",
			strings.Join(grade.SkippedDimensions, " and ")))
	case !grade.VulnerabilitiesAssessed:
		basis = r.color(colorYellow, "  upper bound, vulnerability checks skipped")
	}

	fmt.Fprintf(w, "  TLS Security:     %s  (%d/100)%s\n",
		r.color(letterColor+colorBold, fmt.Sprintf("%-3s", grade.Letter)),
		grade.Score, basis)
	fmt.Fprintf(w, "  Quantum Ready:    %s\n",
		r.color(quantumColor+colorBold, grade.QuantumGrade))
	if grade.QuantumGrade != types.QuantumGradeNotAssessed {
		fmt.Fprintf(w, "                    %s\n", r.color(colorDim, quantumGradeLegend))
	}
	fmt.Fprintln(w)

	// Factors breakdown
	fmt.Fprintf(w, "  %s\n", r.color(colorDim, "Score Breakdown:"))
	for _, f := range grade.Factors {
		bar := r.progressBar(f.Score, f.MaxScore, 20)
		fmt.Fprintf(w, "    %-20s %s %d/%d\n", f.Category, bar, f.Score, f.MaxScore)
	}
	r.printScoreReconciliation(w, grade)
	fmt.Fprintln(w)
}

// printScoreReconciliation closes the arithmetic between the dimension
// breakdown and the headline score.
//
// The dimensions above summed to 66 while the headline read 21/100, because a
// real and consistently applied vulnerability penalty sat between them and was
// never printed. The normalization is shown too, since a skipped dimension
// changes the denominator and four dimensions worth 25 each then do not total 100.
func (r *TextReporter) printScoreReconciliation(w io.Writer, grade types.Grade) {
	const labelWidth = 44

	subtotal := fmt.Sprintf("%d/100", grade.DimensionScore)
	if len(grade.SkippedDimensions) > 0 && grade.DimensionMaxPoints > 0 {
		subtotal += fmt.Sprintf("  (%d of %d points; %s not assessed)",
			grade.DimensionPoints, grade.DimensionMaxPoints,
			strings.Join(grade.SkippedDimensions, " and "))
	}
	fmt.Fprintf(w, "    %-*s%s\n", labelWidth, "Dimension subtotal", subtotal)

	penalty := "none"
	switch {
	case !grade.VulnerabilitiesAssessed:
		penalty = r.color(colorYellow, "not measured (vulnerability checks skipped)")
	case grade.VulnerabilityPenalty > 0:
		penalty = fmt.Sprintf("-%d  (%s)",
			grade.VulnerabilityPenalty, describePenalties(grade.Penalties))
	}
	fmt.Fprintf(w, "    %-*s%s\n", labelWidth, "Vulnerability penalty", penalty)

	final := fmt.Sprintf("%d/100", grade.Score)
	if grade.PenaltyFloored {
		final += "  (the penalty exceeded the subtotal, so the score is held at 0)"
	}
	fmt.Fprintf(w, "    %-*s%s\n", labelWidth, "TLS Security score", final)
}

// describePenalties renders the per-severity deduction, for example
// "1 HIGH x 15, 6 MEDIUM x 5".
func describePenalties(penalties []types.GradePenalty) string {
	parts := make([]string, 0, len(penalties))
	for _, p := range penalties {
		parts = append(parts, fmt.Sprintf("%d %s x %d", p.Count, p.Severity, p.PointsEach))
	}
	return strings.Join(parts, ", ")
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
			if types.IsDeprecatedProtocol(p.Version) {
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

		// Marked as this scan's own negotiation rather than as the server's
		// preference. For TLS 1.3 the suite here is chosen by this scanner's
		// client preference, not the server's, and an unlabelled row reads as
		// the server having picked it.
		negotiated := ""
		if cs.Negotiated {
			negotiated = r.color(colorCyan, " [negotiated by this scan]")
		}

		fmt.Fprintf(w, "    %s %-50s %d-bit%s%s%s\n",
			status, cs.Name, cs.Bits, pfs, quantum, negotiated)

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

	// Status. A certificate a client would refuse must not be headed "Valid":
	// the name and chain checks are part of that verdict, not a footnote to it.
	status := r.color(colorGreen, "✓ Valid")
	switch {
	case cert.Expired:
		status = r.color(colorRed, "✗ EXPIRED")
	case cert.NotYetValid:
		status = r.color(colorRed, "✗ NOT YET VALID")
	case cert.NameMatch == types.CheckFailed:
		status = r.color(colorRed, "✗ NOT VALID FOR THIS NAME")
	case cert.ChainTrust == types.CheckFailed:
		status = r.color(colorRed, "✗ NOT TRUSTED")
	case cert.DaysUntilExpiry < 30:
		status = r.color(colorYellow, fmt.Sprintf("⚠ Expiring in %d days", cert.DaysUntilExpiry))
	}

	// Almost every string below is chosen by the scanned server: the subject and
	// issuer directly, and the check reasons by way of the verifier's error text.
	// RequestedName is the exception, coming from --sni or the target argument, so
	// it is the user's own text; it is sanitised too because a name reaching the
	// report should not depend on who typed it. macOS formats its verifier errors as
	// `x509: "<subject>" certificate is not trusted`, so the subject reaches the
	// reason too. An ANSI sequence in a common name could clear and rewrite the
	// line above it, printing a green "Chain trust: OK" over the real verdict,
	// and it survived --no-color. That is the same forgery the policy-name fix in
	// this release closed; the certificate path had not been closed with it,
	// because the sanitiser lived in the analyzer package and nothing here
	// reached it.
	fmt.Fprintf(w, "    Status:      %s\n", status)
	fmt.Fprintf(w, "    Subject:     %s\n", cert.Subject)
	fmt.Fprintf(w, "    Issuer:      %s\n", cert.Issuer)
	fmt.Fprintf(w, "    Valid:       %s to %s\n",
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(w, "    Key:         %s %d-bit\n", cert.PublicKeyAlgorithm, cert.PublicKeyBits)
	fmt.Fprintf(w, "    Signature:   %s\n", cert.SignatureAlgorithm)

	if len(cert.SANs) > 0 {
		// Quoted per item: sanitising collapses control characters to spaces, so an
		// unquoted join let one name read as two, and a name that was entirely
		// control characters became an empty entry.
		sans := make([]string, 0, len(cert.SANs))
		for _, s := range cert.SANs {
			sans = append(sans, fmt.Sprintf("%q", s))
		}
		fmt.Fprintf(w, "    SANs:        %s\n", strings.Join(sans, ", "))
	}

	// Both checks are printed whatever their outcome, including when they did
	// not run. A check whose result is absent from the report is a check the
	// reader assumes passed.
	fmt.Fprintf(w, "    Name check:  %s\n", r.certCheckLine(
		cert.NameMatch,
		"valid for "+cert.RequestedName,
		cert.NameMismatchReason,
		"not checked against any name"))
	fmt.Fprintf(w, "    Chain trust: %s\n", r.certCheckLine(
		cert.ChainTrust,
		"chains to a root this host trusts",
		cert.ChainTrustReason,
		"not verified"))

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

// certCheckLine renders one certificate check in its own right, so that
// "passed", "failed" and "did not run" are three visibly different answers.
func (r *TextReporter) certCheckLine(result types.CheckResult, passed, failReason, notRun string) string {
	switch result {
	case types.CheckPassed:
		return r.color(colorGreen, "✓ "+passed)
	case types.CheckFailed:
		if failReason == "" {
			failReason = "failed"
		}
		return r.color(colorRed, "✗ "+failReason)
	default:
		return r.color(colorYellow, "? "+notRun)
	}
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

		// The findings block carries the same server-chosen text the certificate
		// block does: CERT_CHAIN_UNTRUSTED interpolates ChainTrustReason into its
		// description and CERT_NAME_MISMATCH interpolates NameMismatchReason, and
		// x509 builds the latter by joining the certificate's DNS names raw. So an
		// ANSI sequence in a SAN reached this line unescaped and could overprint it
		// with a passing verdict, surviving --no-color, while the certificate block
		// three sections above was already defended. Sanitising one block and not
		// its sibling is not a smaller version of the fix, it is the same hole.
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

	// A verdict that skipped rules is about a smaller set than the policy
	// defines, and the score is computed by deducting from 100, so a skipped
	// rule can only raise it. Say so beside both numbers rather than only in the
	// list further down.
	incomplete := ""
	if !pr.Complete {
		incomplete = r.color(colorYellow, fmt.Sprintf(
			"  not comparable: %d rule(s) were not evaluated", len(pr.SkippedRules)))
	}

	fmt.Fprintf(w, "    Policy:     %s\n", r.color(colorBold, pr.PolicyName))
	fmt.Fprintf(w, "    Status:     %s%s\n", complianceStatus, incomplete)
	fmt.Fprintf(w, "    Score:      %d/100%s\n", pr.Score, incomplete)
	if pr.Scope != "" {
		r.printScope(w, "Scope:", pr.Scope, 16)
	}
	fmt.Fprintln(w)

	// Violations. The remediation is carried in JSON and was dropped here, so
	// the default output named every problem and no fix.
	if len(pr.Violations) > 0 {
		fmt.Fprintf(w, "    %s (%d)\n", r.color(colorRed+colorBold, "Violations"), len(pr.Violations))
		for _, v := range pr.Violations {
			fmt.Fprintf(w, "      • [%s] %s\n", v.Severity, v.Description)
			fmt.Fprintf(w, "        Expected: %s | Actual: %s\n", v.Expected, v.Actual)
			if v.Remediation != "" {
				fmt.Fprintf(w, "        %s %s\n", r.color(colorDim, "Fix:"), v.Remediation)
			}
		}
		fmt.Fprintln(w)
	}

	// Warnings
	if len(pr.Warnings) > 0 {
		fmt.Fprintf(w, "    %s (%d)\n", r.color(colorYellow+colorBold, "Warnings"), len(pr.Warnings))
		for _, v := range pr.Warnings {
			fmt.Fprintf(w, "      • [%s] %s\n", v.Severity, v.Description)
			if v.Remediation != "" {
				fmt.Fprintf(w, "        %s %s\n", r.color(colorDim, "Fix:"), v.Remediation)
			}
		}
		fmt.Fprintln(w)
	}

	// Rules that were not evaluated at all. Neither passed nor failed, and the
	// reason has to be visible or the verdict reads as covering the whole policy.
	if len(pr.SkippedRules) > 0 {
		fmt.Fprintf(w, "    %s (%d)\n",
			r.color(colorYellow+colorBold, "Not evaluated"), len(pr.SkippedRules))
		for _, s := range pr.SkippedRules {
			fmt.Fprintf(w, "      • %s\n", s.Rule)
			r.printScope(w, "", s.Reason, 8)
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
	fmt.Fprintf(w, "    Next Action:        %s\n", timeline.NextAction)
	if timeline.Scope != "" {
		r.printScope(w, "Scope:", timeline.Scope, 24)
	}
	fmt.Fprintln(w)

	// Milestones. The status glyphs had no key anywhere in the output or in
	// --help, so a reader could not tell what they meant.
	fmt.Fprintf(w, "    %s\n", r.color(colorBold, "Milestones:"))
	fmt.Fprintf(w, "      %s\n", r.color(colorDim, "legend: "+r.milestoneLegend()))
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
