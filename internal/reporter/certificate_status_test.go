package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

func certResult(cert *types.Certificate) *types.ScanResult {
	return &types.ScanResult{
		Target:      "example.com",
		Host:        "example.com",
		Port:        443,
		Timestamp:   time.Now(),
		Certificate: cert,
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true, Preferred: true},
			{Version: "TLS 1.2", Supported: true},
			{Version: "TLS 1.1", Supported: true},
			{Version: "TLS 1.0", Supported: false},
		},
		Grade: types.Grade{
			Letter:                  "F",
			Score:                   0,
			QuantumGrade:            types.QuantumGradeNotAssessed,
			VulnerabilitiesAssessed: true,
			Factors: []types.GradeFactor{
				{Category: "Certificate", Score: 0, MaxScore: 25, Details: "Critical: Certificate is not valid for example.com"},
			},
		},
	}
}

func healthyCert() *types.Certificate {
	return &types.Certificate{
		Subject:            "CN=example.com",
		Issuer:             "CN=Example CA",
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(90 * 24 * time.Hour),
		SignatureAlgorithm: "ECDSA-SHA256",
		PublicKeyAlgorithm: "ECDSA",
		PublicKeyBits:      256,
		SANs:               []string{"example.com"},
		DaysUntilExpiry:    90,
		RequestedName:      "example.com",
		NameMatch:          types.CheckPassed,
		ChainTrust:         types.CheckPassed,
	}
}

// TestTextReporterDoesNotHeadAFailedCertificateAsValid pins the headline word,
// not just the detail lines. A report that prints "Status: Valid" above a name
// or chain failure has told the reader the opposite of its own finding, and the
// status line is the part a reader takes away.
func TestTextReporterDoesNotHeadAFailedCertificateAsValid(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*types.Certificate)
		wantSub string
	}{
		{
			name: "name mismatch",
			mutate: func(c *types.Certificate) {
				c.NameMatch = types.CheckFailed
				c.NameMismatchReason = "x509: certificate is valid for other.example, not example.com"
			},
			wantSub: "NOT VALID FOR THIS NAME",
		},
		{
			name: "untrusted chain",
			mutate: func(c *types.Certificate) {
				c.ChainTrust = types.CheckFailed
				c.ChainTrustReason = "x509: certificate signed by unknown authority"
			},
			wantSub: "NOT TRUSTED",
		},
		{
			name: "expired",
			mutate: func(c *types.Certificate) {
				c.Expired = true
				c.DaysUntilExpiry = -3
			},
			wantSub: "EXPIRED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := healthyCert()
			tc.mutate(cert)

			var buf bytes.Buffer
			r := &TextReporter{NoColor: true}
			if err := r.Report(&buf, certResult(cert)); err != nil {
				t.Fatalf("report: %v", err)
			}
			out := buf.String()

			status := statusLine(t, out)
			if !strings.Contains(status, tc.wantSub) {
				t.Fatalf("status line = %q, want it to contain %q", status, tc.wantSub)
			}
			if strings.Contains(status, "✓ Valid") {
				t.Fatalf("status line = %q still heads the certificate as valid", status)
			}
		})
	}
}

// TestTextReporterHeadsAPassingCertificateAsValid is the acceptance control for
// the case above. A status line that never says valid would satisfy it alone.
func TestTextReporterHeadsAPassingCertificateAsValid(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{NoColor: true}
	if err := r.Report(&buf, certResult(healthyCert())); err != nil {
		t.Fatalf("report: %v", err)
	}

	status := statusLine(t, buf.String())
	if !strings.Contains(status, "Valid") {
		t.Fatalf("status line = %q, want a certificate that passed every check to read as valid", status)
	}
}

// TestTextReporterPrintsBothCertificateChecks requires each check to appear
// whatever its outcome. A check whose result is absent from the report is a
// check the reader assumes passed.
func TestTextReporterPrintsBothCertificateChecks(t *testing.T) {
	cert := healthyCert()
	cert.NameMatch = types.CheckNotPerformed
	cert.ChainTrust = types.CheckNotPerformed

	var buf bytes.Buffer
	r := &TextReporter{NoColor: true}
	if err := r.Report(&buf, certResult(cert)); err != nil {
		t.Fatalf("report: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"Name check:", "Chain trust:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report omits %q for a certificate whose checks did not run", want)
		}
	}
}

func statusLine(t *testing.T, report string) string {
	t.Helper()
	for _, line := range strings.Split(report, "\n") {
		if strings.Contains(line, "Status:") && !strings.Contains(line, "COMPLIANT") {
			return line
		}
	}
	t.Fatalf("no certificate status line in the report:\n%s", report)
	return ""
}

// TestDeprecatedProtocolsAreMarkedInEveryReport is the cross-consumer check for
// the shared predicate. The text report, the HTML icon and the HTML badge all
// answer "is this version deprecated", and before they shared a predicate the
// HTML report painted TLS 1.0 and TLS 1.1 with the same green check as TLS 1.3
// while the text report called them deprecated.
//
// The expectation is stated here rather than read from the predicate, so this
// test can disagree with it: RFC 8996 deprecates TLS 1.0 and TLS 1.1, and
// SSL 3.0 was deprecated by RFC 7568.
func TestDeprecatedProtocolsAreMarkedInEveryReport(t *testing.T) {
	deprecated := []string{"SSL 3.0", "TLS 1.0", "TLS 1.1"}
	current := []string{"TLS 1.2", "TLS 1.3"}

	for _, v := range deprecated {
		if !types.IsDeprecatedProtocol(v) {
			t.Fatalf("%s is not reported as deprecated, but RFC 8996 and RFC 7568 deprecate it", v)
		}
	}
	for _, v := range current {
		if types.IsDeprecatedProtocol(v) {
			t.Fatalf("%s is reported as deprecated, which would mark a current protocol as a defect", v)
		}
	}

	// Every deprecated version, rendered as supported, must be visibly distinct
	// from a current one in both reports.
	for _, v := range deprecated {
		result := certResult(healthyCert())
		result.Protocols = []types.Protocol{
			{Version: v, Supported: true},
			{Version: "TLS 1.3", Supported: true},
		}

		var text bytes.Buffer
		if err := (&TextReporter{NoColor: true}).Report(&text, result); err != nil {
			t.Fatalf("text report: %v", err)
		}
		if !strings.Contains(text.String(), v+"      ⚠ Supported (Deprecated)") &&
			!strings.Contains(text.String(), "⚠ Supported (Deprecated)") {
			t.Fatalf("text report does not mark supported %s as deprecated:\n%s", v, text.String())
		}

		var html bytes.Buffer
		if err := (&HTMLReporter{}).Report(&html, result); err != nil {
			t.Fatalf("html report: %v", err)
		}
		rows := protocolRows(html.String())
		row, ok := rows[v]
		if !ok {
			t.Fatalf("no HTML row for %s", v)
		}
		if !strings.Contains(row, "status-warn") {
			t.Fatalf("HTML row for supported %s carries no warning icon, so it reads as good "+
				"while the text report calls it deprecated. Row: %s", v, row)
		}
		if strings.Contains(row, "status-good") {
			t.Fatalf("HTML row for supported %s still carries the good icon: %s", v, row)
		}
		if !strings.Contains(row, "Deprecated") {
			t.Fatalf("HTML row for supported %s carries no Deprecated badge: %s", v, row)
		}

		currentRow, ok := rows["TLS 1.3"]
		if !ok {
			t.Fatal("no HTML row for TLS 1.3")
		}
		if !strings.Contains(currentRow, "status-good") {
			t.Fatalf("HTML row for supported TLS 1.3 is not marked good: %s", currentRow)
		}
	}
}

// protocolRows splits the rendered protocol table into one string per version,
// so an assertion is made against the row for a version rather than against the
// whole document, where a match could come from anywhere.
func protocolRows(doc string) map[string]string {
	rows := map[string]string{}
	for _, chunk := range strings.Split(doc, "<tr>") {
		for _, v := range []string{"SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"} {
			if strings.Contains(chunk, "<td>"+v+"</td>") {
				rows[v] = chunk
			}
		}
	}
	return rows
}

// TestTextReporterMarksTheNegotiatedSuite pins the label in the rendered cipher
// list, where the misreading happens. For TLS 1.3 the suite reported is chosen
// by this scanner's client preference, not the server's, so an unlabelled row
// reads as the server's choice.
func TestTextReporterMarksTheNegotiatedSuite(t *testing.T) {
	result := certResult(healthyCert())
	result.CipherSuites = []types.CipherSuite{
		{Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true},
		{Name: "TLS_AES_128_GCM_SHA256", Bits: 128, ForwardSecrecy: true, Negotiated: true},
	}

	var buf bytes.Buffer
	if err := (&TextReporter{NoColor: true}).Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}

	for _, line := range strings.Split(buf.String(), "\n") {
		switch {
		case strings.Contains(line, "TLS_AES_128_GCM_SHA256"):
			if !strings.Contains(line, "negotiated by this scan") {
				t.Errorf("the negotiated suite is not marked as such: %q", line)
			}
		case strings.Contains(line, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"):
			if strings.Contains(line, "negotiated by this scan") {
				t.Errorf("an enumerated suite is marked as negotiated: %q", line)
			}
		}
	}
}
