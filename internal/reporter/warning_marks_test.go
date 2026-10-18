package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The reports drew three warnings with U+26A0 WARNING SIGN, which has the
// Unicode Emoji property, and keyed the CNSA 2.0 "not yet required" milestone
// with U+2014 EM DASH. Scanned on 2026-10-18, example.com printed U+26A0 before
// "Supported (Deprecated)" beside TLS 1.1 and TLS 1.0, and U+2014 in the
// milestone legend and before its two milestones not yet due. Those warnings
// are now drawn with "!" and that milestone with "-".

// bannedMarks are the two glyphs no report may draw.
var bannedMarks = []struct {
	glyph string
	name  string
}{
	{"\u26a0", "U+26A0 WARNING SIGN"},
	{"\u2014", "U+2014 EM DASH"},
}

// warningMarksResult carries the four verdicts the reports drew with one of the
// two glyphs: a supported deprecated protocol, a certificate with fewer than 30
// days left, a self-signed certificate, and a milestone not yet required.
func warningMarksResult() *types.ScanResult {
	result := fullResult()
	result.Protocols = []types.Protocol{
		{Version: "TLS 1.3", Supported: true, Preferred: true},
		{Version: "TLS 1.0", Supported: true},
	}
	result.Certificate.NotAfter = time.Now().Add(12 * 24 * time.Hour)
	result.Certificate.DaysUntilExpiry = 12
	result.Certificate.IsSelfSigned = true
	return result
}

func TestTextReportDrawsWarningsWithBangAndNotYetRequiredWithHyphen(t *testing.T) {
	text := render(t, &TextReporter{NoColor: true}, warningMarksResult())

	lines := []struct {
		needle string // finds the line whatever its mark
		want   string // the whole line, trimmed
	}{
		{"Supported (Deprecated)", "TLS 1.0      ! Supported (Deprecated)"},
		{"Expiring in 12 days", "Status:      ! Expiring in 12 days"},
		{"Self-signed certificate", "! Self-signed certificate"},
		{"legend:", "legend: ✓ met, ◐ partial, ○ in progress, ✗ not met, - not yet required"},
		{"Exclusive use of CNSA 2.0 for web",
			"- not yet required: Exclusive use of CNSA 2.0 for web (2033-01-01)"},
	}
	for _, l := range lines {
		if got := strings.TrimSpace(lineContaining(t, text, l.needle)); got != l.want {
			t.Errorf("text line = %q, want %q", got, l.want)
		}
	}

	for _, b := range bannedMarks {
		if strings.Contains(text, b.glyph) {
			t.Errorf("the text report draws %s:\n%s", b.name, text)
		}
	}
}

func TestHTMLPageDrawsWarningsWithBangAndNotYetRequiredWithHyphen(t *testing.T) {
	page := render(t, &HTMLReporter{IncludeCSS: true}, warningMarksResult())

	row, ok := protocolRows(page)["TLS 1.0"]
	if !ok {
		t.Fatal("no HTML row for TLS 1.0")
	}
	if want := `<span class="status-icon status-warn">!</span>`; !strings.Contains(row, want) {
		t.Errorf("HTML row for supported TLS 1.0 does not carry %q: %s", want, row)
	}

	sections := []struct {
		id   string
		want []string
	}{
		{"certificate", []string{
			`<span aria-hidden="true">!</span> Expiring in 12 days`,
			`<span aria-hidden="true">!</span> Self-signed certificate`,
		}},
		{"cnsa2-timeline", []string{
			`<span aria-hidden="true">-</span> not yet required</span></p>`,
			`<span aria-hidden="true">-</span> not yet required</span>: Exclusive use of CNSA 2.0 for web`,
		}},
	}
	for _, s := range sections {
		section := htmlSection(t, page, s.id)
		for _, want := range s.want {
			if !strings.Contains(section, want) {
				t.Errorf("section %q does not carry %q:\n%s", s.id, want, section)
			}
		}
	}

	for _, b := range bannedMarks {
		if strings.Contains(page, b.glyph) {
			t.Errorf("the HTML page draws %s", b.name)
		}
	}
}
