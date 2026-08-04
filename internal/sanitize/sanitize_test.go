package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// This package is the single defence for two independent untrusted inputs: the
// policy file and the certificate a scanned server presents. It had no tests of
// its own when it was extracted, which is how it came to be applied on one path
// and not the other for a whole release.

func TestEveryControlCharacterIsCollapsed(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"ESC", "a\x1bb"},
		{"carriage return", "a\rb"},
		{"newline", "a\nb"},
		{"tab", "a\tb"},
		{"NUL", "a\x00b"},
		{"DEL", "a\x7fb"},
		{"vertical tab", "a\vb"},
		{"form feed", "a\fb"},
		{"C1 CSI", "ab"},
		{"C1 NEL", "ab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := ForReport(tc.in, 100)
			for _, r := range out {
				if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
					t.Errorf("a control character U+%04X survived: %q -> %q", r, tc.in, out)
				}
			}
			// The surrounding text must survive, or the field becomes useless.
			if !strings.Contains(out, "a") || !strings.Contains(out, "b") {
				t.Errorf("the ordinary text either side was lost: %q -> %q", tc.in, out)
			}
		})
	}
}

// TestAnAnsiVerdictCannotSurviveAsItsOwnLine is the shape that matters: the
// escape sequence an attacker uses to clear a line and rewrite it.
func TestAnAnsiVerdictCannotSurviveAsItsOwnLine(t *testing.T) {
	forged := "Innocent CA\x1b[2K\r\x1b[32m  Chain trust: OK\x1b[0m\nStatus: VALID"

	out := ForReport(forged, 500)

	if strings.ContainsAny(out, "\x1b\r\n") {
		t.Fatalf("the sequence survived: %q", out)
	}
	if strings.Contains(out, "\n") {
		t.Errorf("the text can still occupy more than one line: %q", out)
	}
}

// TestOrdinaryTextIsUntouched is the control. A sanitiser that mangled normal
// input would satisfy every test above and make the report unreadable.
func TestOrdinaryTextIsUntouched(t *testing.T) {
	for _, in := range []string{
		"CN=example.com,O=Example Ltd,C=GB",
		"x509: certificate signed by unknown authority",
		`the chain certificate "Example Intermediate CA" expired on 2026-07-04`,
		"TLS_AES_256_GCM_SHA384",
		"café-ünïcode.example",
	} {
		if out := ForReport(in, 500); out != in {
			t.Errorf("ordinary text was altered:\n  in:  %q\n  out: %q", in, out)
		}
	}
}

// TestTruncationStaysOnARuneBoundary pins that a cut cannot produce invalid
// UTF-8, which would corrupt the report rather than shorten it.
func TestTruncationStaysOnARuneBoundary(t *testing.T) {
	// Every rune here is multi-byte, so a naive byte cut would split one.
	long := strings.Repeat("é", 400)

	out := ForReport(long, 50)

	if !utf8.ValidString(out) {
		t.Errorf("truncation produced invalid UTF-8: %q", out)
	}
	if len(out) > 50 {
		t.Errorf("output is %d bytes, over the %d cap", len(out), 50)
	}
	if !strings.HasSuffix(out, "...") {
		t.Errorf("truncated output does not say it was truncated: %q", out)
	}
}

// TestALongHostileStringIsBothScrubbedAndCapped covers the two defences
// together, since a caller gets only one call.
func TestALongHostileStringIsBothScrubbedAndCapped(t *testing.T) {
	hostile := strings.Repeat("\x1b[2K\rEVERYTHING IS FINE ", 5000)

	out := ForReport(hostile, 200)

	if strings.ContainsAny(out, "\x1b\r") {
		t.Error("control characters survived in a long input")
	}
	if len(out) > 200 {
		t.Errorf("output is %d bytes, over the 200 cap", len(out))
	}
}

// TestTheCapIsNotDefeatedByATinyBudget guards the arithmetic. maxLen below the
// length of the ellipsis must not produce a negative budget or a panic.
func TestTheCapIsNotDefeatedByATinyBudget(t *testing.T) {
	for _, maxLen := range []int{0, 1, 2, 3, 4} {
		out := ForReport("abcdefghij", maxLen)
		if !utf8.ValidString(out) {
			t.Errorf("maxLen=%d produced invalid UTF-8: %q", maxLen, out)
		}
	}
}
