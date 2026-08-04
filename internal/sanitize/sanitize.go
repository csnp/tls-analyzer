// Package sanitize strips the control characters that let untrusted text forge
// the report it appears in.
//
// Two independent sources of untrusted text reach the human-readable report: a
// policy file, which arrives from a vendor, a repository or a colleague; and the
// certificate a scanned server chooses to present, whose subject, issuer and
// verifier error text the report prints. Both were able to overprint the verdict
// with an ANSI sequence, and both survived --no-color, while the exit code and
// the JSON stayed honest. That is why the text renderer has to be fixed rather
// than relied upon.
//
// This lives in its own package so the analyzer and the reporter share one
// implementation. They previously could not: the policy path was sanitised and
// the certificate path was not, and the difference was invisible because both
// looked correct in isolation.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

// MaxReportDetail is the budget every report field uses. It lives here so the
// analyzer and the reporter cannot drift apart on it, which is the same shape as
// the two copies of the sanitiser this package was extracted to remove.
const MaxReportDetail = 500

// ForReport collapses control characters to spaces and caps the length.
//
// Collapsing rather than deleting keeps the text's shape recognisable, so a
// reader can still see that something odd was in the field.
func ForReport(s string, maxLen int) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f: // C0 controls, including newline and ESC
			b.WriteRune(' ')
		case r >= 0x80 && r <= 0x9f: // C1 controls, a second escape route
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())

	// Collapsing the newlines stops the layout being forged; a very long single
	// line would still wrap far enough to push the real verdict out of view, so
	// cap it. Truncation is on a rune boundary, because cutting mid-sequence
	// produces invalid UTF-8.
	if len(out) > maxLen {
		budget := maxLen - 3
		if budget < 1 {
			budget = 1
		}
		// Walk the runes once, accumulating the encoded length, rather than
		// rebuilding the whole string to measure it after dropping each rune.
		// That loop was O(n^2) in the length of untrusted text: a 300 KB policy
		// name cost 100 seconds of CPU before any socket was opened.
		var cut strings.Builder
		total := 0
		for _, r := range out {
			n := utf8.RuneLen(r)
			if total+n > budget {
				break
			}
			cut.WriteRune(r)
			total += n
		}
		out = cut.String() + "..."
	}
	return out
}
