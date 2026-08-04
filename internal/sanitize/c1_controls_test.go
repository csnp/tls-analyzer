package sanitize

import (
	"strings"
	"testing"
)

// TestAProperlyEncodedC1ControlIsCollapsed
//
// A mutation narrowing the C1 range survived the whole suite, which meant the C1
// arm was untested. The reason it looked covered: every test reaching it used a
// RAW 0x9b byte, and a raw 0x9b is invalid UTF-8, so ranging the string yields
// U+FFFD and the C1 arm never runs at all. The bytes are neutralised either way,
// which is why nothing failed, but the arm that exists for C1 was never the
// thing doing it. That is the difference between a defence and a coincidence.
//
// A C1 control encoded properly (U+009B, two bytes 0xc2 0x9b) IS a valid rune
// and does reach the arm. U+009B is CSI on its own: a terminal reading it begins
// a control sequence with no ESC anywhere, so stripping ESC alone leaves the
// same capability behind.
func TestAProperlyEncodedC1ControlIsCollapsed(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"CSI as a single rune", "before\u009bafter"},
		{"NEL, next line", "before\u0085after"},
		{"the C1 block boundaries", "\u0080\u008f\u009f"},
		{"CSI driving a cursor move", "x\u009b2K\u009b1AFORGED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ForReport(tc.in, MaxReportDetail)
			for _, r := range got {
				if r >= 0x80 && r <= 0x9f {
					t.Errorf("a C1 control %#U survived ForReport: %q", r, got)
				}
			}
		})
	}
}

// TestTheCharactersEitherSideOfTheC1BlockAreKept is the acceptance control.
//
// Widening the C1 arm until it swallowed ordinary text would satisfy the test
// above and quietly damage every report carrying an accented name. U+007F is
// DEL, which is stripped by the C0 arm; U+00A0 is a non-breaking space and
// U+00A1 an inverted exclamation mark, both ordinary printable text.
func TestTheCharactersEitherSideOfTheC1BlockAreKept(t *testing.T) {
	got := ForReport("a\u00a0b¡céd", MaxReportDetail)
	for _, want := range []rune{'\u00a0', '¡', 'é', 'a', 'b', 'c', 'd'} {
		if !strings.ContainsRune(got, want) {
			t.Errorf("ForReport dropped %#U, which is ordinary printable text: %q", want, got)
		}
	}
}

// TestARawC1ByteIsAlsoNeutralised records the other half, so the distinction
// above is not lost again. An invalid byte becomes U+FFFD, which cannot steer a
// terminal, but it gets there by Go's UTF-8 decoding rather than by the C1 arm.
func TestARawC1ByteIsAlsoNeutralised(t *testing.T) {
	got := ForReport("x\x9b2K\x9b1AFORGED", MaxReportDetail)
	if strings.ContainsRune(got, 0x9b) {
		t.Errorf("a raw C1 byte survived: %q", got)
	}
	if !strings.ContainsRune(got, '�') {
		t.Errorf("expected the invalid byte to decode to U+FFFD, got %q", got)
	}
}

// TestUnicodeLineSeparatorsAreCollapsed
//
// U+2028 and U+2029 terminate a line for any consumer that splits on Unicode
// line boundaries rather than on \n, which is what a JavaScript log viewer does.
// They are the same class as the newline this package already collapses, not the
// bidi and zero-width characters deferred to 0.4.1.
func TestUnicodeLineSeparatorsAreCollapsed(t *testing.T) {
	got := ForReport("before\u2028middle\u2029after", MaxReportDetail)
	if strings.ContainsRune(got, 0x2028) || strings.ContainsRune(got, 0x2029) {
		t.Errorf("a Unicode line separator survived ForReport: %q", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Errorf("collapsing the separators lost the surrounding text: %q", got)
	}
}
