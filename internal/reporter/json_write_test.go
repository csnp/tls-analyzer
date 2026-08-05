package reporter

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

// WriteJSON rewrites bytes inside already-encoded JSON, which is the kind of
// code that corrupts output silently and only for inputs nobody tried. So it is
// held to a property rather than to examples, with the stock encoder as the
// oracle.
//
// Property: WriteJSON must change the ENCODING and never the VALUE. Whatever
// goes in must decode back identical to what the stock encoder would yield, for
// arbitrary bytes including invalid UTF-8, a lone 0xC2, 0xC2 followed by a byte
// outside the C1 range, DEL, and both boundaries of the escaped block.
func TestWriteJSONChangesTheEncodingAndNeverTheValue(t *testing.T) {
	fixed := []string{
		// Every control character is written as an escape. The literal form is
		// invisible in a diff and in a review, which is why staticcheck's ST1018
		// exists and why this release converted another fixture away from it.
		// BOTH boundaries of the block escapeRemainingControls handles, U+0080 and
		// U+009F, plus the printable characters either side of it. Rewriting the
		// control characters as escapes for the linter dropped both boundaries
		// once, and a mutation narrowing the upper bound to 0x9e then survived:
		// U+009F is APC, a live terminal control, and nothing would have noticed
		// if the escaper stopped handling it.
		"", "plain", "\x1b", "\u0080", "\u009f", "\u009b", "\u0085", "\x7f", "~",
		"\u007f\u0080", "\u009f\u00a0", "\u0080\u009f",
		// A lone 0xC2, and 0xC2 followed by bytes on both sides of the C1 range.
		"\xc2", "\xc2\x7f", "\xc2\xa0", "\xc3\x9b", "\xc2\x9b\xc2\x9b",
		// Invalid UTF-8, a surrogate, and an overlong encoding.
		"\xff\xfe", "a\xc2", "\xc2b", "\xed\xa0\x80", "\xc0\x80",
		// C0 including NUL, and the boundary either side of the C0 block.
		"\x00\x1f\x20", "\u2028\u2029",
		"emoji \U0001F600", "\u00bf\u00c0", strings.Repeat("\u009b", 500),
		"tail\xc2", "quote\"back\\slash",
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 4000; i++ {
		b := make([]byte, r.Intn(24))
		for j := range b {
			b[j] = byte(r.Intn(256))
		}
		fixed = append(fixed, string(b))
	}

	for _, s := range fixed {
		var buf bytes.Buffer
		if err := WriteJSON(&buf, map[string]string{"v": s}, ""); err != nil {
			t.Fatalf("WriteJSON(%q) errored: %v", s, err)
		}
		var got map[string]string
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("output for %q is not valid JSON: %v\n%s", s, err, buf.String())
		}

		// The stock encoder is the oracle: WriteJSON must agree with it on the
		// decoded value, differing only in how the bytes are spelled.
		var plain bytes.Buffer
		if err := json.NewEncoder(&plain).Encode(map[string]string{"v": s}); err != nil {
			t.Fatalf("baseline encode failed: %v", err)
		}
		var want map[string]string
		if err := json.Unmarshal(plain.Bytes(), &want); err != nil {
			t.Fatalf("baseline is not valid JSON: %v", err)
		}
		if got["v"] != want["v"] {
			t.Errorf("value changed.\n input %q\n   got %q\n  want %q", s, got["v"], want["v"])
		}

		for _, ru := range buf.String() {
			if ru == 0x7f || (ru >= 0x80 && ru <= 0x9f) {
				t.Errorf("input %q left an unescaped control %#U in the output: %s",
					s, ru, buf.String())
			}
		}
		if !utf8.ValidString(buf.String()) {
			t.Errorf("input %q produced invalid UTF-8 output: %q", s, buf.String())
		}
	}
}

// TestWriteJSONEscapesOnlyWhatATerminalExecutes bounds the escaping from the
// other side.
//
// The round-trip property above cannot see an escaper that is too GREEDY:
// rewriting "£" as £ preserves the value perfectly and decodes identically,
// so every assertion there still passes. Widening the C1 test from 0x9f to 0xbf
// does exactly that and survived the property test. It would escape U+0080
// through U+00BF, which is ordinary printable Latin-1 that a terminal displays
// and never executes, and it would make any report carrying a non-ASCII
// certificate subject unreadable.
func TestWriteJSONEscapesOnlyWhatATerminalExecutes(t *testing.T) {
	// Printable, must survive as itself.
	for _, s := range []string{" ", "£", "¿", "é", "€", "中"} {
		var buf bytes.Buffer
		if err := WriteJSON(&buf, map[string]string{"v": s}, ""); err != nil {
			t.Fatalf("WriteJSON(%q): %v", s, err)
		}
		if !strings.Contains(buf.String(), s) {
			t.Errorf("printable %q was escaped rather than emitted: %s", s, buf.String())
		}
	}

	// Executable, must be escaped.
	for _, s := range []string{"\u0080", "\u009f", "\u009b", "\u0085", "\x7f"} {
		var buf bytes.Buffer
		if err := WriteJSON(&buf, map[string]string{"v": s}, ""); err != nil {
			t.Fatalf("WriteJSON(%q): %v", s, err)
		}
		if strings.Contains(buf.String(), s) {
			t.Errorf("control %q reached the output raw: %q", s, buf.String())
		}
	}
}

// TestEscapeRemainingControlsHandlesATruncatedSequence pins the bound directly.
//
// A lone 0xC2 as the final byte cannot occur in encoded JSON, which always ends
// with a brace and a newline, so this is unreachable through WriteJSON and a
// mutation of the bound survives the property test above. It is still the
// difference between returning the input and indexing past the end of the slice,
// and a panic in a report writer is not an acceptable failure mode, so the
// function is exercised directly.
func TestEscapeRemainingControlsHandlesATruncatedSequence(t *testing.T) {
	for _, in := range [][]byte{
		{0xc2},
		{'x', 0xc2},
		{0xc2, 0xc2},
		{},
		{0xc2, 0x7f},
	} {
		got := escapeRemainingControls(append([]byte(nil), in...))
		if !utf8.Valid(got) && utf8.Valid(in) {
			t.Errorf("input %x became invalid UTF-8: %x", in, got)
		}
		// A trailing lone 0xC2 has no second byte to escape, so it must be
		// carried through untouched rather than read past.
		if len(in) > 0 && in[len(in)-1] == 0xc2 && got[len(got)-1] != 0xc2 {
			t.Errorf("input %x lost its trailing byte: %x", in, got)
		}
	}
}
