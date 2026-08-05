package reporter

import (
	"bytes"
	"encoding/json"
	"io"
)

// WriteJSON encodes v as JSON with the control characters Go's encoder leaves
// raw escaped as \uXXXX.
//
// The machine-readable formats deliberately keep the bytes the server actually
// sent, rather than scrubbing them the way the text renderer does, so an
// operator diffing JSON sees what was really presented. That decision rests on
// one premise, stated in sanitize_result.go: "their encoders escape control
// characters rather than executing them, so they are honest already".
//
// The premise is only mostly true. encoding/json escapes C0 (below 0x20) and
// U+2028 and U+2029, and it does NOT escape DEL or the C1 block at
// U+0080-U+009F. U+009B is CSI: it is the single-codepoint form of the ESC [
// that this release's headline fix exists to stop, it is perfectly valid UTF-8,
// and a certificate subject can carry it. So a saved report.json, sarif or cbom
// file could steer a terminal the moment somebody cat, less or grep-ed it, on
// three surfaces documented as safe.
//
// The forgery sweep could not see this because its C1 payload was a bare 0x9b
// byte, which is invalid UTF-8: encoding/json replaced it with U+FFFD and the
// assertion passed on a substitution rather than on an escape. Writing the same
// codepoint properly encoded made all three formats fail immediately.
//
// Escaping rather than scrubbing keeps the fidelity the design asked for: a JSON
// decoder yields the identical string, byte for byte, so nothing is lost to a
// consumer. Only a terminal displaying the file sees the difference, and what it
// sees is inert ASCII.
func WriteJSON(w io.Writer, v any, indent string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(escapeRemainingControls(buf.Bytes()))
	return err
}

// escapeRemainingControls rewrites DEL and the C1 block as \uXXXX escapes.
//
// It operates on ENCODED JSON, where the syntax itself is pure ASCII, so any
// occurrence of these bytes is necessarily inside a string literal and can be
// replaced without parsing. C1 encodes as 0xC2 followed by 0x80-0x9F, a complete
// two-byte sequence that cannot be the prefix of a longer one, so the scan
// cannot split a rune.
func escapeRemainingControls(b []byte) []byte {
	needs := false
	for i := 0; i < len(b); i++ {
		if b[i] == 0x7f || (b[i] == 0xc2 && i+1 < len(b) && b[i+1] >= 0x80 && b[i+1] <= 0x9f) {
			needs = true
			break
		}
	}
	if !needs {
		return b
	}

	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)+16)
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == 0x7f:
			out = append(out, '\\', 'u', '0', '0', '7', 'f')
		case b[i] == 0xc2 && i+1 < len(b) && b[i+1] >= 0x80 && b[i+1] <= 0x9f:
			out = append(out, '\\', 'u', '0', '0', hex[b[i+1]>>4], hex[b[i+1]&0xf])
			i++
		default:
			out = append(out, b[i])
		}
	}
	return out
}
