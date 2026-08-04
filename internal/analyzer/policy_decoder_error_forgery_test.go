package analyzer

import (
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
)

// The pre-push adversarial review found the third forgery surface still open,
// on the one path this release itself created.
//
// decodePolicy interpolates the YAML decoder's message with %s. dec.KnownFields
// (true) is new in 0.4.0, and it makes the decoder echo an unrecognised key's
// NAME back verbatim and untruncated. A policy file is untrusted text by this
// tool's own rule (it "arrives from a vendor, a repository or a colleague"), so
// a key name carrying a cursor-up sequence and newlines printed a fabricated
// verdict on stderr, which shares the terminal with the report:
//
//	Error: failed to load policy: failed to parse policy YAML: yaml: unmarshal
//	errors:
//	  line 2: field
//	Policy loaded: modern
//	Status: COMPLIANT
//	Score: 100/100
//	<green>All checks passed<reset>
//	# not found in the top level of a policy file
//
// Reproduced against the release binary: 2 raw ESC bytes on stderr and a forged
// COMPLIANT line. The baseline binary printed nothing at all here, because it
// accepted the unknown key, so this is a regression of this range rather than an
// older hole.
//
// The fix scrubs the DECODER'S MESSAGE, not the composed error. That
// distinction is the point: cmd/tlsanalyzer wraps this text in its own prose and
// its own newline, and collapsing the whole message would flatten the guidance
// line this loader deliberately prints. Untrusted text loses its newlines;
// tool-authored text keeps them.

// hostileKeyPolicy is a policy whose only defect is an unrecognised top-level
// key whose NAME is an attack. Written with Go escape sequences rather than
// literal bytes: a literal control character in a source file trips ST1018 and
// cannot be typed into a shell command safely.
// It carries BOTH escape routes: a cursor-up sequence, which steers the
// terminal, and newlines, which fabricate what look like separate lines spoken
// by the tool. A fixture with only the first leaves the "line of its own"
// assertion below vacuous.
const hostileKeyPolicy = "name: p\n" +
	"\"\\u001b[40A\\u001b[2K\\nStatus: COMPLIANT\\nScore: 100/100\\n" +
	"\\u001b[32mAll checks passed\\u001b[0m\\n#\": 1\n" +
	"rules:\n" +
	"  cipher:\n" +
	"    minKeySize: 128\n"

func TestAnUnknownKeyNameCannotForgeTheErrorOutput(t *testing.T) {
	e := NewPolicyEvaluator()

	_, err := e.LoadPolicy(writePolicyFile(t, hostileKeyPolicy))
	if err == nil {
		t.Fatal("a policy with an unrecognised top-level key must be refused; " +
			"it loaded instead, which is the fail-open this loader exists to stop")
	}

	msg := err.Error()

	// Every byte that can steer a terminal, by codepoint rather than by raw
	// byte: counting bytes in 0x80-0x9f matches the UTF-8 continuation bytes of
	// this tool's own box-drawing glyphs and produces a false count.
	for _, r := range msg {
		switch {
		case r == '\n':
			// Tool-authored, asserted below.
		case r == '\t' || r < 0x20 || r == 0x7f:
			t.Errorf("the refusal message carries C0 control %q, so an unrecognised "+
				"key name can still steer the terminal it is printed to.\nmessage: %q",
				r, msg)
		case r >= 0x80 && r <= 0x9f:
			t.Errorf("the refusal message carries C1 control %q, the second escape "+
				"route.\nmessage: %q", r, msg)
		}
	}

	// The forged verdict must not survive as a line of its own. The attacker's
	// newlines are what turn interpolated text into what looks like the tool
	// speaking, so the payload has to arrive as one line.
	for _, line := range strings.Split(msg, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Status: COMPLIANT") {
			t.Errorf("a line of the refusal reads as a compliance verdict the tool "+
				"never reached: %q", trimmed)
		}
	}

	// Direction control: scrubbing the untrusted value must not flatten the
	// loader's own guidance, which is a separate line on purpose. A fix that
	// scrubbed the whole composed error would pass every assertion above and
	// silently destroy this.
	if !strings.Contains(msg, "\nRun 'tlsanalyzer print-policy modern'") {
		t.Errorf("the loader's own guidance line was lost, so the fix scrubbed the "+
			"composed message rather than the untrusted value inside it.\nmessage: %q",
			msg)
	}

	// The decoder echoes the key name untruncated, so the scrub's cap has to
	// bind here too.
	if len(msg) > 4*sanitize.MaxReportDetail {
		t.Errorf("the refusal message is %d bytes; an unrecognised key name is "+
			"attacker-sized and must be bounded", len(msg))
	}
}

// TestAnOrdinaryUnknownKeyStillNamesItself is the acceptance control. A guard
// that refuses real input is a false clean of the opposite kind: the whole value
// of KnownFields(true) is telling an author which key they misspelled.
func TestAnOrdinaryUnknownKeyStillNamesItself(t *testing.T) {
	e := NewPolicyEvaluator()

	_, err := e.LoadPolicy(writePolicyFile(t, "name: p\nminVersionn: \"TLS 1.2\"\n"+
		"rules:\n  cipher:\n    minKeySize: 128\n"))
	if err == nil {
		t.Fatal("a misspelled top-level key must still be refused")
	}
	if !strings.Contains(err.Error(), "minVersionn") {
		t.Errorf("the refusal no longer names the offending key, so scrubbing has "+
			"cost the author the one thing this check is for: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "print-policy modern") {
		t.Errorf("the refusal no longer points at a valid starting point: %q", err.Error())
	}
}
