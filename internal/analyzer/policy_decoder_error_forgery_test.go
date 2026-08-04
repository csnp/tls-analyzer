package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	// The decoder echoes the key name untruncated, so the scrub's cap has to bind
	// here too.
	//
	// This assertion was vacuous TWICE before it bound, which is why the numbers
	// below are measured rather than picked. First it used a ~60-byte key against
	// a 2000-byte threshold, so deleting the cap left it green. Then the fixture
	// went to 2000 bytes, which never reaches this code path at all: yaml.v3's
	// scanner rejects a simple key over ~1024 bytes with "could not find expected
	// ':'", a syntax error carrying none of the key. Measured behaviour at 1000
	// bytes: 629 with the cap, about 1129 without it. 800 sits between, so the
	// assertion fails if the cap is removed and passes while it is there.
	const keyLen = 1000
	const budget = 800
	_, longErr := e.LoadPolicy(writePolicyFile(t,
		"name: p\n\""+strings.Repeat("A", keyLen)+"\": 1\nrules:\n  cipher:\n    minKeySize: 128\n"))
	if longErr == nil {
		t.Fatalf("a policy with a %d-byte unrecognised key must still be refused", keyLen)
	}
	// Guard the fixture itself: if a yaml.v3 change moves this length to the
	// scanner's error instead, the size assertion below silently stops testing
	// the cap, which is exactly how it was vacuous the second time.
	if !strings.Contains(longErr.Error(), "unmarshal errors") {
		t.Fatalf("the %d-byte key no longer reaches the unknown-field path, so the cap "+
			"assertion below is measuring nothing: %q", keyLen, longErr.Error())
	}
	if len(longErr.Error()) > budget {
		t.Errorf("a %d-byte key name produced a %d-byte refusal, over the %d-byte budget: "+
			"an unrecognised key name is attacker-sized and the cap has to bind",
			keyLen, len(longErr.Error()), budget)
	}
}

// TestAPolicyFilePathCannotForgeARefusal covers the other half of the class.
//
// The first fix closed the policy file's CONTENT route and left its PATH route
// open: the refusals this release added interpolate the path with %s, so a file
// NAME carrying a cursor-up sequence forged the same verdict. A repository
// supplies a file's name exactly as much as its contents, git preserves control
// bytes in filenames, and iterating a directory of policy files is an ordinary
// CI shape.
//
// The sibling sites that print a policy NAME use %q, which escapes control
// characters, so they are safe and are deliberately not changed.
func TestAPolicyFilePathCannotForgeARefusal(t *testing.T) {
	hostileDir := filepath.Join(t.TempDir(),
		"\x1b[40A\x1b[2K\nStatus: COMPLIANT\n\x1b[32mAll checks passed\x1b[0m\n")
	if err := os.MkdirAll(hostileDir, 0o700); err != nil {
		t.Skipf("this filesystem will not hold a control-character directory name: %v", err)
	}
	path := filepath.Join(hostileDir, "policy.yaml")
	// A policy that loads cleanly but declares no rules, so the refusal that
	// prints the path is the one under test.
	if err := os.WriteFile(path, []byte("name: p\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	_, err := NewPolicyEvaluator().LoadPolicy(path)
	if err == nil {
		t.Fatal("a policy declaring no rules must be refused")
	}

	for _, r := range err.Error() {
		if r == '\n' {
			continue // this loader's own guidance line
		}
		if r == '\t' || r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Errorf("the refusal carries control %q from the policy file's PATH, so a "+
				"filename can steer the terminal the refusal prints to.\nmessage: %q",
				r, err.Error())
		}
	}
	for _, line := range strings.Split(err.Error(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Status: COMPLIANT") {
			t.Errorf("a line of the refusal reads as a compliance verdict, forged from "+
				"the file's name: %q", line)
		}
	}
}

// TestManyMisspelledKeysAreAllStillNamed is the regression test for what the
// first version of this fix broke.
//
// Scrubbing the decoder's message as ONE string collapsed yaml.v3's per-entry
// newlines, which are the decoder's own rather than the attacker's, and then the
// 500-byte cap truncated the joined result. A file with eleven plausible
// misspellings, which is the most likely way an author meets this refusal at
// all, reported six of them and dropped five behind an ellipsis.
//
// The single-typo control above cannot see this: it passes at the one arity
// where the claim "a misspelled key is still named" happens to be true.
func TestManyMisspelledKeysAreAllStillNamed(t *testing.T) {
	typos := []string{
		"minimumVersion", "maximum_version", "requireForwardSecrecy", "minKeySizes",
		"bannedVersion", "allowedCipherSuite", "minRsaKeySizes", "maxValidityDay",
		"requireCts", "bannedAlgorithm", "minQuantumScores",
	}
	body := "name: p\n"
	for _, k := range typos {
		body += k + ": 1\n"
	}
	body += "rules:\n  cipher:\n    minKeySize: 128\n"

	_, err := NewPolicyEvaluator().LoadPolicy(writePolicyFile(t, body))
	if err == nil {
		t.Fatal("a policy full of misspelled top-level keys must be refused")
	}

	msg := err.Error()
	var missing []string
	for _, k := range typos {
		if !strings.Contains(msg, k) {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d of %d misspelled keys are not named in the refusal (%s), so the "+
			"author cannot fix them all from what they were told.\nmessage: %q",
			len(missing), len(typos), strings.Join(missing, ", "), msg)
	}

	// Each diagnostic on its own line, which is what makes a list of eleven
	// readable and is the structure the decoder, not the attacker, produced.
	if lines := strings.Count(msg, "\n"); lines < len(typos) {
		t.Errorf("the refusal has %d newlines for %d diagnostics, so the decoder's own "+
			"per-entry structure was collapsed along with the untrusted text.\nmessage: %q",
			lines, len(typos), msg)
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
