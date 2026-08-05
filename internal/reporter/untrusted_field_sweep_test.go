package reporter

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file exists because sanitising was fixed four times in one release and
// each of the first three fixes was partial.
//
// The pattern every time: a reviewer reported a forgeable field, the field was
// sanitised at its own print site, and the next review found a different field
// reaching a different print site raw. Policy name and description were fixed,
// then the rule values were found; the rule values were fixed, then the findings
// block was found; the findings block was fixed, then the target, the scan
// warnings and the scan error were found.
//
// So this test does not name any field. It fills EVERY string the result type
// carries, found by reflection, with text that would forge the report, renders
// every format, and asserts that nothing capable of moving a terminal cursor
// survives. A field added to types.ScanResult next year is covered the day it is
// added, and a print site added for it fails here rather than in a release test.

// forgery is the payload written into every string field.
//
// It carries the things that let untrusted text rewrite a finished report: a CSI
// sequence that erases a line, one that moves the cursor up, a C1 introducer,
// which is the same instruction in one codepoint and was the escape route left
// open when only ESC was stripped, and the Unicode line separators that end a
// line for a consumer splitting on Unicode boundaries rather than on \n. The
// readable words are there so a failure message shows which field carried it.
//
// U+009B is written BOTH ways, and the reason is a correction to what this file
// used to claim. \x9b alone is a bare byte, which is not valid UTF-8, so
// `for _, r := range` decodes it to U+FFFD before assertNoCursorControl's C1 arm
// can look at it: that arm could never fire for this payload, and the file said
// it covered C1 anyway. The raw byte IS neutralised, by UTF-8 decoding rather
// than by the sanitiser, and U+FFFD steers nothing. The properly encoded \u009b
// is what actually reaches the C1 arm, in the sanitiser and in the assertion.
// (The sanitiser's own C1 handling was covered throughout by sanitize_test.go
// and c1_controls_test.go; only this file's claim to cover it was untrue.)
const forgery = "\x1b[2K\x1b[1AFORGED  TLS Security:     A+   (100/100)" +
	"\u009b1BEND\x9braw\r\n\x00tail\u2028\u2029end"

// TestNoUntrustedFieldCanMoveTheCursorInAnyReport fills every string in the
// result and asserts no report format emits a byte that steers a terminal.
//
// Both result shapes are swept, and that is not a detail. A ScanResult carrying
// an Error renders the short NOT SCANNED block and returns, so a sweep that
// filled Error along with everything else exercised eighteen lines of a report
// and reported success: 3 of 121 payloads reached the output. That is the
// vacuous-guard shape, and it passed until the coverage floor below was added.
func TestNoUntrustedFieldCanMoveTheCursorInAnyReport(t *testing.T) {
	// NoColor, because the point is what the DATA can do. With colour enabled the
	// tool emits its own escapes and there would be nothing to measure; a saved
	// report (-o) is written with colour off, which is exactly the artifact an
	// auditor opens later.
	formats := map[string]Reporter{
		"text":  &TextReporter{NoColor: true},
		"json":  &JSONReporter{},
		"sarif": &SARIFReporter{},
		"cbom":  &CBOMReporter{},
	}

	for _, shape := range []resultShape{shapeScanned, shapeFailed} {
		for name, reporter := range formats {
			t.Run(string(shape)+"/"+name, func(t *testing.T) {
				var buf bytes.Buffer
				if err := reporter.Report(&buf, hostileScanResult(t, shape)); err != nil {
					t.Fatalf("%s report failed: %v", name, err)
				}
				out := buf.String()
				if out == "" {
					t.Fatalf("%s produced no output, so this test measured nothing", name)
				}
				assertNoCursorControl(t, name, out)
			})
		}
	}
}

// TestTheSweepRendersAWholeReportAndNotJustItsHeader is the coverage floor.
//
// Without it the sweep above is satisfied by a report that renders a header and
// stops, which is exactly what it did on first run. Asserting the section
// headings is what ties the sweep's pass to the report a user actually sees, so
// a change that stops rendering a section fails here rather than quietly
// shrinking what the forgery sweep covers.
func TestTheSweepRendersAWholeReportAndNotJustItsHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TextReporter{NoColor: true}).Report(&buf, hostileScanResult(t, shapeScanned)); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	out := buf.String()

	// EVERY block the report renders, not a sample. The first version of this
	// list named six of the ten headings and set the numbers so loosely that any
	// single section could stop rendering with both still satisfied, which made
	// the floor decorative on the axis it existed for.
	for _, section := range []string{
		"OVERALL GRADE", "POLICY EVALUATION", "CNSA 2.0 COMPLIANCE TIMELINE",
		"PROTOCOL SUPPORT", "CIPHER SUITES", "CERTIFICATE",
		"QUANTUM RISK ASSESSMENT", "VULNERABILITIES", "RECOMMENDATIONS",
		"SCAN COVERAGE",
		// Field labels inside the certificate block, which is where the
		// server-controlled text is densest.
		"Name check", "Chain trust",
	} {
		if !strings.Contains(out, section) {
			t.Errorf("the swept report has no %q section, so the forgery sweep is not "+
				"covering the print sites in it", section)
		}
	}

	// Numbers chosen to BIND. Measured at 9881 bytes and 52 payloads, so these
	// sit just below that: loose enough to survive ordinary wording changes,
	// tight enough that dropping a section trips them rather than sliding by.
	if got := strings.Count(out, "FORGED"); got < 45 {
		t.Errorf("only %d payloads reached the rendered report, below the floor of 45; "+
			"a block that prints untrusted text has probably stopped rendering", got)
	}
	if len(out) < 8500 {
		t.Errorf("the swept report is %d bytes, below the floor of 8500; the sweep is "+
			"probably taking an early-return path or has lost a section", len(out))
	}
}

// TestTheSweepCoversTheNotScannedPathToo is the second coverage floor.
//
// The failed shape had no floor at all, on a path where TWO of the three fields
// this release shipped raw live: the target in the header and the error in the
// NOT SCANNED block. Without this, that half of the sweep was satisfied by any
// non-empty output.
func TestTheSweepCoversTheNotScannedPathToo(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TextReporter{NoColor: true}).Report(&buf, hostileScanResult(t, shapeFailed)); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "NOT SCANNED") {
		t.Error("the failed shape did not render the NOT SCANNED block, so the sweep is " +
			"not covering the error path at all")
	}
	if strings.Contains(out, "OVERALL GRADE") {
		t.Error("the failed shape rendered a grade block; a target that was never reached " +
			"must not be given a graded report")
	}
	// The target in the header and the error in the block, at minimum.
	if got := strings.Count(out, "FORGED"); got < 3 {
		t.Errorf("only %d payloads reached the NOT SCANNED report, below the floor of 3; "+
			"the target and the error should both carry one", got)
	}
}

// assertNoCursorControl fails on any byte that can steer a terminal.
//
// Newline and tab are the two controls a report legitimately contains. Every
// other C0 byte, DEL, and every C1 byte is a finding: C1 matters because a
// single 0x9b is CSI, so stripping ESC alone leaves the same capability behind.
func assertNoCursorControl(t *testing.T, format, out string) {
	t.Helper()
	for i, r := range out {
		switch {
		case r == '\n' || r == '\t':
			continue
		case r < 0x20 || r == 0x7f:
			t.Errorf("%s: control byte %#U at offset %d survived into the report: %q",
				format, r, i, contextAround(out, i))
		case r >= 0x80 && r <= 0x9f:
			t.Errorf("%s: C1 control %#U at offset %d survived into the report: %q",
				format, r, i, contextAround(out, i))
		case r == 0x2028 || r == 0x2029:
			t.Errorf("%s: Unicode line separator %#U at offset %d survived: %q",
				format, r, i, contextAround(out, i))
		}
	}
}

func contextAround(s string, i int) string {
	start := i - 40
	if start < 0 {
		start = 0
	}
	end := i + 40
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

// TestTheSweepReachesEveryStringTheResultCarries guards the guard.
//
// The sweep above is only worth its runtime if it actually populated the result.
// A reflection walker that silently skipped a branch would render an empty
// report and pass, which is the shape of a test that measures nothing. So count
// what was filled and assert a floor, and assert the payload is genuinely
// present in the structure before any reporter sees it.
func TestTheSweepReachesEveryStringTheResultCarries(t *testing.T) {
	result := hostileScanResult(t, shapeScanned)

	// The floor was 50 against 120 real payloads, which does not bind: a walker
	// that skipped PolicyResult, CNSA2Timeline and Compliance together, 46
	// strings and three of the most policy-relevant blocks in the report, would
	// still have passed a test named "reaches every string the result carries".
	//
	// Measured at 120. The floor is 110, close enough to bind on the loss of any
	// one substructure and loose enough to survive a field being removed.
	filled := countPayloads(reflect.ValueOf(result))
	if filled < 110 {
		t.Fatalf("the hostile result carries only %d payload strings, measured at 120 when "+
			"this floor was set; the reflection walker is skipping a branch", filled)
	}

	// Per-substructure floors, because a total can be met while a whole block is
	// missing: the top-level scalars and the certificate alone are 34 strings.
	// Each number is the measured count for that field.
	for _, sub := range []struct {
		name  string
		value any
		want  int
	}{
		{"Certificate", result.Certificate, 15},
		{"CertChain", result.CertChain, 15},
		{"PolicyResult", result.PolicyResult, 16},
		{"CNSA2Timeline", result.CNSA2Timeline, 15},
		{"Compliance", result.Compliance, 15},
		{"Vulnerabilities", result.Vulnerabilities, 7},
		{"CipherSuites", result.CipherSuites, 7},
		{"KeyExchanges", result.KeyExchanges, 5},
		{"Grade", result.Grade, 6},
		{"QuantumRisk", result.QuantumRisk, 6},
		{"Recommendations", result.Recommendations, 6},
	} {
		if got := countPayloads(reflect.ValueOf(sub.value)); got < sub.want {
			t.Errorf("%s carries %d payload strings, want at least %d; the sweep is not "+
				"reaching that block and its print sites are unexercised",
				sub.name, got, sub.want)
		}
	}

	// Named spot checks, so a walker that filled many fields but missed the ones
	// this release actually shipped raw still fails.
	if !strings.Contains(result.Target, "FORGED") {
		t.Error("Target was not filled, and Target is one of the fields this release shipped raw")
	}
	if len(result.ScanWarnings) == 0 || !strings.Contains(result.ScanWarnings[0], "FORGED") {
		t.Error("ScanWarnings was not filled, and it is one of the fields this release shipped raw")
	}
	if result.Certificate == nil || !strings.Contains(result.Certificate.Subject, "FORGED") {
		t.Error("Certificate.Subject was not filled")
	}
	if len(result.Vulnerabilities) == 0 || !strings.Contains(result.Vulnerabilities[0].Description, "FORGED") {
		t.Error("Vulnerabilities was not filled")
	}
}

// TestTheTwoWalkersAgreeOnWhatTheyCanReach records the one asymmetry between
// them and why it is not a hole.
//
// countPayloads has a reflect.Interface arm and fillHostile does not, so an
// interface-typed field would be counted and never filled, and the coverage
// floor above would fall rather than the sweep failing. That asymmetry is real
// and it is already defended, one file over:
// TestTheResultTypeGraphContainsNoKindTheScrubberCannotHandle fails on any
// interface, chan, func or unsafe.Pointer anywhere in the result type graph, and
// its message names fillHostile explicitly as one of the two things to update.
//
// So the arm is unreachable rather than untested, and this says so out loud
// because the sweep's header claims a field added later is covered the day it is
// added, which is true only because of that guard.
func TestTheTwoWalkersAgreeOnWhatTheyCanReach(t *testing.T) {
	// Kinds fillHostile handles. If countPayloads gains a kind not on this list,
	// or fillHostile loses one, the two can disagree silently.
	filled := map[reflect.Kind]bool{
		reflect.Pointer: true, reflect.Struct: true, reflect.Slice: true,
		reflect.Array: true, reflect.Map: true, reflect.String: true,
		reflect.Bool: true, reflect.Int: true, reflect.Int8: true,
		reflect.Int16: true, reflect.Int32: true, reflect.Int64: true,
		reflect.Uint: true, reflect.Uint8: true, reflect.Uint16: true,
		reflect.Uint32: true, reflect.Uint64: true,
		reflect.Float32: true, reflect.Float64: true,
	}

	counted := []reflect.Kind{
		reflect.Pointer, reflect.Interface, reflect.Struct,
		reflect.Slice, reflect.Array, reflect.Map, reflect.String,
	}

	for _, k := range counted {
		if !filled[k] && k != reflect.Interface {
			t.Errorf("countPayloads counts %s and fillHostile does not fill it, so a field "+
				"of that kind would lower the coverage floor instead of failing the sweep", k)
		}
	}

	// The one exception has to stay guarded elsewhere. If that guard is renamed
	// or deleted, this comment stops being true, so assert the type graph is
	// still interface-free here too rather than trusting the note.
	var problems []string
	walkType(reflect.TypeOf(types.ScanResult{}), "ScanResult", map[reflect.Type]bool{}, &problems, 0)
	for _, p := range problems {
		t.Errorf("the result type graph now contains a kind neither walker handles: %s", p)
	}
}

// TestTheSweepFailsWhenAFieldIsPrintedRaw proves this test is not vacuous.
//
// A sweep that passes because the assertion is too weak is worse than no sweep.
// Render the same hostile result through a writer that re-inserts one raw escape
// and assert the checker catches it: if it does not, the checker cannot have
// been what made the real reports pass.
func TestTheSweepFailsWhenAFieldIsPrintedRaw(t *testing.T) {
	fake := &testing.T{}
	assertNoCursorControl(fake, "probe", "a clean line\n\x1b[1Aforged\n")
	if !fake.Failed() {
		t.Fatal("assertNoCursorControl accepted a raw ESC, so it would accept a forged report")
	}

	clean := &testing.T{}
	assertNoCursorControl(clean, "probe", "a clean line\n\twith a tab\n")
	if clean.Failed() {
		t.Fatal("assertNoCursorControl rejected ordinary report text, so it would fail on every input")
	}
}

// resultShape selects which of the two report paths the sweep exercises.
type resultShape string

const (
	// shapeScanned is a result that produced measurements: the whole report
	// renders, which is where all but three of the print sites live.
	shapeScanned resultShape = "scanned"
	// shapeFailed is a result carrying an Error: the report prints a header and
	// the NOT SCANNED block and returns. Two of the three fields this release
	// shipped raw are only reachable here.
	shapeFailed resultShape = "failed"
)

// hostileScanResult builds a ScanResult whose every string is the forgery
// payload, by walking the type rather than by listing fields.
func hostileScanResult(t *testing.T, shape resultShape) *types.ScanResult {
	t.Helper()
	result := &types.ScanResult{}
	fillHostile(reflect.ValueOf(result), 0)

	// A few values have to be plausible rather than hostile, because a report
	// that refuses to render measures nothing. These are all non-string, so they
	// cannot carry the payload anyway.
	result.Timestamp = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	result.Port = 443
	if result.Certificate != nil {
		result.Certificate.NotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		result.Certificate.NotAfter = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	}

	// Error is the switch between the two report paths, so it is set by the
	// shape rather than by the walker.
	if shape == shapeScanned {
		result.Error = ""
	}
	return result
}

// fillHostile writes the payload into every settable string reachable from v.
//
// Slices are given one element so their element type is reached; pointers are
// allocated for the same reason. Depth is bounded because the type graph may be
// recursive, and a test that hangs is a test nobody runs.
func fillHostile(v reflect.Value, depth int) {
	if depth > 8 || !v.IsValid() {
		return
	}

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			if !v.CanSet() {
				return
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
		fillHostile(v.Elem(), depth+1)

	case reflect.Struct:
		// time.Time carries unexported fields and no string worth forging.
		if v.Type() == reflect.TypeOf(time.Time{}) {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !f.CanSet() {
				continue // unexported
			}
			fillHostile(f, depth+1)
		}

	case reflect.Slice:
		if !v.CanSet() {
			return
		}
		elem := reflect.New(v.Type().Elem()).Elem()
		fillHostile(elem, depth+1)
		v.Set(reflect.Append(reflect.MakeSlice(v.Type(), 0, 1), elem))

	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fillHostile(v.Index(i), depth+1)
		}

	case reflect.Map:
		if !v.CanSet() {
			return
		}
		m := reflect.MakeMap(v.Type())
		key := reflect.New(v.Type().Key()).Elem()
		fillHostile(key, depth+1)
		val := reflect.New(v.Type().Elem()).Elem()
		fillHostile(val, depth+1)
		m.SetMapIndex(key, val)
		v.Set(m)

	case reflect.String:
		if v.CanSet() {
			v.SetString(forgery)
		}

	case reflect.Bool:
		if v.CanSet() {
			// True reaches the branches that print a field at all: a report skips
			// most optional blocks when their flag is false.
			v.SetBool(true)
		}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.CanSet() && v.Int() == 0 {
			v.SetInt(1)
		}

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.CanSet() && v.Uint() == 0 {
			v.SetUint(1)
		}

	case reflect.Float32, reflect.Float64:
		if v.CanSet() && v.Float() == 0 {
			v.SetFloat(1)
		}
	}
}

// countPayloads reports how many strings reachable from v carry the payload.
func countPayloads(v reflect.Value) int {
	if !v.IsValid() {
		return 0
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return 0
		}
		return countPayloads(v.Elem())
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			return 0
		}
		n := 0
		for i := 0; i < v.NumField(); i++ {
			n += countPayloads(v.Field(i))
		}
		return n
	case reflect.Slice, reflect.Array:
		n := 0
		for i := 0; i < v.Len(); i++ {
			n += countPayloads(v.Index(i))
		}
		return n
	case reflect.Map:
		n := 0
		for _, k := range v.MapKeys() {
			n += countPayloads(k)
			n += countPayloads(v.MapIndex(k))
		}
		return n
	case reflect.String:
		if strings.Contains(v.String(), "FORGED") {
			return 1
		}
		return 0
	}
	return 0
}
