package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/scanner"
)

// A targets file is read line by line, and before this check every line that
// was not blank or a comment was a target: it was printed in the text report,
// in the JSON target and error fields and in the closing error, and a line
// without a colon was handed to the operating system's name lookup. Pointing
// --targets at the wrong file, one holding KEY=VALUE pairs, therefore printed
// and looked up its values.
//
// Every value below is built at run time and carries FAKE and a fresh nonce, so
// a hit in any output is unambiguous and cannot be a leftover from another run.
// Failure messages report counts, never the values.
//
// Mutants these tests are written to catch, and the assertion each one fails:
//   - checking each line inside the scan loop instead of before the first
//     lookup: the valid first line is looked up, so the lookup count in
//     TestATargetsFileWithAnyOtherLineIsRefusedBeforeAnyLookup is not 0;
//   - skipping refused lines and scanning the rest: same test, the run does not
//     fail and the valid line is looked up;
//   - a refusal message that quotes the line or any part of it:
//     TestARefusedTargetsFileNeverPrintsItsLines finds a FAKE marker or a
//     fragment of a refused line in the error;
//   - the old `invalid port %q` still reachable from refused input: the same
//     test, on the `key: value` line, whose value sits where a port would.

// reasons is the fixed set a refusal may give, and the only text it may give
// about a line.
const (
	reasonNotATarget = "not a host name, IP address or host:port"
	reasonURL        = "looks like a URL: use the host name, or host:port"
	reasonPort       = "the port is not a number from 1 to 65535"
	reasonEmpty      = "the target is empty"
)

// lookupRecorder stands in for the resolver and records every name it is asked
// to look up. It never touches the network.
type lookupRecorder struct {
	mu     sync.Mutex
	names  []string
	answer func(host string) ([]net.IP, error)
}

func (r *lookupRecorder) lookup(host string) ([]net.IP, error) {
	r.mu.Lock()
	r.names = append(r.names, host)
	r.mu.Unlock()
	if r.answer != nil {
		return r.answer(host)
	}
	return nil, errors.New("the test resolver answers no lookups")
}

func (r *lookupRecorder) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.names...)
}

func installLookupRecorder(t *testing.T, answer func(string) ([]net.IP, error)) *lookupRecorder {
	t.Helper()
	recorder := &lookupRecorder{answer: answer}
	previous := scanner.LookupIP
	scanner.LookupIP = recorder.lookup
	t.Cleanup(func() { scanner.LookupIP = previous })
	return recorder
}

func newNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return hex.EncodeToString(b)
}

// fakeMarker builds a value that carries FAKE, a label and the nonce.
func fakeMarker(label, nonce string) string {
	return "FA" + "KE" + label + nonce
}

func writeTargetsFile(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write targets file: %v", err)
	}
	return path
}

// cliRun is everything one run printed or returned.
type cliRun struct {
	stdout, stderr string
	err            error
}

// runCLI drives runScan with the given targets file and output settings, and
// captures what it writes to stdout and stderr. Colour stays on so the progress
// line is written to stderr when there is an output file: one more stream that
// has to stay clean.
func runCLI(t *testing.T, args []string, targets, format, output string) cliRun {
	t.Helper()

	prevTargets, prevOutput, prevFormat, prevNoColor := targetsFile, outputFile, outputFormat, noColor
	prevVulns, prevQuantum, prevCNSA2 := skipVulns, skipQuantum, skipCNSA2
	prevTimeout, prevConcurrency := timeout, concurrency
	defer func() {
		targetsFile, outputFile, outputFormat, noColor = prevTargets, prevOutput, prevFormat, prevNoColor
		skipVulns, skipQuantum, skipCNSA2 = prevVulns, prevQuantum, prevCNSA2
		timeout, concurrency = prevTimeout, prevConcurrency
	}()
	targetsFile, outputFile, outputFormat, noColor = targets, output, format, false
	skipVulns, skipQuantum, skipCNSA2 = true, true, true
	timeout, concurrency = 5, 4

	dir := t.TempDir()
	stdoutFile, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	stderrFile, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}

	prevStdout, prevStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutFile, stderrFile
	runErr := runScan(rootCmd, args)
	os.Stdout, os.Stderr = prevStdout, prevStderr
	_ = stdoutFile.Close()
	_ = stderrFile.Close()

	stdout, _ := os.ReadFile(stdoutFile.Name())
	stderr, _ := os.ReadFile(stderrFile.Name())
	return cliRun{stdout: string(stdout), stderr: string(stderr), err: runErr}
}

// hostileFile is the shape a wrong file takes: a valid target first, so a
// check made lazily inside the scan loop would look it up before reaching the
// first bad line, then the kinds of line a credentials file holds.
type hostileFile struct {
	path    string
	valid   string
	refused map[int]string // line number to the reason it must be given
	lines   map[int]string // line number to the refused text
}

func newHostileFile(t *testing.T) hostileFile {
	t.Helper()
	n := newNonce(t)

	valid := "reachable-" + n + ".example"
	lines := []string{
		valid,                                  // 1
		"DB_PASSWORD=" + fakeMarker("A", n),    // 2
		"SERVICE_TOKEN=" + fakeMarker("B", n),  // 3
		"# vellum marmot",                      // 4
		"",                                     // 5
		"smtp_password: " + fakeMarker("C", n), // 6
		"https://" + fakeMarker("U", n) + ":" + fakeMarker("P", n) +
			"@" + fakeMarker("H", n) + ".test/", // 7
		"zebra quokka " + fakeMarker("D", n) + " yak", // 8
	}
	return hostileFile{
		path:  writeTargetsFile(t, lines),
		valid: valid,
		refused: map[int]string{
			2: reasonNotATarget,
			3: reasonNotATarget,
			6: reasonPort,
			7: reasonURL,
			8: reasonNotATarget,
		},
		lines: map[int]string{2: lines[1], 3: lines[2], 6: lines[5], 7: lines[6], 8: lines[7]},
	}
}

// fragmentsFound counts the substrings of at least four bytes of secret that
// appear in text. Four bytes is short enough to catch a prefix, a suffix or a
// truncation of the line, and the fixtures are written so that no four-byte
// piece of a refused line occurs in the tool's own wording.
func fragmentsFound(text, secret string) int {
	const minFragment = 4
	found := 0
	for i := 0; i+minFragment <= len(secret); i++ {
		if strings.Contains(text, secret[i:i+minFragment]) {
			found++
		}
	}
	return found
}

// TestATargetsFileWithAnyOtherLineIsRefusedBeforeAnyLookup is cell 1: the run
// refuses before the first lookup, exits 1, and writes no report.
func TestATargetsFileWithAnyOtherLineIsRefusedBeforeAnyLookup(t *testing.T) {
	recorder := installLookupRecorder(t, nil)
	file := newHostileFile(t)
	report := filepath.Join(t.TempDir(), "report.json")

	run := runCLI(t, nil, file.path, "json", report)

	if run.err == nil {
		t.Fatal("a targets file holding lines that are not targets was accepted")
	}
	var gate *policyGateError
	if errors.As(run.err, &gate) {
		t.Error("the refusal is classified as a policy failure, which exits 2 rather than 1")
	}
	if calls := recorder.calls(); len(calls) != 0 {
		t.Errorf("the run made %d lookups; a file with any refused line must be refused "+
			"before the first one, the valid first line included", len(calls))
	}
	if _, err := os.Stat(report); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a report file was written for a refused targets file (stat: %v)", err)
	}
}

// TestARefusedTargetsFileNeverPrintsItsLines is cell 2: no FAKE marker and no
// piece of a refused line reaches stdout, stderr, the returned error or any
// file the run wrote, and the error says where to look and why.
func TestARefusedTargetsFileNeverPrintsItsLines(t *testing.T) {
	installLookupRecorder(t, nil)
	file := newHostileFile(t)
	outDir := t.TempDir()
	report := filepath.Join(outDir, "report.json")

	run := runCLI(t, nil, file.path, "json", report)
	if run.err == nil {
		t.Fatal("a targets file holding lines that are not targets was accepted")
	}
	message := run.err.Error()

	surfaces := map[string]string{
		"stdout": run.stdout,
		"stderr": run.stderr,
		// The path is the tool's to print and is not part of any line.
		"error": strings.ReplaceAll(message, file.path, "<targets file>"),
	}
	written, _ := os.ReadDir(outDir)
	for _, entry := range written {
		content, _ := os.ReadFile(filepath.Join(outDir, entry.Name()))
		surfaces["written file "+entry.Name()] = string(content)
	}

	for name, text := range surfaces {
		if hits := strings.Count(text, "FA"+"KE"); hits != 0 {
			t.Errorf("%s carries %d FAKE markers from the targets file", name, hits)
		}
		for line, refused := range file.lines {
			if found := fragmentsFound(text, refused); found != 0 {
				t.Errorf("%s carries %d fragments of refused line %d", name, found, line)
			}
		}
	}
	if fragmentsFound(surfaces["error"], "vellum marmot") != 0 {
		t.Error("the error prints a comment line from the targets file")
	}

	if !strings.Contains(message, file.path) {
		t.Errorf("the error does not name the targets file: %q", surfaces["error"])
	}
	if !strings.Contains(message, strconv.Itoa(len(file.refused))+" lines") {
		t.Errorf("the error does not give the count of refused lines (%d): %q",
			len(file.refused), surfaces["error"])
	}
	for line, reason := range file.refused {
		if want := fmt.Sprintf("line %d: %s", line, reason); !strings.Contains(message, want) {
			t.Errorf("the error does not give %q: %q", want, surfaces["error"])
		}
	}
	for _, line := range []int{1, 4, 5} {
		if strings.Contains(message, fmt.Sprintf("line %d:", line)) {
			t.Errorf("the error lists line %d, which is not refused", line)
		}
	}
}

// TestARefusalListsAtMostFiveLines keeps a long wrong file from turning the
// error into a listing of the file.
func TestARefusalListsAtMostFiveLines(t *testing.T) {
	recorder := installLookupRecorder(t, nil)
	n := newNonce(t)
	var lines []string
	for i := 0; i < 7; i++ {
		lines = append(lines, fmt.Sprintf("KEY_%d=%s", i, fakeMarker("Q", n)))
	}
	path := writeTargetsFile(t, lines)

	run := runCLI(t, nil, path, "text", "")
	if run.err == nil {
		t.Fatal("a file of seven KEY=VALUE lines was accepted")
	}
	message := run.err.Error()
	if !strings.Contains(message, "7 lines") {
		t.Errorf("the error does not count all seven refused lines: %q", message)
	}
	for line := 1; line <= 5; line++ {
		if !strings.Contains(message, fmt.Sprintf("line %d: %s", line, reasonNotATarget)) {
			t.Errorf("the error does not list line %d", line)
		}
	}
	for _, line := range []int{6, 7} {
		if strings.Contains(message, fmt.Sprintf("line %d:", line)) {
			t.Errorf("the error lists line %d, past the first five", line)
		}
	}
	if !strings.Contains(message, "and 2 more") {
		t.Errorf("the error does not say how many more lines were refused: %q", message)
	}
	if strings.Contains(message, "FA"+"KE") || len(recorder.calls()) != 0 {
		t.Errorf("the refusal printed a marker or made %d lookups", len(recorder.calls()))
	}
}

// TestAFileOfValidTargetsIsAcceptedAndItsNamesReachTheReport is the positive
// control for cells 1 and 2. It runs the same capture over a file that holds
// only valid lines, and shows the recorder sees each lookup and the report
// carries each name. Without it, a marker missing from the output above could
// mean the capture is blind rather than that the line was never printed.
func TestAFileOfValidTargetsIsAcceptedAndItsNamesReachTheReport(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	// The probes offer versions and suites the server refuses on purpose, and
	// each refusal would otherwise be logged.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	recorder := installLookupRecorder(t, func(host string) ([]net.IP, error) {
		if host == "localhost" {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		if ip := net.ParseIP(host); ip != nil {
			return []net.IP{ip}, nil
		}
		return nil, errors.New("the test resolver answers only the control's names")
	})

	targets := []string{"localhost:" + port, "127.0.0.1:" + port, "[::1]:" + port}
	path := writeTargetsFile(t, append([]string{"# only valid lines"}, targets...))
	report := filepath.Join(t.TempDir(), "report.json")

	run := runCLI(t, nil, path, "json", report)
	if run.err != nil {
		for _, reason := range []string{reasonNotATarget, reasonURL, reasonPort, reasonEmpty} {
			if strings.Contains(run.err.Error(), reason) {
				t.Fatalf("a file of valid targets was refused: %v", run.err)
			}
		}
	}

	looked := strings.Join(recorder.calls(), " ")
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if !strings.Contains(looked, host) {
			t.Errorf("the recorder did not see a lookup of %s, so it could not have seen a refused line's either", host)
		}
	}

	content, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("no report was written for a file of valid targets: %v", err)
	}
	var results []struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(content, &results); err != nil {
		t.Fatalf("the report did not parse: %v", err)
	}
	reported := map[string]bool{}
	for _, r := range results {
		reported[r.Target] = true
	}
	for _, target := range targets {
		if !reported[target] {
			t.Errorf("the report does not carry %s", target)
		}
	}
}

// TestARefusedCommandLineTargetIsNotEchoed covers the other source of targets.
// The positional argument is checked by the same rule, before any lookup, and
// the message gives the reason without any of the argument.
func TestARefusedCommandLineTargetIsNotEchoed(t *testing.T) {
	recorder := installLookupRecorder(t, nil)
	n := newNonce(t)

	cases := []struct {
		target, reason string
	}{
		{"API_KEY=" + fakeMarker("K", n), reasonNotATarget},
		{"https://" + fakeMarker("U", n) + ":" + fakeMarker("P", n) + "@" + fakeMarker("H", n) + ".test/", reasonURL},
		{"", reasonEmpty},
	}
	for i, tc := range cases {
		run := runCLI(t, []string{tc.target}, "", "text", "")
		if run.err == nil {
			t.Errorf("case %d: the command-line target was accepted", i)
			continue
		}
		message := run.err.Error()
		if !strings.Contains(message, tc.reason) {
			t.Errorf("case %d: the error does not give the reason %q: %q", i, tc.reason, message)
		}
		for name, text := range map[string]string{"stdout": run.stdout, "stderr": run.stderr, "error": message} {
			if strings.Contains(text, "FA"+"KE") {
				t.Errorf("case %d: %s carries a FAKE marker from the argument", i, name)
			}
			if found := fragmentsFound(text, tc.target); found != 0 {
				t.Errorf("case %d: %s carries %d fragments of the argument", i, name, found)
			}
		}
	}
	if calls := recorder.calls(); len(calls) != 0 {
		t.Errorf("refused command-line targets were looked up %d times", len(calls))
	}

	err := rootCmd.Args(rootCmd, []string{fakeMarker("X", n) + ".example", fakeMarker("Y", n) + ".example"})
	if err == nil {
		t.Fatal("two command-line targets were accepted")
	}
	if !strings.Contains(err.Error(), "--targets") {
		t.Errorf("two command-line targets give no pointer to --targets: %q", err.Error())
	}
	if strings.Contains(err.Error(), "FA"+"KE") {
		t.Error("the two-targets message echoes the arguments")
	}
}

// TestATargetListedTwiceIsScannedOnce compares hosts ignoring case and with the
// default port filled in. The host is printed in the note, which is fine
// because it passed the check.
func TestATargetListedTwiceIsScannedOnce(t *testing.T) {
	recorder := installLookupRecorder(t, nil)
	n := newNonce(t)
	dup := "dup-" + n + ".example"
	path := writeTargetsFile(t, []string{
		"Dup-" + n + ".Example",
		"other-" + n + ".example",
		dup + ":443",
	})

	run := runCLI(t, nil, path, "json", "")

	lookups, ofDup := recorder.calls(), 0
	for _, name := range lookups {
		if strings.EqualFold(name, dup) {
			ofDup++
		}
	}
	if ofDup != 1 || len(lookups) != 2 {
		t.Errorf("a host listed twice was looked up %d times (%d lookups in all); want 1 of 2",
			ofDup, len(lookups))
	}
	if !strings.Contains(run.stderr, "lines 1 and 3") {
		t.Errorf("no note names both lines the host is listed on; stderr: %q", run.stderr)
	}

	var results []struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal([]byte(run.stdout), &results); err != nil {
		t.Fatalf("the report did not parse: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("the report has %d results for 2 distinct targets", len(results))
	}
}

// TestATargetsFileOfOnlyCommentsSaysSo replaces "no targets specified", which
// told someone who had passed --targets to pass --targets.
func TestATargetsFileOfOnlyCommentsSaysSo(t *testing.T) {
	recorder := installLookupRecorder(t, nil)
	path := writeTargetsFile(t, []string{"# hosts to scan", "", "   ", "# none yet"})

	run := runCLI(t, nil, path, "text", "")
	if run.err == nil {
		t.Fatal("a targets file of only comments and blank lines was accepted")
	}
	if !strings.Contains(run.err.Error(), "the targets file has no targets") {
		t.Errorf("the error does not say the file has no targets: %q", run.err.Error())
	}
	if strings.Contains(run.err.Error(), "hosts to scan") {
		t.Error("the error prints a comment from the file")
	}
	if len(recorder.calls()) != 0 {
		t.Error("an empty targets file led to a lookup")
	}
}
