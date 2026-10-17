package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startLoopbackTLSServer serves TLS on 127.0.0.1 for the duration of the test
// and returns its port. The recorder installed alongside it answers 127.0.0.1
// and nothing else, so no lookup leaves the machine.
func startLoopbackTLSServer(t *testing.T) string {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	// The probes offer versions and suites the server refuses on purpose, and
	// each refusal would otherwise be logged.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	installLookupRecorder(t, func(host string) ([]net.IP, error) {
		if host == "127.0.0.1" {
			return []net.IP{net.ParseIP(host)}, nil
		}
		return nil, errors.New("the test resolver answers only 127.0.0.1")
	})
	return port
}

// TestATargetsFileListingOneTargetTwiceStillPrintsAnArray is the reproduction
// of "a targets file whose lines name one target now prints a JSON object".
// Repeated targets are scanned once, and the run then took the single-target
// path, which prints one object, so `jq '.[].target'`, the form the release
// smoke uses for --targets runs, failed with "Cannot index string". 0.4.1
// printed an array for the same file.
func TestATargetsFileListingOneTargetTwiceStillPrintsAnArray(t *testing.T) {
	port := startLoopbackTLSServer(t)
	target := "127.0.0.1:" + port
	path := writeTargetsFile(t, []string{target, target})

	run := runCLI(t, nil, path, "json", "")
	if run.err != nil {
		t.Fatalf("the scan of a reachable TLS server failed: %v", run.err)
	}

	var results []struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal([]byte(run.stdout), &results); err != nil {
		t.Fatalf("a targets file listing one target twice did not print a JSON array: %v", err)
	}
	if len(results) != 1 || results[0].Target != target {
		t.Errorf("the array holds %d results; want the one target, scanned once", len(results))
	}
}

// TestATargetsFileOfOneLinePrintsAnObject keeps the other side: a file with a
// single line printed one object in 0.4.1, and still does.
func TestATargetsFileOfOneLinePrintsAnObject(t *testing.T) {
	port := startLoopbackTLSServer(t)
	target := "127.0.0.1:" + port
	path := writeTargetsFile(t, []string{target})

	run := runCLI(t, nil, path, "json", "")
	if run.err != nil {
		t.Fatalf("the scan of a reachable TLS server failed: %v", run.err)
	}

	var result struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal([]byte(run.stdout), &result); err != nil {
		t.Fatalf("a targets file of one line did not print a JSON object: %v", err)
	}
	if result.Target != target {
		t.Errorf("the object names %q; want %q", result.Target, target)
	}
}

// TestATargetsFileStartingWithAByteOrderMarkIsRead is the reproduction of "a
// targets file that starts with a UTF-8 byte order mark is refused at line 1".
// Some Windows editors and PowerShell write one. TrimSpace leaves U+FEFF in
// place, so the first line failed the check and the whole file was refused,
// and the refusal never prints the line, so nothing showed the cause.
func TestATargetsFileStartingWithAByteOrderMarkIsRead(t *testing.T) {
	recorder := installLookupRecorder(t, nil)
	n := newNonce(t)
	first, second := "bom-"+n+".example", "crlf-"+n+".example"

	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "\xef\xbb\xbf" + first + "\r\n" + second + "\r\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	run := runCLI(t, nil, path, "json", "")
	if run.err != nil && strings.Contains(run.err.Error(), reasonNotATarget) {
		t.Fatalf("a targets file starting with a byte order mark was refused: %v", run.err)
	}

	looked := recorder.calls()
	for _, host := range []string{first, second} {
		found := false
		for _, name := range looked {
			if name == host {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not looked up; lookups: %q", host, looked)
		}
	}
}

// TestAByteOrderMarkAfterTheFirstLineIsStillRefused brackets the fix: only the
// mark a file starts with is removed. U+FEFF anywhere else is not part of a
// host name, and that line is refused.
func TestAByteOrderMarkAfterTheFirstLineIsStillRefused(t *testing.T) {
	recorder := installLookupRecorder(t, nil)
	n := newNonce(t)

	path := writeTargetsFile(t, []string{"first-" + n + ".example", "\xef\xbb\xbfsecond-" + n + ".example"})

	run := runCLI(t, nil, path, "json", "")
	if run.err == nil || !strings.Contains(run.err.Error(), "line 2: "+reasonNotATarget) {
		t.Fatalf("a byte order mark at the start of line 2 was accepted: %v", run.err)
	}
	if calls := recorder.calls(); len(calls) != 0 {
		t.Errorf("a refused file led to %d lookups", len(calls))
	}
}
