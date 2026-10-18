package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// A line of one word passes the target check, since a one-label name such as
// localhost is a valid host name, so a token on a line by itself in a targets
// file was looked up as a host name. The README and the 0.5.0 changelog said so,
// and the changelog records that on Linux such a line reached the DNS server.
// A targets file line whose host is one word is now refused before anything is
// looked up, unless --allow-single-label is given. localhost is accepted without
// it, and so is a one-word target typed on the command line.
//
// The mutation each test is written to catch:
//   - no single-label refusal, as before this change: the run is not refused and
//     the one-word lines are looked up in
//     TestAOneWordTargetsLineIsRefusedBeforeAnyLookup.
//   - the refusal checked inside the scan loop: the valid first line is looked up
//     in the same test.
//   - a refusal that quotes the line: the FAKE marker in the same test.
//   - --allow-single-label not consulted:
//     TestAOneWordTargetsLineIsLookedUpWithAllowSingleLabel.
//   - localhost refused, or the rule applied to the command line:
//     TestLocalhostAndACommandLineTargetNeedNoFlag.

// wantSingleLabelReason is the reason a one-word targets file line is refused,
// written out so that the test pins the words a user reads.
const wantSingleLabelReason = "a single word, accepted as a host name only with --allow-single-label"

// TestAOneWordTargetsLineIsRefusedBeforeAnyLookup is the reproduction: a stray
// token and a one-word name with a port, after a valid first line.
func TestAOneWordTargetsLineIsRefusedBeforeAnyLookup(t *testing.T) {
	recorder := installLookupRecorder(t, nil)
	n := newNonce(t)
	token := fakeMarker("W", n)
	path := writeTargetsFile(t, []string{"valid-" + n + ".example", token, "intranet:8443"})

	run := runCLI(t, nil, path, "json", "")
	if run.err == nil {
		t.Fatal("a targets file with one-word lines was accepted")
	}
	var gate *policyGateError
	if errors.As(run.err, &gate) {
		t.Error("the refusal is classified as a policy failure, which exits 2 rather than 1")
	}
	if calls := recorder.calls(); len(calls) != 0 {
		t.Errorf("the run made %d lookups; a one-word line must be refused before the first "+
			"one, the valid first line included", len(calls))
	}

	message := strings.ReplaceAll(run.err.Error(), path, "<targets file>")
	for _, line := range []int{2, 3} {
		if want := fmt.Sprintf("line %d: %s", line, wantSingleLabelReason); !strings.Contains(message, want) {
			t.Errorf("the error does not give %q: %q", want, message)
		}
	}
	if strings.Contains(message, "line 1:") {
		t.Errorf("the error lists line 1, which is not refused: %q", message)
	}
	for name, text := range map[string]string{"stdout": run.stdout, "stderr": run.stderr, "error": message} {
		if strings.Contains(text, "FA"+"KE") || fragmentsFound(text, token) != 0 {
			t.Errorf("%s carries the one-word line: %q", name, text)
		}
	}
}

// TestAOneWordTargetsLineIsLookedUpWithAllowSingleLabel is the same kind of line
// with the flag: it is a target, so it is looked up.
func TestAOneWordTargetsLineIsLookedUpWithAllowSingleLabel(t *testing.T) {
	previous := allowSingleLabel
	allowSingleLabel = true
	t.Cleanup(func() { allowSingleLabel = previous })

	recorder := installLookupRecorder(t, nil)
	path := writeTargetsFile(t, []string{"intranet", "build-server:8443"})

	run := runCLI(t, nil, path, "json", "")
	if run.err != nil && strings.Contains(run.err.Error(), wantSingleLabelReason) {
		t.Fatalf("--allow-single-label did not stop the refusal: %v", run.err)
	}
	looked := strings.Join(recorder.calls(), " ")
	for _, host := range []string{"intranet", "build-server"} {
		if !strings.Contains(looked, host) {
			t.Errorf("%s was not looked up with --allow-single-label; lookups: %q", host, looked)
		}
	}
}

// TestLocalhostAndACommandLineTargetNeedNoFlag keeps the two one-word targets
// that are not refused: localhost in a targets file, in any case and with a
// trailing dot, and a one-word target given on the command line.
func TestLocalhostAndACommandLineTargetNeedNoFlag(t *testing.T) {
	answer := func(host string) ([]net.IP, error) {
		return nil, errors.New("the test resolver answers no lookups")
	}

	t.Run("localhost in a targets file", func(t *testing.T) {
		recorder := installLookupRecorder(t, answer)
		path := writeTargetsFile(t, []string{"localhost", "LocalHost.:8443"})
		run := runCLI(t, nil, path, "json", "")
		if run.err != nil && strings.Contains(run.err.Error(), wantSingleLabelReason) {
			t.Fatalf("localhost was refused: %v", run.err)
		}
		if calls := recorder.calls(); len(calls) != 2 {
			t.Errorf("want a lookup for each localhost line, got %q", calls)
		}
	})

	t.Run("a one-word target on the command line", func(t *testing.T) {
		recorder := installLookupRecorder(t, answer)
		run := runCLI(t, []string{"intranet"}, "", "json", "")
		if run.err != nil && strings.Contains(run.err.Error(), wantSingleLabelReason) {
			t.Fatalf("a one-word target typed on the command line was refused: %v", run.err)
		}
		if calls := recorder.calls(); len(calls) != 1 || calls[0] != "intranet" {
			t.Errorf("want one lookup of intranet, got %q", calls)
		}
	})
}
