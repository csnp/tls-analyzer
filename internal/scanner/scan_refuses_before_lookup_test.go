package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

// This file names only Scan and LookupIP, so it builds against the scanner as
// it was before targets were checked and fails there at run time, on a lookup
// that happened or a value that was printed. The rule itself is pinned in
// target_check_test.go.

// TestScanRefusesATargetBeforeLookingItUp holds the library to the same rule as
// the command: Scan is the one path every target takes to the resolver, so a
// caller that never went through the command's check is still covered.
func TestScanRefusesATargetBeforeLookingItUp(t *testing.T) {
	var mu sync.Mutex
	lookups := 0
	previous := LookupIP
	LookupIP = func(string) ([]net.IP, error) {
		mu.Lock()
		lookups++
		mu.Unlock()
		return nil, errors.New("the test resolver answers no lookups")
	}
	defer func() { LookupIP = previous }()

	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	n := hex.EncodeToString(b)
	marker := func(label string) string { return "FA" + "KE" + label + n }

	for i, target := range []string{
		"DB_PASSWORD=" + marker("A"),
		"smtp_password: " + marker("C"),
		marker("E") + ":" + marker("F"),
		"zebra quokka " + marker("D") + " yak",
		"https://" + marker("U") + ":" + marker("P") + "@" + marker("H") + ".test/",
		"[" + marker("V") + "]:443",
	} {
		_, err := New(DefaultConfig()).Scan(context.Background(), target)
		if err == nil {
			t.Errorf("case %d: Scan accepted a target that is not a host name, IP address or host:port", i)
			continue
		}
		if strings.Contains(err.Error(), "FA"+"KE") {
			t.Errorf("case %d: the error carries the target's FAKE marker", i)
		}
	}

	if lookups != 0 {
		t.Errorf("Scan made %d lookups for targets it should have refused first", lookups)
	}
}
