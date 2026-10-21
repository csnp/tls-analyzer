package scanner

import (
	"context"
	"crypto/tls"
	"slices"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// probeKeyExchangeGroups skipped a group only when the Go toolchain did not
// name it. Go 1.26 names SecP256r1MLKEM768 and SecP384r1MLKEM1024 and keeps them
// disabled for a module that declares go 1.25 (GODEBUG tlssecpmlkem=0), so a
// binary built with Go 1.26 probed both, every probe failed, and a server
// offering SecP384r1MLKEM1024 next to X25519 was reported as classical only,
// quantum score 0, with no note that the group was never offered. A Go 1.25
// build skips both and says they were not probed.

// TestAGroupThisBuildCannotNegotiateIsReportedNotProbed serves every group the
// scan probes and checks each against what crypto/tls does in this build: a
// group this build negotiates must be found, and a group it cannot negotiate
// must be listed as not probed rather than reported absent.
//
// On a Go 1.26 or later toolchain this exercises the P-curve hybrids, which the
// earlier code probed and reported absent. On Go 1.25 the toolchain does not
// name them, so both versions of the code skip them and the test passes either
// way. In the FIPS 140-3 child process that TestAFIPSBuildListsX25519AsNotProbed
// starts, it exercises X25519, which that mode leaves out of the ClientHello and
// which the scan probed and reported absent when it read only the hybrid groups.
func TestAGroupThisBuildCannotNegotiateIsReportedNotProbed(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)

	host, port := startTLSServerWithConfig(t, &tls.Config{
		Certificates:     []tls.Certificate{cert.serving},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: slices.Clone(keyExchangeCandidates),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	supported, skipped := New(localScanConfig()).probeKeyExchangeGroups(ctx, host, port,
		&reachedAddresses{})

	for _, id := range keyExchangeCandidates {
		name := tlsGroups[id].name
		found := slices.ContainsFunc(supported, func(ke types.KeyExchange) bool { return ke.Name == name })
		notProbed := slices.Contains(skipped, name)

		if negotiatesOnly(t, cert.serving, id) {
			if !found || notProbed {
				t.Errorf("%s: this build negotiates it and the server offers it, but it is "+
					"found=%v and listed as not probed=%v", name, found, notProbed)
			}
			continue
		}
		t.Logf("%s: this build cannot negotiate it", name)
		if !notProbed {
			t.Errorf("%s: this build cannot negotiate it, so the probe could only fail, but "+
				"it is not listed as not probed (found=%v, not probed: %v)", name, found, skipped)
		}
		if found {
			t.Errorf("%s: reported as supported although this build cannot negotiate it", name)
		}
	}
}
