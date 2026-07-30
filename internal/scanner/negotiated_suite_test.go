package scanner

import (
	"net"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Go offers all three TLS 1.3 suites and ignores per-suite configuration, so
// the suite a scan reports for TLS 1.3 is chosen by this scanner's client
// preference and not by the server. Measured against openssl 3.6.1 on
// 2026-07-30: example.com, cloudflare.com and google.com each negotiate
// TLS_AES_256_GCM_SHA384 with a client that offers AES-256 first, while this
// scanner reports TLS_AES_128_GCM_SHA256 for all three. An unlabelled row reads
// as the server's preference, which is a claim the scan cannot support.

// TestTheNegotiatedSuiteIsMarkedAsSuch pins the marker and the disclosure.
func TestTheNegotiatedSuiteIsMarkedAsSuch(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)
	result := scanLocal(t, localScanConfig(), host, port)

	if len(result.CipherSuites) == 0 {
		t.Fatal("no cipher suites reported, so the marker cannot be asserted")
	}

	negotiated := 0
	for _, cs := range result.CipherSuites {
		if cs.Negotiated {
			negotiated++
		}
	}
	if negotiated == 0 {
		t.Fatalf("no suite is marked as the one this scan negotiated, so the cipher list "+
			"reads as the server's own preference. Suites: %+v", result.CipherSuites)
	}
	if negotiated > 1 {
		t.Errorf("%d suites are marked as negotiated, but one connection negotiates one suite",
			negotiated)
	}

	found := false
	for _, w := range result.ScanWarnings {
		if strings.Contains(w, "client preference") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no scan warning says whose preference the negotiated suite reflects; "+
			"warnings were %q", result.ScanWarnings)
	}
}

// TestEnumeratedSuitesAreNotMarkedAsNegotiated is the other half. A marker on
// every row carries no information, and would claim the scan negotiated suites
// it only found the server willing to accept.
func TestEnumeratedSuitesAreNotMarkedAsNegotiated(t *testing.T) {
	merged := mergeCipherSuites(
		[]types.CipherSuite{{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Bits: 128, Negotiated: true}},
		[]types.CipherSuite{
			{ID: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Bits: 256},
			{ID: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Bits: 128},
		},
	)

	for _, cs := range merged {
		switch cs.Name {
		case "TLS_AES_128_GCM_SHA256":
			if !cs.Negotiated {
				t.Error("the negotiated suite lost its marker when merged with the " +
					"enumerated ones")
			}
		default:
			if cs.Negotiated {
				t.Errorf("%s is marked as negotiated, but it was only enumerated as accepted",
					cs.Name)
			}
		}
	}
}
