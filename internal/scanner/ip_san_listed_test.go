package scanner

import (
	"net"
	"slices"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The certificate's subject alternative names were filled from its DNS names
// alone, so a certificate valid for a target through an IP address SAN passed
// the name check and listed no SAN at all, in the text report and in JSON
// certificate.subjectAltNames.
//
// The mutation each test is written to catch:
//   - SANs filled from DNSNames only, as before this change: both tests.
//   - the IP addresses put ahead of the DNS names:
//     TestSANsListTheDNSNamesThenTheIPAddresses.

// TestAnIPAddressSANIsListed is the reproduction, reduced to a local server
// whose certificate names 127.0.0.1 in an IP address SAN and has no DNS name.
func TestAnIPAddressSANIsListed(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, cert.serving)
	result := scanLocal(t, localScanConfig(), host, port)

	if result.Certificate.NameMatch != types.CheckPassed {
		t.Fatalf("the name check did not pass for %s through the IP address SAN (%s: %s), so "+
			"this test does not reproduce the report", host, result.Certificate.NameMatch,
			result.Certificate.NameMismatchReason)
	}
	if !slices.Contains(result.Certificate.SANs, "127.0.0.1") {
		t.Errorf("the certificate passed the name check through its IP address SAN, and its "+
			"SANs are %q", result.Certificate.SANs)
	}
}

// TestSANsListTheDNSNamesThenTheIPAddresses reads a certificate that carries
// both kinds, with an IPv4 and an IPv6 address.
func TestSANsListTheDNSNamesThenTheIPAddresses(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"example.test", "www.example.test"},
		[]net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")}, notBefore, notAfter)

	got := parseCertificate(cert.leaf).SANs
	want := []string{"example.test", "www.example.test", "192.0.2.10", "2001:db8::1"}
	if !slices.Equal(got, want) {
		t.Errorf("SANs = %q, want %q", got, want)
	}
}
