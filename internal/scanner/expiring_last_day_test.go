package scanner

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file names nothing that did not already exist, so it compiles against the
// pre-fix sources and fails there on behaviour.
//
// The defect: the expiring-soon finding was guarded on DaysUntilExpiry > 0,
// standing in for "the certificate has not expired". DaysUntilExpiry is computed
// by truncating hours to whole days, so a certificate with anything under 24
// hours left counts 0. It cleared neither that guard nor the expiry finding, so
// the last day of a certificate's life produced no finding at all, which is the
// window where renewal is most urgent.

func certificateWithHoursLeft(daysUntilExpiry int, expired bool) *types.ScanResult {
	return &types.ScanResult{
		Host: "example.com",
		Port: 443,
		Certificate: &types.Certificate{
			Subject:            "CN=example.com",
			PublicKeyAlgorithm: "ECDSA",
			PublicKeyBits:      256,
			SignatureAlgorithm: "ECDSA-SHA256",
			DaysUntilExpiry:    daysUntilExpiry,
			Expired:            expired,
			NameMatch:          types.CheckPassed,
			ChainTrust:         types.CheckPassed,
		},
		Protocols: []types.Protocol{{Version: "TLS 1.3", Supported: true}},
		CipherSuites: []types.CipherSuite{
			{Name: "TLS_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true, Protocol: "TLS 1.3"},
		},
	}
}

// TestACertificateInItsFinalHoursIsReportedExpiringSoon is the reproduction.
// Eleven hours left truncates to 0 days, which is neither expired nor greater
// than zero.
func TestACertificateInItsFinalHoursIsReportedExpiringSoon(t *testing.T) {
	s := &Scanner{config: &Config{CheckVulns: true}}
	result := certificateWithHoursLeft(0, false)
	result.Vulnerabilities = s.checkVulnerabilities(result)

	if findVulnerability(result, "CERT_EXPIRING") == nil {
		t.Errorf("a certificate with under a day left raised no CERT_EXPIRING finding; "+
			"got %d findings. The last day before expiry is the window where the warning "+
			"matters most", len(result.Vulnerabilities))
	}
}

// TestAnExpiredCertificateIsNotAlsoReportedExpiringSoon is the control the
// original guard existed to hold. Removing the guard rather than correcting it
// would satisfy the test above and report one condition twice.
func TestAnExpiredCertificateIsNotAlsoReportedExpiringSoon(t *testing.T) {
	s := &Scanner{config: &Config{CheckVulns: true}}
	result := certificateWithHoursLeft(-5, true)
	result.Vulnerabilities = s.checkVulnerabilities(result)

	if findVulnerability(result, "CERT_EXPIRED") == nil {
		t.Fatal("an expired certificate raised no CERT_EXPIRED finding, so this control " +
			"is not measuring what it says")
	}
	if findVulnerability(result, "CERT_EXPIRING") != nil {
		t.Errorf("an expired certificate was also reported as expiring soon, which states " +
			"one condition twice and deducts for it twice")
	}
}

// TestACertificateWithPlentyOfTimeIsNotReportedExpiringSoon is the second
// control. A guard that always fired would satisfy both tests above.
func TestACertificateWithPlentyOfTimeIsNotReportedExpiringSoon(t *testing.T) {
	s := &Scanner{config: &Config{CheckVulns: true}}
	result := certificateWithHoursLeft(90, false)
	result.Vulnerabilities = s.checkVulnerabilities(result)

	if findVulnerability(result, "CERT_EXPIRING") != nil {
		t.Errorf("a certificate with 90 days left was reported as expiring soon")
	}
}
