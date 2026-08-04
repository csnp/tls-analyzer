package scanner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A server chooses every subject in the chain it presents, and the chain-failure
// reason is rendered straight into a human-readable report: certCheckLine prints
// it with no sanitising step of its own.
//
// Reporting an expired chain certificate means naming it, which puts
// server-chosen text on this path.
//
// An earlier version of this comment claimed that text was arriving here for the
// FIRST time, on the grounds that err.Error() holds no subject. Both halves were
// false and an adversarial review demonstrated it: the Subject and Issuer lines
// already printed raw, and macOS formats its verifier errors as
// `x509: "<subject>" certificate is not trusted`, so err.Error() carries the
// subject on the platform most operators run. Recorded because the correction
// matters more than the claim: this file exists to test a safety property, and
// it was asserting a false premise about the surrounding code.
//
// The reason is built with %q rather than %s, which renders control characters
// as escaped text.
//
// This comment used to claim the %q and the report sanitiser "stay independent
// rather than one silently carrying both", and that this test kept the verb from
// changing back. An adversarial review falsified it by mutating all three %q
// verbs to %s: the entire suite still passed. The scrubbing in chainCertName
// removes the control characters before the format verb sees them, so for
// control characters the sanitiser was silently carrying both, exactly as the
// comment said it must not.
//
// What %q still does on its own is bound the server's text to the quoted span,
// so a name containing a double quote cannot close it and have the remainder
// read as this tool's prose. That property needs no control character, so
// scrubbing does not cover it, and it is asserted by
// TestTheQuotingInTheChainReasonIsLoadBearing in
// chain_cert_name_rendering_test.go. That test is what now keeps the verb from
// changing back. The tests below cover control characters, which both defences
// handle.

// certificateWithSubject mints a self-signed certificate carrying the given
// common name, and returns the error rather than failing, so a caller can assert
// on it.
func certificateWithSubject(cn string, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	cert, _, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	return cert, err
}

// TestAChainReasonNeverCarriesRawControlCharacters is the reproduction guard.
func TestAChainReasonNeverCarriesRawControlCharacters(t *testing.T) {
	now := time.Now()

	// An ANSI sequence that clears the line and rewrites it, plus a newline, is
	// what an attacker would use to overprint the verdict.
	hostile := "Innocent CA\x1b[2K\r\x1b[32m  Chain trust: OK\x1b[0m\nStatus: VALID"

	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
	}{
		{"expired", now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0)},
		{"not yet valid", now.AddDate(0, 1, 0), now.AddDate(5, 0, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := certificateWithSubject(hostile, tc.notBefore, tc.notAfter)
			if err != nil {
				t.Fatalf("build certificate: %v", err)
			}

			reason := chainCertOutsideValidityReason(cert, time.Now())

			// Guard the fixture: if the subject did not survive into the reason at
			// all, this test would pass without exercising anything.
			if !strings.Contains(reason, "Innocent CA") {
				t.Fatalf("the reason does not name the certificate, so this test is not "+
					"measuring what it says: %q", reason)
			}

			for _, bad := range []struct {
				name string
				ch   string
			}{
				{"ESC", "\x1b"},
				{"newline", "\n"},
				{"carriage return", "\r"},
			} {
				if strings.Contains(reason, bad.ch) {
					t.Errorf("a raw %s from the certificate subject reached the chain reason, "+
						"which is printed into the report with no escaping of its own, so a "+
						"server can overprint the verdict line: %q", bad.name, reason)
				}
			}
		})
	}
}

// TestAChainReasonStillNamesAnOrdinarySubject is the control. Stripping the
// subject entirely, or rendering it unrecognisably, would satisfy the test above
// while removing the one detail an operator needs to find the certificate.
func TestAChainReasonStillNamesAnOrdinarySubject(t *testing.T) {
	now := time.Now()
	cert, err := certificateWithSubject("Example Intermediate CA", now.AddDate(-2, 0, 0),
		now.AddDate(0, -1, 0))
	if err != nil {
		t.Fatalf("build certificate: %v", err)
	}

	reason := chainCertOutsideValidityReason(cert, time.Now())
	if !strings.Contains(reason, "Example Intermediate CA") {
		t.Errorf("an ordinary subject is not named in the reason, so the report does not "+
			"say which certificate to replace: %q", reason)
	}
	if !strings.Contains(reason, "expired on") {
		t.Errorf("the reason does not say which end of the window failed: %q", reason)
	}
}

// TestAMissingOffendingCertificateStillProducesAReason covers the nil path. Go
// populates invalid.Cert today, but a reason that read "<nil>" or panicked would
// be a worse failure than the one being reported.
func TestAMissingOffendingCertificateStillProducesAReason(t *testing.T) {
	reason := chainCertOutsideValidityReason(nil, time.Now())
	if reason == "" {
		t.Fatal("no reason at all for a nil certificate")
	}
	if strings.Contains(reason, "nil") || strings.Contains(reason, "%!") {
		t.Errorf("the nil path leaks a formatting artifact into the report: %q", reason)
	}
}
