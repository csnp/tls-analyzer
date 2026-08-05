package scanner

import (
	"fmt"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// checkVulnerabilities analyzes the scan result for known vulnerabilities.
func (s *Scanner) checkVulnerabilities(result *types.ScanResult) []types.Vulnerability {
	var vulns []types.Vulnerability

	// Check for deprecated protocols
	for _, proto := range result.Protocols {
		if proto.Supported {
			switch proto.Version {
			case "TLS 1.0":
				vulns = append(vulns, types.Vulnerability{
					ID:          "TLS10_ENABLED",
					Name:        "TLS 1.0 Enabled",
					Severity:    types.SeverityHigh,
					Description: "TLS 1.0 is deprecated and has known vulnerabilities including BEAST and POODLE.",
					CVE:         "CVE-2011-3389",
					Remediation: "Disable TLS 1.0 and enable TLS 1.2 or TLS 1.3.",
					References:  []string{"https://datatracker.ietf.org/doc/rfc8996/"},
				})
			case "TLS 1.1":
				vulns = append(vulns, types.Vulnerability{
					ID:          "TLS11_ENABLED",
					Name:        "TLS 1.1 Enabled",
					Severity:    types.SeverityMedium,
					Description: "TLS 1.1 is deprecated. While more secure than TLS 1.0, it lacks modern cipher suites.",
					Remediation: "Disable TLS 1.1 and enable TLS 1.2 or TLS 1.3.",
					References:  []string{"https://datatracker.ietf.org/doc/rfc8996/"},
				})
			case "SSL 3.0":
				vulns = append(vulns, types.Vulnerability{
					ID:          "SSL3_ENABLED",
					Name:        "SSL 3.0 Enabled",
					Severity:    types.SeverityCritical,
					Description: "SSL 3.0 is severely deprecated and vulnerable to POODLE attack.",
					CVE:         "CVE-2014-3566",
					Remediation: "Disable SSL 3.0 immediately.",
					References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-3566"},
				})
			}
		}
	}

	// Check TLS 1.3 support
	tls13Supported := false
	for _, proto := range result.Protocols {
		if proto.Version == "TLS 1.3" && proto.Supported {
			tls13Supported = true
			break
		}
	}
	if !tls13Supported {
		vulns = append(vulns, types.Vulnerability{
			ID:          "NO_TLS13",
			Name:        "TLS 1.3 Not Supported",
			Severity:    types.SeverityMedium,
			Description: "TLS 1.3 provides improved security and performance. Not supporting it limits modern security features.",
			Remediation: "Enable TLS 1.3 support on the server.",
			References:  []string{"https://datatracker.ietf.org/doc/rfc8446/"},
		})
	}

	// Check cipher suites
	for _, cs := range result.CipherSuites {
		if cs.Deprecated {
			vulns = append(vulns, types.Vulnerability{
				ID:          "DEPRECATED_CIPHER_" + cs.Name,
				Name:        "Deprecated Cipher Suite: " + cs.Name,
				Severity:    types.SeverityHigh,
				Description: cs.DeprecatedReason,
				Remediation: "Remove " + cs.Name + " from the cipher suite configuration.",
			})
		}

		// Check for non-forward-secrecy ciphers
		if !cs.ForwardSecrecy && cs.KeyExchange == "RSA" {
			vulns = append(vulns, types.Vulnerability{
				ID:          "NO_PFS_" + cs.Name,
				Name:        "No Forward Secrecy: " + cs.Name,
				Severity:    types.SeverityMedium,
				Description: "Cipher suite uses RSA key exchange without forward secrecy. If the private key is compromised, all past sessions can be decrypted.",
				Remediation: "Prefer ECDHE or DHE key exchange for forward secrecy.",
			})
		}

		// Check for weak key sizes
		if cs.Bits > 0 && cs.Bits < 128 {
			vulns = append(vulns, types.Vulnerability{
				ID:          "WEAK_CIPHER_" + cs.Name,
				Name:        "Weak Cipher Strength: " + cs.Name,
				Severity:    types.SeverityHigh,
				Description: "Cipher suite uses less than 128-bit encryption, which is considered weak.",
				Remediation: "Use cipher suites with at least 128-bit encryption (256-bit preferred).",
			})
		}
	}

	// Check certificate
	if result.Certificate != nil {
		cert := result.Certificate

		// Expired certificate
		if cert.Expired {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_EXPIRED",
				Name:        "Certificate Expired",
				Severity:    types.SeverityCritical,
				Description: "The server certificate has expired. Browsers will show security warnings.",
				Remediation: "Renew the certificate immediately.",
			})
		}

		// Not yet valid. The chain check declines to run for a certificate
		// outside its validity window on the grounds that the window is reported
		// on its own, so this end of the window has to be reported here or the
		// certificate is scored as though nothing were wrong with it.
		if cert.NotYetValid {
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_NOT_YET_VALID",
				Name:     "Certificate Not Yet Valid",
				Severity: types.SeverityCritical,
				Description: "The server certificate's validity period has not started, so " +
					"clients will refuse it exactly as they refuse an expired one.",
				Remediation: "Check the certificate's notBefore date and the clock on this " +
					"machine, then deploy a certificate that is valid now.",
			})
		}

		// Expiring soon. The guard exists so an EXPIRED certificate is not also
		// reported as expiring soon, and a not-yet-valid one has a positive count
		// and walked straight through it, so a short future window produced two
		// findings for one condition, a double penalty, and a "plan renewal"
		// instruction pointing the wrong way.
		//
		// The guard now asks whether the certificate is expired, which is the
		// question the previous DaysUntilExpiry > 0 was standing in for. That
		// stand-in was wrong for the last day of a certificate's life:
		// DaysUntilExpiry truncates, so a certificate with eleven hours left counts
		// 0, cleared neither the > 0 test nor the expiry test, and produced no
		// finding at all in the window where renewal is most urgent.
		if !cert.NotYetValid && !cert.Expired && cert.DaysUntilExpiry < 30 {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_EXPIRING",
				Name:        "Certificate Expiring Soon",
				Severity:    types.SeverityMedium,
				Description: "The certificate will expire in less than 30 days.",
				Remediation: "Plan certificate renewal before expiration.",
			})
		}

		// Certificate presented for a different name
		if cert.NameMatch == types.CheckFailed {
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_NAME_MISMATCH",
				Name:     "Certificate Name Mismatch",
				Severity: types.SeverityHigh,
				Description: fmt.Sprintf(
					"The certificate served for %s is not valid for that name (%s). A client "+
						"that verifies the connection refuses it, so this name cannot be reached "+
						"over TLS by a normal browser or API client.",
					cert.RequestedName, cert.NameMismatchReason),
				Remediation: fmt.Sprintf(
					"Install a certificate whose subject alternative names include %s, or point "+
						"clients at a name the presented certificate already covers.",
					cert.RequestedName),
			})
		}

		// A chain that does not build to a trusted root produces exactly one
		// finding, and the same one whatever shape the certificate has.
		//
		// These used to be two independent conditions whose exclusions composed:
		// the untrusted-chain finding stepped aside for a self-signed certificate
		// on the grounds that the self-signed finding was the more specific
		// diagnosis, and the self-signed finding stepped aside for a CA. A
		// self-signed CA leaf satisfies both, so neither fired, and `openssl req
		// -x509` emits CA:TRUE by default, which makes that the common shape
		// rather than an exotic one. Measured on the production path against a
		// local listener: self-signed CA:TRUE scored C 66 with no findings,
		// self-signed CA:FALSE scored C 61 with one, and an untrusted CA-issued
		// certificate scored D 51. The server chose its own row and the worst
		// posture scored best.
		//
		// The severity no longer depends on IsSelfSigned, which matters because
		// IsSelfSigned is a subject-equals-issuer STRING comparison and the server
		// picks both names. It selects the wording of the diagnosis and nothing
		// else, so a certificate cannot lower its own penalty by choosing how it
		// describes itself. What decides the finding is the verification result,
		// which is the one thing in this decision the server does not control.
		//
		// A client that verifies refuses all three of these the same way, so they
		// carry the same severity. The self-signed case is not a milder condition
		// than an untrusted chain; it is the same condition with a shorter chain.
		switch {
		case cert.ChainTrust == types.CheckFailed && cert.IsSelfSigned:
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_SELF_SIGNED",
				Name:     "Self-Signed Certificate",
				Severity: types.SeverityHigh,
				Description: fmt.Sprintf(
					"The certificate signed itself, so the chain does not build to a root in "+
						"this host's trust store (%s). Browsers and API clients refuse it by "+
						"default, exactly as they refuse a chain from an untrusted CA.",
					cert.ChainTrustReason),
				Remediation: "Use a certificate from a Certificate Authority the intended " +
					"clients trust. If this host is deliberately served by an internal CA, " +
					"issue the certificate from that CA rather than self-signing it, and " +
					"install the CA in the trust store of every machine that has to reach it.",
			})

		case cert.ChainTrust == types.CheckFailed:
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_CHAIN_UNTRUSTED",
				Name:     "Certificate Chain Not Trusted",
				Severity: types.SeverityHigh,
				Description: fmt.Sprintf(
					"The presented certificate chain does not build to a root in this host's "+
						"trust store (%s). A client that verifies the connection refuses it.",
					cert.ChainTrustReason),
				Remediation: "Serve the full chain including every intermediate, and use a " +
					"certificate from a CA the intended clients trust. If this host is served " +
					"by an internal CA, that CA has to be installed in the trust store of the " +
					"machine running the scan for this check to pass.",
			})

		case cert.ChainTrust == types.CheckPassed && cert.IsSelfSigned:
			// The chain verified and the certificate still signed itself, which
			// means this machine's trust store carries it. That is a real
			// configuration and not a failure here, but it does not travel: a
			// client anywhere else refuses the same certificate. Reported at a
			// lower severity because nothing was measured to be broken from where
			// the scan ran.
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_SELF_SIGNED",
				Name:     "Self-Signed Certificate",
				Severity: types.SeverityMedium,
				Description: "The certificate signed itself and verified only because this " +
					"machine's trust store already carries it. Any client that does not have " +
					"it installed refuses the connection.",
				Remediation: "Use a certificate from a Certificate Authority the intended " +
					"clients trust, rather than relying on the certificate being installed " +
					"on each machine.",
			})

		case cert.IsSelfSigned:
			// The chain check did not run, which this scanner does when the
			// certificate is outside its own validity window. So this finding must
			// not describe a verification result: there isn't one.
			//
			// The first version of this switch had no case for CheckNotPerformed
			// and fell into the one above, which told the reader the certificate
			// "verified only because this machine's trust store already carries
			// it" about a certificate that was never verified and is in nobody's
			// trust store. A false measurement claim, in a release whose subject
			// is refusing to describe what was not measured.
			//
			// The SECOND version said "see the line above for why", which is a
			// claim about the report's own layout, and it was false on four of the
			// five renderers: SARIF and HTML carry no chain-trust line at all, and
			// in the text report the line above is another finding's remediation.
			// A finding must carry its own reason, the way the failed-chain arm
			// does, so the reason is interpolated here and no positional reference
			// is made. Two rounds of review on one paragraph is the argument for
			// saying less, not more.
			//
			// Reachable and not exotic: an expired self-signed certificate on the
			// pure-Go verifier, which is what every Linux host runs.
			reason := cert.ChainTrustReason
			if reason == "" {
				reason = "the chain check did not run"
			}
			vulns = append(vulns, types.Vulnerability{
				ID:       "CERT_SELF_SIGNED",
				Name:     "Self-Signed Certificate",
				Severity: types.SeverityMedium,
				Description: fmt.Sprintf(
					"The certificate signed itself. Whether its chain builds to a trusted "+
						"root was not established (%s), so this scan says nothing either way "+
						"about it. A self-signed certificate is refused by default by any "+
						"client that does not already have it installed.", reason),
				Remediation: "Resolve the condition that stopped the chain from being " +
					"checked, then use a certificate from a Certificate Authority the " +
					"intended clients trust.",
			})
		}

		// Weak signature algorithm
		if containsAny(cert.SignatureAlgorithm, "SHA1", "MD5", "MD2") {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_WEAK_SIG",
				Name:        "Weak Certificate Signature",
				Severity:    types.SeverityHigh,
				Description: "Certificate uses a weak signature algorithm: " + cert.SignatureAlgorithm,
				Remediation: "Reissue the certificate with SHA-256 or stronger signature.",
				References:  []string{"https://shattered.io/"},
			})
		}

		// Weak RSA key
		if cert.PublicKeyAlgorithm == "RSA" && cert.PublicKeyBits < 2048 {
			vulns = append(vulns, types.Vulnerability{
				ID:          "CERT_WEAK_KEY",
				Name:        "Weak RSA Key Size",
				Severity:    types.SeverityHigh,
				Description: "RSA key is less than 2048 bits, which is considered weak.",
				Remediation: "Reissue the certificate with at least 2048-bit RSA key (4096-bit recommended).",
			})
		}
	}

	return vulns
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
