package reporter

import (
	"strings"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// CycloneDX 1.6 defines classicalSecurityLevel as the classical security
// strength in bits, and nistQuantumSecurityLevel as the NIST post-quantum
// security category. The functions below return 0 when no NIST document gives
// a value for the input, and both fields are omitempty, so a value without a
// source is left out of the document rather than estimated. A key size is never
// returned as a security strength: before this, an RSA-2048 certificate claimed
// 2048 bits of security instead of 112.

// strengthRow is one row of a comparable-strengths table: keys of at least
// minBits provide strength bits of security.
type strengthRow struct {
	minBits  int
	strength int
}

// NIST SP 800-57 Part 1 Rev. 5, Section 5.6.1.1, Table 2 (Comparable security
// strengths of symmetric block cipher and asymmetric-key algorithms). Rows run
// from strongest to weakest, so a key between two rows takes the lower one: an
// RSA-4096 key reaches the k = 3072 row but not the k = 7680 row, and provides
// 128 bits. The weakest row is listed as "<= 80"; 80 is its maximum, as every
// entry in the table is an estimated maximum. A key below the weakest row has no
// strength in the table and is left out.
var (
	// IFC column: k, the size of the RSA modulus.
	ifcStrength = []strengthRow{
		{15360, 256}, {7680, 192}, {3072, 128}, {2048, 112}, {1024, 80},
	}
	// ECC column: f, the size of the order of the base point, which for the NIST
	// prime curves is the curve size the scanner reports (P-256 is 256).
	eccStrength = []strengthRow{
		{512, 256}, {384, 192}, {256, 128}, {224, 112}, {160, 80},
	}
)

func strengthFromTable(table []strengthRow, bits int) int {
	for _, row := range table {
		if bits >= row.minBits {
			return row.strength
		}
	}
	return 0
}

// certificateKeyStrength returns the classical security strength of a
// certificate's subject public key, or 0 when no NIST table covers the key.
func certificateKeyStrength(cert *types.Certificate) int {
	switch cert.PublicKeyAlgorithm {
	case "RSA":
		return strengthFromTable(ifcStrength, cert.PublicKeyBits)
	case "ECDSA":
		return strengthFromTable(eccStrength, cert.PublicKeyBits)
	case "Ed25519":
		// SP 800-57 Table 2 gives ranges and names no curve. NIST SP 800-186
		// (February 2023), Section 3.1.2, Table 1 (Approximate Security Strength
		// of the Recommended Curves) names Edwards25519 at 128.
		return 128
	default:
		// DSA needs both L and N from Table 2 and the scanner records neither;
		// a post-quantum key is not in a classical table at all.
		return 0
	}
}

// cipherStrength returns the classical security strength of a cipher suite's
// bulk cipher, or 0 when no source gives one.
func cipherStrength(cs types.CipherSuite) int {
	switch cs.Encryption {
	case "AES", "AES-GCM":
		// SP 800-57 Part 1 Rev. 5, Table 2: AES-128, AES-192 and AES-256 provide
		// 128, 192 and 256 bits.
		switch cs.Bits {
		case 128, 192, 256:
			return cs.Bits
		}
		return 0
	case "3DES":
		// SP 800-57 Part 1 Rev. 5, Table 2: 3TDEA provides 112 bits. Its key is
		// 168 bits, which is what the suite's Bits field carries.
		return 112
	case "ChaCha20-Poly1305":
		// No NIST table lists ChaCha20. RFC 8439 defines it with a 256-bit key
		// only, and 256 is the value this field has always carried for it.
		return 256
	default:
		// RC4 has no published security strength, and an unrecognised cipher
		// has no source at all.
		return 0
	}
}

// nistQuantumCategories maps a post-quantum parameter set to its NIST security
// category. ML-KEM: FIPS 203, Section 8 (Parameter Sets). ML-DSA: FIPS 204,
// Section 4 (Parameter Sets), Table 1, which gives the claimed category; FIPS
// 204 lowers ML-DSA-44 to category 1 when its random bit generator provides
// less than 192 bits, which a TLS scan cannot observe.
var nistQuantumCategories = map[string]int{
	"MLKEM512":  1,
	"MLKEM768":  3,
	"MLKEM1024": 5,
	"MLDSA44":   2,
	"MLDSA65":   3,
	"MLDSA87":   5,
}

// nistQuantumCategory returns the NIST security category of a parameter set
// such as "ML-KEM-768", or 0 when the parameter set is not known.
func nistQuantumCategory(parameterSet string) int {
	key := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToUpper(parameterSet))
	return nistQuantumCategories[key]
}
