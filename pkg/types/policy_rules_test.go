package types

import "testing"

// This file is separate from the analyzer's policy-loading tests because it
// names a method that did not exist before, so it cannot compile against the
// pre-fix sources. The behavioural tests over there compile against the old
// code and fail in it, which is what makes them a proof.

// TestPolicyRulesIsEmptyTracksTheWholeStruct pins the property that keeps the
// ruleless check from rotting: it is derived from the zero value, so a rule
// field added later is covered without anyone updating a list.
func TestPolicyRulesIsEmptyTracksTheWholeStruct(t *testing.T) {
	if !(PolicyRules{}).IsEmpty() {
		t.Fatal("a zero-valued rule set is not reported as empty")
	}

	// Every top-level rule group, set on its own, has to make the set non-empty.
	groups := []PolicyRules{
		{Protocol: ProtocolRules{MinVersion: "TLS 1.2"}},
		{Cipher: CipherRules{MinKeySize: 128}},
		{Certificate: CertificateRules{MinRSAKeySize: 2048}},
		{Quantum: QuantumRules{MinQuantumScore: 1}},
		{Cipher: CipherRules{RequireForwardSecrecy: true}},
		{Certificate: CertificateRules{AllowSelfSigned: true}},
		{Cipher: CipherRules{BannedAlgorithms: []string{"RC4"}}},
	}
	for i, g := range groups {
		if g.IsEmpty() {
			t.Errorf("case %d: %+v reported as empty, so a policy setting only this rule "+
				"would be refused as ruleless", i, g)
		}
	}
}
