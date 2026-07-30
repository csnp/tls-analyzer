package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
	"gopkg.in/yaml.v3"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

// TestLoadPolicyRefusesAPolicyThatCannotFail is the reproduction of "an empty
// or unparseable --policy-file reports COMPLIANT 100/100".
//
// Every case here previously loaded, evaluated against nothing, and produced a
// compliant verdict with exit 0, on hosts that the built-in strict policy fails
// with dozens of HIGH violations at the same moment.
func TestLoadPolicyRefusesAPolicyThatCannotFail(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantWord string
	}{
		{
			name:     "empty file",
			body:     "",
			wantWord: "no YAML document",
		},
		{
			name:     "comments only",
			body:     "# a policy I meant to write\n",
			wantWord: "no YAML document",
		},
		{
			name:     "named but ruleless",
			body:     "name: mine\nversion: \"1.0\"\n",
			wantWord: "no rules",
		},
		{
			name: "rules present but every key misspelled",
			body: "name: typo\nrules:\n  protocol:\n    minimumVersion: \"TLS 1.3\"\n",
			// A misspelled key is refused outright, so this never reaches the
			// ruleless check. Either way it must not load.
			wantWord: "minimumVersion",
		},
		{
			name:     "snake_case spelling of a real key",
			body:     "name: snake\nrules:\n  cipher:\n    min_key_size: 256\n",
			wantWord: "min_key_size",
		},
		{
			name:     "flat shape with no rules block",
			body:     "name: flat\nminVersion: \"TLS 1.3\"\nminKeySize: 256\n",
			wantWord: "minVersion",
		},
		{
			name:     "unnamed policy",
			body:     "rules:\n  cipher:\n    minKeySize: 256\n",
			wantWord: "no 'name'",
		},
		{
			name:     "extends a policy that does not exist",
			body:     "name: mine\nextends: modren\nrules:\n  cipher:\n    minKeySize: 256\n",
			wantWord: "not a built-in policy",
		},
	}

	e := NewPolicyEvaluator()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := e.LoadPolicy(writePolicy(t, tc.body))
			if err == nil {
				t.Fatalf("policy loaded with no error and would be evaluated as %+v. "+
					"A compliance gate that passes on an input it did not understand is "+
					"the worst direction available to it.", policy)
			}
			if !strings.Contains(err.Error(), tc.wantWord) {
				t.Fatalf("error = %q, want it to name %q so the user can fix the file",
					err.Error(), tc.wantWord)
			}
		})
	}
}

// TestLoadPolicyAcceptsAWellFormedPolicy is the acceptance control. A loader
// that refuses everything satisfies every case above on its own, and would make
// the feature unusable rather than safe.
func TestLoadPolicyAcceptsAWellFormedPolicy(t *testing.T) {
	body := `name: house-rules
version: "1.0"
description: what we require
rules:
  protocol:
    minVersion: "TLS 1.2"
    bannedVersions: ["TLS 1.0", "TLS 1.1"]
  cipher:
    minKeySize: 256
    requireForwardSecrecy: true
  certificate:
    minValidityDays: 30
    minRsaKeySize: 2048
  quantum:
    requireHybridKeyExchange: true
    minQuantumScore: 50
`
	policy, err := NewPolicyEvaluator().LoadPolicy(writePolicy(t, body))
	if err != nil {
		t.Fatalf("a policy written to the documented schema was refused: %v", err)
	}
	if policy.Name != "house-rules" {
		t.Fatalf("Name = %q, want house-rules", policy.Name)
	}
	if policy.Rules.Cipher.MinKeySize != 256 {
		t.Fatalf("cipher.minKeySize = %d, want 256", policy.Rules.Cipher.MinKeySize)
	}
	if policy.Rules.Quantum.MinQuantumScore != 50 {
		t.Fatalf("quantum.minQuantumScore = %d, want 50", policy.Rules.Quantum.MinQuantumScore)
	}
}

// TestExtendsKeepsEveryKeyTheFileSets covers the rule fields the old merge
// dropped, which was every field it had not been written to copy.
//
// The old merge copied eight fields by hand. A file extending "modern" to ban
// AES, require a larger RSA key or forbid a signature algorithm was accepted,
// reported under its own name, and evaluated against the base policy's looser
// rules, with nothing saying the override had been discarded.
func TestExtendsKeepsEveryKeyTheFileSets(t *testing.T) {
	body := `name: tightened
version: "2.0"
extends: modern
rules:
  protocol:
    maxVersion: "TLS 1.3"
  cipher:
    bannedAlgorithms: ["AES"]
    bannedCipherSuites: ["TLS_RSA_WITH_AES_128_GCM_SHA256"]
    allowedCipherSuites: ["TLS_AES_256_GCM_SHA384"]
  certificate:
    minRsaKeySize: 8192
    minEccKeySize: 521
    maxValidityDays: 90
    requiredSignatureAlgorithms: ["ECDSA-SHA384"]
    bannedSignatureAlgorithms: ["SHA256"]
    requireCt: true
    allowSelfSigned: true
  quantum:
    requirePqcCertificates: true
    cnsa2TargetYear: 2030
    requiredKeyExchangeAlgorithms: ["ML-KEM-1024"]
weights:
  protocol: 40
  cipher: 30
  certificate: 20
  quantum: 10
`
	policy, err := NewPolicyEvaluator().LoadPolicy(writePolicy(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Every key the file set has to be the file's value.
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"protocol.maxVersion", policy.Rules.Protocol.MaxVersion, "TLS 1.3"},
		{"cipher.bannedAlgorithms", strings.Join(policy.Rules.Cipher.BannedAlgorithms, ","), "AES"},
		{"cipher.bannedCipherSuites", strings.Join(policy.Rules.Cipher.BannedCipherSuites, ","), "TLS_RSA_WITH_AES_128_GCM_SHA256"},
		{"cipher.allowedCipherSuites", strings.Join(policy.Rules.Cipher.AllowedCipherSuites, ","), "TLS_AES_256_GCM_SHA384"},
		{"certificate.minRsaKeySize", policy.Rules.Certificate.MinRSAKeySize, 8192},
		{"certificate.minEccKeySize", policy.Rules.Certificate.MinECCKeySize, 521},
		{"certificate.maxValidityDays", policy.Rules.Certificate.MaxValidityDays, 90},
		{"certificate.requiredSignatureAlgorithms", strings.Join(policy.Rules.Certificate.RequiredSignatureAlgorithms, ","), "ECDSA-SHA384"},
		{"certificate.bannedSignatureAlgorithms", strings.Join(policy.Rules.Certificate.BannedSignatureAlgorithms, ","), "SHA256"},
		{"certificate.requireCt", policy.Rules.Certificate.RequireCT, true},
		{"certificate.allowSelfSigned", policy.Rules.Certificate.AllowSelfSigned, true},
		{"quantum.requirePqcCertificates", policy.Rules.Quantum.RequirePQCCertificates, true},
		{"quantum.cnsa2TargetYear", policy.Rules.Quantum.CNSA2TargetYear, 2030},
		{"quantum.requiredKeyExchangeAlgorithms", strings.Join(policy.Rules.Quantum.RequiredKeyExchangeAlgorithms, ","), "ML-KEM-1024"},
		{"name", policy.Name, "tightened"},
		{"version", policy.Version, "2.0"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v: the file set it and the overlay dropped it",
				c.field, c.got, c.want)
		}
	}

	if policy.Weights == nil {
		t.Fatal("weights block was dropped entirely")
	}
	if policy.Weights.Protocol != 40 {
		t.Errorf("weights.protocol = %d, want 40", policy.Weights.Protocol)
	}

	// And every key the file did NOT set has to come from the base, or extends
	// would be doing nothing.
	base, _ := NewPolicyEvaluator().GetPolicy("modern")
	if policy.Rules.Protocol.MinVersion != base.Rules.Protocol.MinVersion {
		t.Errorf("protocol.minVersion = %q, want %q inherited from modern",
			policy.Rules.Protocol.MinVersion, base.Rules.Protocol.MinVersion)
	}
	if strings.Join(policy.Rules.Protocol.BannedVersions, ",") !=
		strings.Join(base.Rules.Protocol.BannedVersions, ",") {
		t.Errorf("protocol.bannedVersions = %v, want %v inherited from modern",
			policy.Rules.Protocol.BannedVersions, base.Rules.Protocol.BannedVersions)
	}
	if policy.Rules.Cipher.MinKeySize != base.Rules.Cipher.MinKeySize {
		t.Errorf("cipher.minKeySize = %d, want %d inherited from modern",
			policy.Rules.Cipher.MinKeySize, base.Rules.Cipher.MinKeySize)
	}
}

// TestExtendsDoesNotMutateTheBuiltInPolicy guards the shared map. The built-ins
// live in a package-level map, and an overlay that wrote through to it would
// leave the next scan in a batch evaluated against someone else's rules.
func TestExtendsDoesNotMutateTheBuiltInPolicy(t *testing.T) {
	e := NewPolicyEvaluator()
	before, _ := e.GetPolicy("modern")
	beforeMin := before.Rules.Cipher.MinKeySize

	if _, err := e.LoadPolicy(writePolicy(t,
		"name: mine\nextends: modern\nrules:\n  cipher:\n    minKeySize: 512\n")); err != nil {
		t.Fatalf("load: %v", err)
	}

	after, _ := NewPolicyEvaluator().GetPolicy("modern")
	if after.Rules.Cipher.MinKeySize != beforeMin {
		t.Fatalf("built-in modern cipher.minKeySize changed from %d to %d after an overlay "+
			"extended it", beforeMin, after.Rules.Cipher.MinKeySize)
	}
}

// TestEveryBuiltInPolicyRoundTripsThroughItsOwnRenderedForm is what makes
// print-policy a usable starting point rather than a claim about one.
//
// It round-trips the rendered YAML back through the loader instead of comparing
// the renderer against a copy of the schema, so it cannot agree with a shared
// mistake: if the renderer emits a key the loader refuses, or drops a key the
// loader requires, this fails.
func TestEveryBuiltInPolicyRoundTripsThroughItsOwnRenderedForm(t *testing.T) {
	e := NewPolicyEvaluator()
	names := e.ListPolicies()
	if len(names) == 0 {
		t.Fatal("no built-in policies to round-trip, so this test would pass vacuously")
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			policy, ok := e.GetPolicy(name)
			if !ok {
				t.Fatalf("GetPolicy(%q) reported missing after ListPolicies named it", name)
			}

			rendered, err := yaml.Marshal(policy)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			reloaded, err := e.LoadPolicy(writePolicy(t, string(rendered)))
			if err != nil {
				t.Fatalf("the rendered form of built-in %q is not accepted by --policy-file: %v\n%s",
					name, err, rendered)
			}
			if reloaded.Name != policy.Name {
				t.Fatalf("round-tripped name = %q, want %q", reloaded.Name, policy.Name)
			}
			if !equalRules(reloaded.Rules, policy.Rules) {
				t.Fatalf("round-tripped rules differ from the built-in:\ngot  %+v\nwant %+v",
					reloaded.Rules, policy.Rules)
			}
		})
	}
}

func equalRules(a, b types.PolicyRules) bool {
	ay, err1 := yaml.Marshal(a)
	by, err2 := yaml.Marshal(b)
	return err1 == nil && err2 == nil && string(ay) == string(by)
}

// TestPolicyParseErrorsNameTheYAMLPathNotTheGoType keeps the tool's own
// diagnostics from being where the schema leaks. The fresh-user pass found the
// real shape of a policy only by provoking errors that printed Go type names.
func TestPolicyParseErrorsNameTheYAMLPathNotTheGoType(t *testing.T) {
	_, err := NewPolicyEvaluator().LoadPolicy(writePolicy(t,
		"name: mine\nrules:\n  protocol:\n    minimumVersion: \"TLS 1.3\"\n"))
	if err == nil {
		t.Fatal("a misspelled key loaded without error")
	}
	if strings.Contains(err.Error(), "types.") {
		t.Fatalf("error names a Go type: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "rules.protocol") {
		t.Fatalf("error = %q, want it to name the YAML path rules.protocol", err.Error())
	}
}
