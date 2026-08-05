package analyzer

import (
	"strings"
	"testing"
)

// Escaping and bounding are two separate defences against the same surface, and
// 0.4.0 applied only one of them where it mattered.
//
// %q stops a policy file steering the terminal, because Go escapes control
// characters there. It does nothing about volume. Every refusal below quotes
// untrusted text back to the author, and the length of that text is the file's
// to choose, so a 200 KB `name:` in a policy that declares no rules produced
// 200,229 bytes on stderr. That pushes the real verdict out of scrollback as
// effectively as a forged one, and stderr shares the terminal with the report.
//
// The name and description were capped, at the END of LoadPolicy, after
// validatePolicy had already formatted the raw value into five messages. The cap
// now runs before anything formats it, and the sibling rule VALUES are bounded
// where they are echoed.

// hugePayload is 200 KB, the size the original measurement used.
const hugePayloadLen = 200 * 1024

func hugePayload(fill string) string {
	return strings.Repeat(fill, hugePayloadLen/len(fill))
}

// maxRefusalBytes sits between the two behaviours rather than above both.
//
// Measured on this fixture set, with the caps in place and with each of them
// reverted: bounded refusals run 406 to 1,458 bytes, unbounded ones 204,928 to
// 410,057. Any bound in between distinguishes the two; 4,000 leaves room for the
// prose these messages carry (the protocol refusal lists every accepted version)
// without coming near the unbounded size. A bound of "under 200 KB" would have
// passed against no cap at all.
const maxRefusalBytes = 4000

func TestARefusalCannotBeMadeArbitrarilyLongByThePolicyFile(t *testing.T) {
	tests := []struct {
		name string
		body string
		// mustContain proves the fixture reached the refusal under test rather
		// than some earlier one, so a yaml or schema change that moves the branch
		// fails loudly instead of silently measuring nothing.
		mustContain string
	}{
		{
			name:        "a name on a policy that declares no rules",
			body:        "name: " + hugePayload("A") + "\n",
			mustContain: "defines no rules",
		},
		{
			name: "a name on a policy whose only rule can never fail",
			body: "name: " + hugePayload("A") + "\n" +
				"rules:\n  certificate:\n    minValidityDays: 30\n",
			mustContain: "can never fail a policy",
		},
		{
			name: "a name carried into a value refusal",
			body: "name: " + hugePayload("A") + "\n" +
				"rules:\n  protocol:\n    minVersion: \"TLSv1.2\"\n",
			mustContain: "not a protocol version this tool recognises",
		},
		{
			name:        "an extends target that is not a built-in policy",
			body:        "name: mine\nextends: " + hugePayload("A") + "\n",
			mustContain: "is not a built-in policy",
		},
		{
			name: "a protocol version value",
			body: "name: mine\nrules:\n  protocol:\n    minVersion: \"" +
				hugePayload("x") + "\"\n",
			mustContain: "not a protocol version this tool recognises",
		},
		{
			name: "an algorithm name with no letters or digits",
			body: "name: mine\nrules:\n  cipher:\n    bannedAlgorithms: [\"" +
				hugePayload("-") + "\"]\n",
			mustContain: "has no letters or digits",
		},
		// The `extends` cases exist because the first version of this fix was
		// inert on exactly this path. LoadPolicy decodes a SECOND time to overlay
		// the document onto the base policy, and that decode reassigned the whole
		// struct, discarding the bounded name. Every fixture above happens to
		// return before the overlay runs, so six passing cases proved nothing
		// about the path the loader's own refusals tell an author to take.
		{
			name: "a name on a policy that inherits a built-in",
			body: "name: " + hugePayload("A") + "\nextends: modern\n" +
				"rules:\n  protocol:\n    minVersion: \"TLSv1.2\"\n",
			mustContain: "not a protocol version this tool recognises",
		},
		{
			name: "a name on an inheriting policy with a bad algorithm value",
			body: "name: " + hugePayload("A") + "\nextends: modern\n" +
				"rules:\n  cipher:\n    bannedAlgorithms: [\"" + hugePayload("-") + "\"]\n",
			mustContain: "has no letters or digits",
		},
	}

	evaluator := NewPolicyEvaluator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicyFile(t, tt.body)

			_, err := evaluator.LoadPolicy(path)
			if err == nil {
				t.Fatal("the policy loaded, so this case measures nothing")
			}
			if !strings.Contains(err.Error(), tt.mustContain) {
				t.Fatalf("the fixture no longer reaches the refusal under test.\nwant %q in: %.400s",
					tt.mustContain, err.Error())
			}

			if got := len(err.Error()); got > maxRefusalBytes {
				t.Errorf("the refusal is %d bytes, so the policy file still chooses how much "+
					"of the terminal it fills", got)
			}
		})
	}
}

// TestARefusalStillQuotesEnoughOfTheValueToBeUseful is the direction control.
//
// Bounding untrusted text is worth nothing if it is bounded to nothing: a
// refusal that names neither the policy nor the value sends the author looking
// with no starting point, which is the failure the per-entry decoder fix already
// had to repair once in this class.
func TestARefusalStillQuotesEnoughOfTheValueToBeUseful(t *testing.T) {
	const marker = "MyCompanyBaseline"
	path := writePolicyFile(t, "name: "+marker+strings.Repeat("A", 4096)+"\n")

	_, err := NewPolicyEvaluator().LoadPolicy(path)
	if err == nil {
		t.Fatal("the policy loaded, so this case measures nothing")
	}
	if !strings.Contains(err.Error(), marker) {
		t.Errorf("the refusal no longer quotes the start of the policy name: %.300s", err.Error())
	}
	if !strings.Contains(err.Error(), "policy.yaml") {
		t.Errorf("the refusal no longer names the file it read: %.300s", err.Error())
	}
}

// TestAValueIsJudgedOnTheRawTextAndOnlyEchoedScrubbed is the fail-open
// direction of the same change, and it is the one that costs a verdict.
//
// ForReport collapses control characters to spaces and trims, so scrubbing
// before the decision turns "TLS 1.2" plus a trailing escape into the accepted
// spelling, and "modern" plus one into the name of a built-in policy. Each
// refusal exists precisely to stop a value the tool does not recognise being
// treated as one it does: bounding the echo must not be allowed to reintroduce
// that through the transformation.
func TestAValueIsJudgedOnTheRawTextAndOnlyEchoedScrubbed(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		mustContain string
	}{
		{
			name:        "a protocol version that scrubs to an accepted spelling",
			body:        "name: mine\nrules:\n  protocol:\n    minVersion: \"TLS 1.2\\u001b\"\n",
			mustContain: "not a protocol version this tool recognises",
		},
		{
			name:        "an extends target that scrubs to a built-in name",
			body:        "name: mine\nextends: \"modern\\u001b\"\n",
			mustContain: "is not a built-in policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicyFile(t, tt.body)

			_, err := NewPolicyEvaluator().LoadPolicy(path)
			if err == nil {
				t.Fatal("the value was accepted, so the decision is being taken on the " +
					"scrubbed text rather than on what the file actually wrote")
			}
			if !strings.Contains(err.Error(), tt.mustContain) {
				t.Fatalf("refused for a different reason than the one under test: %.300s",
					err.Error())
			}
			if strings.ContainsRune(err.Error(), 0x1b) {
				t.Errorf("a raw escape byte reached stderr: %q", err.Error())
			}
		})
	}
}

// TestANameOfOnlyControlCharactersIsRefusedAsUnnamed pins the second effect of
// sanitising before the check rather than after it.
//
// A name made only of control characters used to satisfy `TrimSpace(Name) != ""`
// and was scrubbed to empty afterwards, so it was reported as an empty policy
// name beside a verdict. That is the exact outcome the unnamed-policy check
// exists to prevent, reached through the check rather than around it.
// The payload is control characters and nothing else. An earlier version of
// this fixture used a full cursor-up sequence, whose "[2K" and "[1A" are
// ordinary printable text: scrubbing left a non-empty name and the case proved
// the opposite of what its name claims.
func TestANameOfOnlyControlCharactersIsRefusedAsUnnamed(t *testing.T) {
	// Both decode paths. The inheriting one is here for the same reason as the
	// `extends` volume fixtures above: it is a second decode that reassigns the
	// whole struct, and the first version of this fix did not survive it. On that
	// path this case regressed from "reported as an empty name" to "reported as
	// three raw control bytes", which is worse than the defect being fixed.
	for _, tc := range []struct{ name, body string }{
		{"standalone", "name: \"\\u001b\\u0007\\u0001\\u009b\"\n" +
			"rules:\n  cipher:\n    minKeySize: 256\n"},
		{"inheriting", "name: \"\\u001b\\u0007\\u0001\\u009b\"\nextends: modern\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPolicyEvaluator().LoadPolicy(writePolicyFile(t, tc.body))
			if err == nil {
				t.Fatal("a policy whose name is only control characters was accepted " +
					"and named nothing")
			}
			if !strings.Contains(err.Error(), "sets no 'name'") {
				t.Errorf("the refusal does not say the policy is unnamed: %.300s", err.Error())
			}
			if strings.ContainsRune(err.Error(), 0x1b) {
				t.Errorf("a raw escape byte reached stderr: %q", err.Error())
			}
		})
	}
}

// TestAnInheritingPolicyCarriesABoundedNameIntoTheVerdict is the other half of
// the same regression: not the refusal, but the value that reaches the report
// when the policy LOADS.
//
// policyResult.policyName is rendered into every surface. On the inheriting path
// it carried the file's chosen length and its control characters verbatim.
func TestAnInheritingPolicyCarriesABoundedNameIntoTheVerdict(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"standalone", "name: \"evil\\u001b[1A" + strings.Repeat("A", 200*1024) + "\"\n" +
			"rules:\n  cipher:\n    minKeySize: 256\n"},
		{"inheriting", "name: \"evil\\u001b[1A" + strings.Repeat("A", 200*1024) + "\"\n" +
			"extends: modern\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := NewPolicyEvaluator().LoadPolicy(writePolicyFile(t, tc.body))
			if err != nil {
				t.Fatalf("the policy was refused, so this case measures nothing: %.200s", err)
			}
			if len(policy.Name) > 120 {
				t.Errorf("the loaded policy name is %d bytes, so the file chose how much "+
					"of every report it fills", len(policy.Name))
			}
			if strings.ContainsRune(policy.Name, 0x1b) {
				t.Errorf("a raw escape byte reached the loaded policy name: %q",
					policy.Name[:40])
			}
			if !strings.HasPrefix(policy.Name, "evil") {
				t.Errorf("bounding lost the start of the name: %q", policy.Name[:40])
			}
		})
	}
}
