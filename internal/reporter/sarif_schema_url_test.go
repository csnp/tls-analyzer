package reporter

import (
	"encoding/json"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// TestSARIFNamesASchemaURLThatIsPublished pins the $schema of the SARIF log. It
// pointed at raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/
// sarif-schema-2.1.0.json, which answered 404 on 2026-10-18, so a validator that
// follows $schema had nothing to validate against.
func TestSARIFNamesASchemaURLThatIsPublished(t *testing.T) {
	const want = "https://json.schemastore.org/sarif-2.1.0.json"

	for name, result := range map[string]*types.ScanResult{
		"scanned":     fullResult(),
		"not scanned": unreachedResult(),
	} {
		var log map[string]any
		if err := json.Unmarshal([]byte(render(t, &SARIFReporter{}, result)), &log); err != nil {
			t.Fatalf("%s: the SARIF log does not parse: %v", name, err)
		}
		if got := log["$schema"]; got != want {
			t.Errorf("%s: $schema = %v, want %s", name, got, want)
		}
	}
}
