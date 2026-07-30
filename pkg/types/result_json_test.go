package types

import (
	"encoding/json"
	"testing"
	"time"
)

// TestScanResultRoundTrips guards the defect where this package could marshal a
// scan result but not read one back, so a consumer importing these public types
// could not decode the tool's own --format json output:
//
//	json: cannot unmarshal string into Go struct field
//	ScanResult.duration of type types.Duration
//
// Duration had a MarshalJSON and no UnmarshalJSON.
func TestScanResultRoundTrips(t *testing.T) {
	original := ScanResult{
		Target:   "example.com:443",
		Host:     "example.com",
		Port:     443,
		Duration: Duration{Duration: 1234 * time.Millisecond},
		Grade: Grade{
			Letter:                  "B",
			Score:                   75,
			DimensionScore:          100,
			DimensionPoints:         100,
			DimensionMaxPoints:      100,
			VulnerabilityPenalty:    25,
			VulnerabilitiesAssessed: true,
			Penalties: []GradePenalty{
				{Severity: SeverityHigh, Count: 1, PointsEach: 15, PointsTotal: 15},
				{Severity: SeverityMedium, Count: 2, PointsEach: 5, PointsTotal: 10},
			},
		},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshalling a scan result failed: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("the tool's own JSON output cannot be decoded into its own types: %v", err)
	}

	if decoded.Duration.Duration != original.Duration.Duration {
		t.Errorf("duration round-tripped as %v, want %v",
			decoded.Duration.Duration, original.Duration.Duration)
	}
	if decoded.Grade.Score != original.Grade.Score ||
		decoded.Grade.DimensionScore != original.Grade.DimensionScore ||
		decoded.Grade.VulnerabilityPenalty != original.Grade.VulnerabilityPenalty {
		t.Errorf("grade round-tripped as %+v, want %+v", decoded.Grade, original.Grade)
	}
	if len(decoded.Grade.Penalties) != len(original.Grade.Penalties) {
		t.Errorf("penalties round-tripped as %d entries, want %d",
			len(decoded.Grade.Penalties), len(original.Grade.Penalties))
	}
}

// TestDurationUnmarshalRejectsGarbage keeps the new decoder from silently
// accepting a value it cannot represent.
func TestDurationUnmarshalRejectsGarbage(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"not-a-duration"`), &d); err == nil {
		t.Error("an unparseable duration string was accepted")
	}
	if err := json.Unmarshal([]byte(`{}`), &d); err == nil {
		t.Error("an object was accepted as a duration")
	}

	// A plain nanosecond count is what the standard time.Duration marshaller
	// emits, so a value that made the round trip through it must still decode.
	if err := json.Unmarshal([]byte(`1500000000`), &d); err != nil {
		t.Errorf("a nanosecond count was refused: %v", err)
	} else if d.Duration != 1500*time.Millisecond {
		t.Errorf("1500000000 ns decoded as %v", d.Duration)
	}
}
