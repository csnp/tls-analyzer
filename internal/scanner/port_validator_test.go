package scanner

import "testing"

// This assertion names ValidatePort, which the port-range fix introduced, so it
// cannot compile against the earlier sources. It is kept apart from
// port_range_test.go so that the parseTarget assertions there stay buildable
// against them and fail at runtime on the accepted port instead.

// TestValidatePortBracketsTheRange pins both edges of the shared check directly.
func TestValidatePortBracketsTheRange(t *testing.T) {
	for _, port := range []int{1, 443, 8443, 65535} {
		if err := ValidatePort(port); err != nil {
			t.Errorf("ValidatePort(%d) refused a valid port: %v", port, err)
		}
	}
	for _, port := range []int{-1, 0, 65536, 70000} {
		if err := ValidatePort(port); err == nil {
			t.Errorf("ValidatePort(%d) accepted a port outside the TCP range", port)
		}
	}
}
