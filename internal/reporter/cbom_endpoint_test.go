package reporter

import (
	"net"
	"net/url"
	"strconv"
	"testing"
)

// cbomEndpoints returns the endpoints of the one service a CBOM lists.
func cbomEndpoints(t *testing.T, out string) []string {
	t.Helper()
	doc := decodeJSON(t, out)
	services, ok := doc["services"].([]any)
	if !ok || len(services) != 1 {
		t.Fatalf("CBOM lists %v services, want exactly 1", doc["services"])
	}
	service, ok := services[0].(map[string]any)
	if !ok {
		t.Fatal("CBOM service is not an object")
	}
	raw, _ := service["endpoints"].([]any)
	endpoints := make([]string, 0, len(raw))
	for _, e := range raw {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("CBOM endpoint %v is not a string", e)
		}
		endpoints = append(endpoints, s)
	}
	return endpoints
}

// TestCBOMEndpointWritesAnIPv6AddressInBrackets is the reproduction of
// "tlsanalyzer '[::1]:<port>' --format cbom lists the endpoint
// https://::1:<port>". The endpoint was written from the host and the port with
// "https://%s:%d", so an IPv6 address lost its brackets and its port read as
// part of the address. Writing it that way again kills the three IPv6 cases;
// this was observed, all three failed on that code. The IPv4 address and the
// host name are the controls, written as before.
//
// Each endpoint is also read back with net/url, which catches a zone written
// with a bare %: url.Parse refuses "https://[fe80::1%lo0]:9" with "invalid URL
// escape". What it does with the missing brackets depends on the
// urlstrictcolons GODEBUG setting. With urlstrictcolons=1, the default when
// go.mod says go 1.26 or later, url.Parse refuses "https://::1:8443" with
// `invalid port "::1:8443" after host`. With urlstrictcolons=0, the default
// when go.mod says go 1.25 or earlier, as this module's does, it reads the same
// string as host ::1 and port 8443 and returns no error. The exact string is
// checked first so the missing brackets fail the test under either setting, and
// so does an endpoint that parses to the same parts but is written another way,
// such as "https://[::1]:8443/" with a trailing slash.
func TestCBOMEndpointWritesAnIPv6AddressInBrackets(t *testing.T) {
	cases := []struct {
		name string
		host string
		port int
		want string
	}{
		{"IPv6 loopback", "::1", 8443, "https://[::1]:8443"},
		{"IPv6 documentation address", "2001:db8::1", 443, "https://[2001:db8::1]:443"},
		// A URL writes the % before a zone as %25 (RFC 6874).
		{"zone-scoped link-local", "fe80::1%lo0", 9, "https://[fe80::1%25lo0]:9"},
		{"IPv4", "127.0.0.1", 8443, "https://127.0.0.1:8443"},
		{"host name", "example.com", 443, "https://example.com:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := scannedResult()
			result.Target = net.JoinHostPort(tc.host, strconv.Itoa(tc.port))
			result.Host = tc.host
			result.Port = tc.port

			endpoints := cbomEndpoints(t, render(t, &CBOMReporter{}, result))
			if len(endpoints) != 1 || endpoints[0] != tc.want {
				t.Fatalf("CBOM endpoints = %q, want [%q]", endpoints, tc.want)
			}

			u, err := url.Parse(endpoints[0])
			if err != nil {
				t.Fatalf("the endpoint is not a URL: %v", err)
			}
			if u.Scheme != "https" || u.Hostname() != tc.host || u.Port() != strconv.Itoa(tc.port) {
				t.Errorf("%q reads back as scheme %q, host %q, port %q; want https, %q, %d",
					endpoints[0], u.Scheme, u.Hostname(), u.Port(), tc.host, tc.port)
			}
		})
	}
}
