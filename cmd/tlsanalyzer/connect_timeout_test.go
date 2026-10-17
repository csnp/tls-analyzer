package main

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestConnectTimeoutIsHalfOfTimeoutAndNeverZero is the reproduction of "with
// --timeout 1, the no-handshake error misdescribes a reachable service". The
// connect timeout was timeout/2 in whole seconds, 0 for --timeout 1, and a dial
// reads 0 as no timeout at all.
func TestConnectTimeoutIsHalfOfTimeoutAndNeverZero(t *testing.T) {
	for _, seconds := range []int{1, 2, 3, 30} {
		got := connectTimeout(seconds)
		want := time.Duration(seconds) * time.Second / 2
		if got <= 0 || got != want {
			t.Errorf("connectTimeout(%d) = %v; want %v", seconds, got, want)
		}
	}
}

// TestTimeoutOneStillNamesAServiceThatDoesNotSpeakTLS runs the command against
// a plain HTTP listener with --timeout 1, the reproduction from the report. The
// error said the host "may not speak TLS or may accept nothing this scanner
// offers" and named two key exchange groups to check, where the default timeout
// said the reply was not TLS.
func TestTimeoutOneStillNamesAServiceThatDoesNotSpeakTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 512)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
			}(conn)
		}
	}()
	installLookupRecorder(t, func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})

	// runCLI fixes --timeout at 5, so the flag variables are set here instead.
	prevTargets, prevOutput, prevFormat := targetsFile, outputFile, outputFormat
	prevVulns, prevQuantum, prevCNSA2 := skipVulns, skipQuantum, skipCNSA2
	prevTimeout, prevConcurrency := timeout, concurrency
	defer func() {
		targetsFile, outputFile, outputFormat = prevTargets, prevOutput, prevFormat
		skipVulns, skipQuantum, skipCNSA2 = prevVulns, prevQuantum, prevCNSA2
		timeout, concurrency = prevTimeout, prevConcurrency
	}()
	targetsFile, outputFile, outputFormat = "", "", "text"
	skipVulns, skipQuantum, skipCNSA2 = true, true, true
	timeout, concurrency = 1, 4

	target := "127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	err = runScan(rootCmd, []string{target})
	if err == nil {
		t.Fatal("a plain HTTP server was scanned as TLS")
	}
	msg := err.Error()
	if !strings.Contains(msg, "does not appear to speak TLS") {
		t.Errorf("with --timeout 1 the error should say the service does not appear to "+
			"speak TLS, as it does with the default timeout, got %q", msg)
	}
	if strings.Contains(msg, "i/o timeout") {
		t.Errorf("with --timeout 1 the diagnostic handshake timed out at once: %q", msg)
	}
}
