package syslog

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

// eventLog records hook events in order.
type eventLog struct {
	mu     sync.Mutex
	events []ConnEvent
	errs   []error
}

func (l *eventLog) hook(ev ConnEvent, _ net.Conn, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	if err != nil {
		l.errs = append(l.errs, err)
	}
}

// waitFor waits until the log ends with ConnClosed and returns a copy.
func (l *eventLog) waitFor(t *testing.T, want []ConnEvent) ([]ConnEvent, []error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		events, errs := slices.Clone(l.events), slices.Clone(l.errs)
		l.mu.Unlock()
		if slices.Equal(events, want) || time.Now().After(deadline) {
			return events, errs
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestConnHookTLSClient(t *testing.T) {
	var events eventLog
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h, func(s *Server) { s.SetConnHook(events.hook) })
	defer stop(t, server)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, octet(sampleFortiGate1)); err != nil {
		t.Fatal(err)
	}
	h.wait(t, 3*time.Second)
	conn.Close()

	want := []ConnEvent{ConnAccepted, ConnHandshakeOK, ConnClosed}
	if got, _ := events.waitFor(t, want); !slices.Equal(got, want) {
		t.Errorf("events = %v, want %v", got, want)
	}
}

func TestConnHookSilentClient(t *testing.T) {
	var events eventLog
	server, addr := startTLSServer(t, RFC5424, newCollectHandler(), func(s *Server) {
		s.SetConnHook(events.hook)
		s.SetHandshakeTimeout(300 * time.Millisecond)
	})
	defer stop(t, server)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	want := []ConnEvent{ConnAccepted, ConnHandshakeFailed, ConnClosed}
	got, errs := events.waitFor(t, want)
	if !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if reason, _ := HandshakeFailure(errs[0]); reason != "timeout" {
		t.Errorf("reason = %q for %v, want timeout", reason, errs[0])
	}
}

// A client that doesn't trust the server's CA: the reason must say so, not
// the misleading error text alone.
func TestConnHookUntrustedServer(t *testing.T) {
	var events eventLog
	server, addr := startTLSServer(t, RFC5424, newCollectHandler(), func(s *Server) { s.SetConnHook(events.hook) })
	defer stop(t, server)

	cfg := getClientConfig()
	cfg.RootCAs = x509.NewCertPool()
	cfg.MaxVersion = tls.VersionTLS12 // the client's alert reaches the server in clear
	if conn, err := tls.Dial("tcp", addr, cfg); err == nil {
		conn.Close()
		t.Fatal("handshake succeeded with an empty trust store")
	}

	want := []ConnEvent{ConnAccepted, ConnHandshakeFailed, ConnClosed}
	got, errs := events.waitFor(t, want)
	if !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	// Go's client sends bad_certificate here; OpenSSL clients send
	// unknown_ca. Both say the client rejected our certificate.
	if reason, _ := HandshakeFailure(errs[0]); reason != "unknown_ca" && reason != "bad_certificate" {
		t.Errorf("reason = %q for %v, want unknown_ca or bad_certificate", reason, errs[0])
	}
}

// A panicking hook must not take down the server.
func TestConnHookPanicIsContained(t *testing.T) {
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h, func(s *Server) {
		s.SetConnHook(func(ConnEvent, net.Conn, error) { panic("hook") })
	})
	defer stop(t, server)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, octet(sampleFortiGate1)); err != nil {
		t.Fatal(err)
	}
	h.wait(t, 3*time.Second)
}

func TestHandshakeFailure(t *testing.T) {
	cases := []struct {
		err    error
		reason string
	}{
		{nil, ""},
		{&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, "timeout"},
		{io.EOF, "eof"},
		{fmt.Errorf("wrapped: %w", syscall.ECONNRESET), "reset"},
		{errors.New("local error: tls: bad record MAC"), "bad_record_mac"},
		{errors.New("remote error: tls: unknown certificate authority"), "unknown_ca"},
		{errors.New("remote error: tls: bad certificate"), "bad_certificate"},
		{errors.New("tls: client offered only unsupported versions: [302 301]"), "old_tls"},
		{errors.New("tls: no cipher suite supported by both client and server"), "no_cipher"},
		{errors.New("tls: client didn't provide a certificate"), "no_client_cert"},
		{errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority"), "client_cert_invalid"},
		{errors.New("tls: first record does not look like a TLS handshake"), "not_tls"},
		{errors.New("something new"), "other"},
	}
	for _, c := range cases {
		reason, hint := HandshakeFailure(c.err)
		if reason != c.reason {
			t.Errorf("HandshakeFailure(%v) = %q, want %q", c.err, reason, c.reason)
		}
		if c.reason != "" && c.reason != "other" && hint == "" {
			t.Errorf("HandshakeFailure(%v) has no hint", c.err)
		}
	}
}
