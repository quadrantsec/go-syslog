package syslog

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"gopkg.in/mcuadros/go-syslog.v2/format"
)

// collectHandler keeps every message it's handed.
type collectHandler struct {
	mu    sync.Mutex
	parts []format.LogParts
	ch    chan format.LogParts
}

func newCollectHandler() *collectHandler {
	return &collectHandler{ch: make(chan format.LogParts, 100)}
}

func (h *collectHandler) Handle(lp format.LogParts, _ int64, _ error) {
	h.mu.Lock()
	h.parts = append(h.parts, lp)
	h.mu.Unlock()
	h.ch <- lp
}

func (h *collectHandler) wait(t *testing.T, timeout time.Duration) format.LogParts {
	t.Helper()
	select {
	case lp := <-h.ch:
		return lp
	case <-time.After(timeout):
		t.Fatalf("no message within %s", timeout)
		return nil
	}
}

// startTLSServer boots a TLS server on a free local port. configure runs
// before Boot.
func startTLSServer(t *testing.T, f format.Format, h Handler, configure ...func(*Server)) (*Server, string) {
	t.Helper()
	server := NewServer()
	server.SetFormat(f)
	server.SetHandler(h)
	for _, fn := range configure {
		fn(server)
	}
	if err := server.ListenTCPTLS("127.0.0.1:0", getServerConfig()); err != nil {
		t.Fatal(err)
	}
	if err := server.Boot(); err != nil {
		t.Fatal(err)
	}
	return server, server.listeners[0].Addr().String()
}

// stop kills the server and fails the test if Wait doesn't return.
func stop(t *testing.T, server *Server) {
	t.Helper()
	if err := server.Kill(); err != nil {
		t.Errorf("Kill: %v", err)
	}
	done := make(chan struct{})
	go func() {
		server.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after Kill")
	}
}

// QIS-825: a peer that connects and never sends a ClientHello must not stop
// other clients on the same port from completing TLS.
func TestStalledHandshakeDoesNotBlockListener(t *testing.T) {
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h, func(s *Server) {
		s.SetHandshakeTimeout(time.Second)
	})
	defer stop(t, server)

	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(100 * time.Millisecond) // let the listener accept it first

	start := time.Now()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, getClientConfig())
	if err != nil {
		t.Fatalf("second client could not complete TLS: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, octet(sampleFortiGate1)); err != nil {
		t.Fatal(err)
	}
	lp := h.wait(t, 3*time.Second)
	// The silent peer would hold the listener for the whole handshake
	// timeout if the handshake still ran on the accept loop.
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("second client took %s; the stalled handshake blocked it", elapsed)
	}
	if lp["tls_peer"] != "dummycert1" {
		t.Errorf("tls_peer = %v", lp["tls_peer"])
	}

	// The silent peer is dropped once the handshake timeout passes.
	if err := silent.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ne net.Error
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Error("silent peer got data instead of being closed")
	} else if errors.As(err, &ne) && ne.Timeout() {
		t.Error("silent peer was not closed after the handshake timeout")
	}
}

// Kill closes open connections, so Wait (and secure-syslog's Stop, /update
// and graceful shutdown) returns even while a sender holds its connection.
func TestKillClosesOpenConnections(t *testing.T) {
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, octet(sampleFortiGate1)); err != nil {
		t.Fatal(err)
	}
	h.wait(t, 3*time.Second)

	stop(t, server) // fails the test if Wait hangs on the open connection

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("connection still open after Kill")
	}
}

// Kill is safe to call twice.
func TestKillTwice(t *testing.T) {
	server, _ := startTLSServer(t, RFC5424, newCollectHandler())
	stop(t, server)
	if err := server.Kill(); err != nil {
		t.Errorf("second Kill: %v", err)
	}
}

// QIS-833 end to end: FortiGate frames over TLS arrive without the next
// frame's length glued on, and a one-message connection is delivered without
// waiting for a second message.
func TestTLSOctetCountedStream(t *testing.T) {
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h)
	defer stop(t, server)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, octet(sampleFortiGate1)); err != nil {
		t.Fatal(err)
	}
	first := h.wait(t, 3*time.Second)
	if _, err := io.WriteString(conn, octet(sampleFortiGate2)+octet(sampleFortiGate1)); err != nil {
		t.Fatal(err)
	}
	second := h.wait(t, 3*time.Second)
	third := h.wait(t, 3*time.Second)

	for _, c := range []struct {
		lp     format.LogParts
		suffix string
	}{
		{first, `rcvdpkt=21`},
		{second, `srcserver=0`},
		{third, `rcvdpkt=21`},
	} {
		msg, _ := c.lp["message"].(string)
		suffix := c.suffix
		if len(msg) < len(suffix) || msg[len(msg)-len(suffix):] != suffix {
			t.Errorf("message should end in %q, got %q", suffix, msg)
		}
	}
	if first["hostname"] != "FGT-EDGE-01" {
		t.Errorf("hostname = %v", first["hostname"])
	}
}

// An RFC 3164 sender on an RFC 5424 port fails to parse ("Invalid year in
// timestamp") and was dropped by secure-syslog. With a fallback format it's
// parsed as RFC 3164 instead.
func TestFallbackFormat(t *testing.T) {
	const line = "<38>Nov  9 15:00:01 web01 sshd[1234]: Accepted publickey for root"
	for _, c := range []struct {
		name     string
		fallback format.Format
		wantErr  bool
	}{
		{"without fallback", nil, true},
		{"with fallback", Automatic, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := &errHandler{}
			server := NewServer()
			server.SetFormat(RFC5424)
			server.SetFallbackFormat(c.fallback)
			server.SetHandler(h)
			server.parser([]byte(line), "192.0.2.1:5000", "")
			if (h.err != nil) != c.wantErr {
				t.Fatalf("err = %v, want error: %v", h.err, c.wantErr)
			}
			if !c.wantErr {
				if h.parts["content"] != "Accepted publickey for root" || h.parts["hostname"] != "web01" {
					t.Errorf("parts = %v", h.parts)
				}
			}
		})
	}
}

type errHandler struct {
	parts format.LogParts
	err   error
}

func (h *errHandler) Handle(lp format.LogParts, _ int64, err error) {
	h.parts, h.err = lp, err
}

// Kill lets open connections deliver frames that already arrived, instead
// of dropping them with the socket.
func TestKillDeliversWhatArrived(t *testing.T) {
	h := newCollectHandler()
	h.ch = make(chan format.LogParts, 1000)
	server, addr := startTLSServer(t, RFC5424, h)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var stream string
	for range 500 {
		stream += octet(sampleFortiGate1)
	}
	if _, err := io.WriteString(conn, stream); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	stop(t, server)

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.parts) != 500 {
		t.Errorf("delivered %d of 500 frames that arrived before Kill", len(h.parts))
	}
}
