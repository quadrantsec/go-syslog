package syslog

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// infoLog keeps the ConnInfo of each connection and signals when one closes.
type infoLog struct {
	mu     sync.Mutex
	infos  []*ConnInfo
	closed chan *ConnInfo
}

func newInfoLog() *infoLog { return &infoLog{closed: make(chan *ConnInfo, 16)} }

func (l *infoLog) hook(ev ConnEvent, info *ConnInfo, _ error) {
	switch ev {
	case ConnAccepted:
		l.mu.Lock()
		l.infos = append(l.infos, info)
		l.mu.Unlock()
	case ConnClosed:
		l.closed <- info
	}
}

func (l *infoLog) waitClosed(t *testing.T) ConnSnapshot {
	t.Helper()
	select {
	case info := <-l.closed:
		return info.Snapshot()
	case <-time.After(5 * time.Second):
		t.Fatal("no connection closed within 5s")
		return ConnSnapshot{}
	}
}

func TestConnInfoTLSClient(t *testing.T) {
	infos := newInfoLog()
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h, func(s *Server) { s.SetConnHook(infos.hook) })
	defer stop(t, server)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, octet(sampleFortiGate1)+octet(sampleFortiGate1)); err != nil {
		t.Fatal(err)
	}
	h.wait(t, 3*time.Second)
	h.wait(t, 3*time.Second)

	// While it's open, the record is live.
	infos.mu.Lock()
	live := infos.infos[0].Snapshot()
	infos.mu.Unlock()
	if !live.Open || live.Frames != 2 {
		t.Errorf("live snapshot: open=%v frames=%d", live.Open, live.Frames)
	}
	conn.Close()

	s := infos.waitClosed(t)
	if s.Proxied || s.Source != s.Peer || s.Source != conn.LocalAddr().String() {
		t.Errorf("addresses: source %s, peer %s, proxied %v; want the client %s", s.Source, s.Peer, s.Proxied, conn.LocalAddr())
	}
	if s.TLSVersion != "TLS 1.3" || s.CipherSuite == "" || s.PeerCN != "dummycert1" {
		t.Errorf("TLS: %q %q peer %q", s.TLSVersion, s.CipherSuite, s.PeerCN)
	}
	if s.Frames != 2 || s.Bytes < int64(2*len(sampleFortiGate1)) || s.Framing != FramingOctet {
		t.Errorf("frames %d, bytes %d, framing %q", s.Frames, s.Bytes, s.Framing)
	}
	if !strings.HasPrefix(sampleFortiGate1, s.LastFrame) || s.LastFrame == "" || s.LastFrameAt == nil {
		t.Errorf("last frame %q", s.LastFrame)
	}
	if s.Open || s.CloseReason != CloseEOF || s.ClosedAt == nil {
		t.Errorf("close: open %v, reason %q", s.Open, s.CloseReason)
	}
}

func TestConnInfoCloseReasons(t *testing.T) {
	t.Run("idle_timeout", func(t *testing.T) {
		infos := newInfoLog()
		server, addr := startTLSServer(t, RFC5424, newCollectHandler(), func(s *Server) {
			s.SetConnHook(infos.hook)
			s.SetTimeout(300)
		})
		defer stop(t, server)
		conn, err := tls.Dial("tcp", addr, getClientConfig())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if s := infos.waitClosed(t); s.CloseReason != CloseIdleTimeout {
			t.Errorf("reason %q, want idle_timeout", s.CloseReason)
		}
	})
	t.Run("killed", func(t *testing.T) {
		infos := newInfoLog()
		server, addr := startTLSServer(t, RFC5424, newCollectHandler(), func(s *Server) { s.SetConnHook(infos.hook) })
		conn, err := tls.Dial("tcp", addr, getClientConfig())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
		stop(t, server)
		if s := infos.waitClosed(t); s.CloseReason != CloseKilled {
			t.Errorf("reason %q, want killed", s.CloseReason)
		}
	})
	t.Run("handshake_failed", func(t *testing.T) {
		infos := newInfoLog()
		server, addr := startTLSServer(t, RFC5424, newCollectHandler(), func(s *Server) {
			s.SetConnHook(infos.hook)
			s.SetHandshakeTimeout(200 * time.Millisecond)
		})
		defer stop(t, server)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if s := infos.waitClosed(t); s.CloseReason != CloseHandshakeFailed || s.CloseError == "" || s.TLSVersion != "" {
			t.Errorf("reason %q, error %q, tls %q", s.CloseReason, s.CloseError, s.TLSVersion)
		}
	})
}

func TestConnInfoDroppedData(t *testing.T) {
	infos := newInfoLog()
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h, func(s *Server) {
		s.SetConnHook(infos.hook)
		s.SetMaxFrameSize(100)
	})
	defer stop(t, server)
	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	long := "<13>1 - - - - - - " + strings.Repeat("x", 200)
	// One oversized octet-counted frame (dropped), then one oversized
	// newline-framed message (truncated).
	if _, err := io.WriteString(conn, octet(long)+long+"\n"); err != nil {
		t.Fatal(err)
	}
	h.wait(t, 3*time.Second)
	conn.Close()
	s := infos.waitClosed(t)
	if s.DroppedFrames != 1 || s.TruncatedFrames != 1 || s.DroppedBytes < int64(len(long)) || s.Framing != FramingLF {
		t.Errorf("dropped frames %d, truncated %d, dropped bytes %d, framing %q", s.DroppedFrames, s.TruncatedFrames, s.DroppedBytes, s.Framing)
	}
}

// captureLog collects the standard logger's output while fn runs.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	var mu sync.Mutex
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}))
	defer log.SetOutput(osStderr)
	fn()
	mu.Lock()
	defer mu.Unlock()
	return buf.String()
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestQuietConnLogs(t *testing.T) {
	run := func(quiet bool) string {
		return captureLog(func() {
			infos := newInfoLog()
			h := newCollectHandler()
			server, addr := startTLSServer(t, RFC5424, h, func(s *Server) {
				s.SetConnHook(infos.hook)
				s.SetQuietConnLogs(quiet)
			})
			conn, err := tls.Dial("tcp", addr, getClientConfig())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, octet(sampleFortiGate1)); err != nil {
				t.Fatal(err)
			}
			h.wait(t, 3*time.Second)
			conn.Close()
			infos.waitClosed(t)
			stop(t, server)
		})
	}
	verbose, quiet := run(false), run(true)
	for _, line := range []string{"Accepted connection", "TLS handshake complete", "Closing connection"} {
		if !strings.Contains(verbose, line) {
			t.Errorf("verbose logs lack %q", line)
		}
		if strings.Contains(quiet, line) {
			t.Errorf("quiet logs still have %q", line)
		}
	}
}

func TestClientHost(t *testing.T) {
	for in, want := range map[string]string{
		"10.50.19.147:33620":  "10.50.19.147",
		"[2001:db8::1]:5555":  "2001:db8::1",
		"[::ffff:10.0.0.1]:1": "::ffff:10.0.0.1",
		"/dev/log":            "/dev/log",
	} {
		if got := clientHost(in); got != want {
			t.Errorf("clientHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// The RFC 3164 hostname fill took everything before the first ':', so an
// IPv6 client became hostname "[2001".
func TestHostnameFillIPv6(t *testing.T) {
	h := newCollectHandler()
	server := NewServer()
	server.SetFormat(RFC3164)
	server.SetHandler(h)
	server.parser([]byte("<166>%FTD-6-430003: test"), "[2001:db8::1]:5555", "")
	lp := h.wait(t, time.Second)
	if lp["hostname"] != "2001:db8::1" || lp["client"] != "[2001:db8::1]:5555" {
		t.Errorf("hostname %q, client %q", lp["hostname"], lp["client"])
	}
}
