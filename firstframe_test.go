package syslog

import (
	"crypto/tls"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLooksLikeSyslog(t *testing.T) {
	accept := []string{
		// PRI first
		"<0>x",
		"<13>Nov  9 15:00:01 web01 sshd[1234]: Accepted publickey for root",
		"<191>1 2026-11-13T17:26:49Z fw01 - - - - eventtime=1",
		"<189>date=2026-11-13 time=17:26:49 devname=fw01",
		"<6> 2026-11-13T17:25:30Z mail-1 audit: {}",
		"<166>2026-11-12T23:59:58Z fw-a : %FTD-6-302013: Built inbound TCP connection",
		"<013>leading zeros are tolerated",
		"\xef\xbb\xbf<13>after a byte order mark",
		// No PRI, a timestamp first
		"2026-11-13T00:01:09Z fw-a : %FTD-1-430002: EventPriority: Low",
		"2026-11-13T00:01:09.123456+05:30 host app: x",
		"2026-11-13T00:01:09-04:00 host",
		"2026-11-13T00:01:09+0530 host",
		"2026-11-13T00:01:09.5-0000 host",
		"CEF:0|Vendor|Product|1.0|100|event|5|src=192.0.2.1",
		"LEEF:1.0|Vendor|Product|1.0|100|src=192.0.2.1",
		"LEEF:2.0|Vendor|Product|1.0|100|^|src=192.0.2.1",
		"2026-11-13T00:01:09 host no zone",
		"2026-11-13 00:01:09 host space instead of T",
		"2026-11-13T00:01:09Z",
		"Nov 13 00:00:29 host app: x",
		"Nov  3 00:00:29 host",
		"Nov 3 00:00:29 host",
		"nov 13 00:00:29 host",
		"Nov 12 2026 23:59:50: %FTD-6-305011: Built dynamic TCP translation",
		"Nov 13 00:00:29",
		"Nov 13 00:00:29.123 host",
		// Cisco FTD's <-1>
		"<-1>Nov 13 2026 00:00:29: %FTD--1-6414004: TCP Syslog Server outside:192.0.2.10/6514 - Connection restored",
		"<-1>Nov 13 2026 00:00:30 fw-b : %FTD--1-6414004: TCP Syslog Server",
		"<-1> 2026-11-13T00:00:30Z fw-b : x",
	}
	reject := []string{
		"",
		"GET / HTTP/1.1",
		"GET /favicon.ico HTTP/1.1",
		"Host: 192.0.2.1:10003",
		"User-Agent: Mozilla/5.0 (compatible; scanner)",
		"User-Agent: curl/7.68.0",
		"Accept: */*",
		"Accept-Encoding: gzip",
		"OPTIONS / HTTP/1.0",
		"OPTIONS * RTSP/1.0",
		"CSEQ: 1",
		"EHLO",
		"HELP",
		"SSH-2.0-OpenSSH_9.6",
		"PRI * HTTP/2.0",
		"<?xml version='1.0'?><methodCall>",
		"<",
		"<>",
		"<192>x",
		"<1000>x",
		"<1a>x",
		"<-1>x",
		"<-1>2026-13-01T00:00:00Z host",
		"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
		"\x00\x00\x00\x85\xffSMBr",
		"0\x0c\x02\x01\x00`\x07\x02\x01\x02\x04",
		"1\xffSMBr",
		"7\x00\x00\x00",
		"\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind",
		"\x07version\x04bind",
		"2026-11-13",
		"2026-11-13T25:00:00Z host",
		"2026-11-13T00:01:09Zhost",
		"2026-11-13T00:01:09.Z host",
		"2026-11-13T00:01:09+05 host",
		"CEF:|x",
		"CEFx",
		"LEEF:x",
		"Nov 13 00:00:290",
		"Nov 32 00:00:00 host",
		"November 13 00:00:29 host",
		"Novel",
		"May I help you",
		"Mar 1 12:00:00x",
	}
	for _, s := range accept {
		if !LooksLikeSyslog([]byte(s)) {
			t.Errorf("LooksLikeSyslog(%q) = false, want true", s)
		}
	}
	for _, s := range reject {
		if LooksLikeSyslog([]byte(s)) {
			t.Errorf("LooksLikeSyslog(%q) = true, want false", s)
		}
	}
}

// connCapture keeps the snapshot of each closed connection.
type connCapture struct {
	mu     sync.Mutex
	closed []ConnSnapshot
	done   chan struct{}
}

func newConnCapture() *connCapture { return &connCapture{done: make(chan struct{}, 10)} }

func (c *connCapture) hook(ev ConnEvent, info *ConnInfo, _ error) {
	if ev != ConnClosed {
		return
	}
	c.mu.Lock()
	c.closed = append(c.closed, info.Snapshot())
	c.mu.Unlock()
	c.done <- struct{}{}
}

func (c *connCapture) wait(t *testing.T) ConnSnapshot {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed within 5s")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed[len(c.closed)-1]
}

// A connection's opening frames that fail the filter are dropped; from the
// first accepted frame on, every frame is parsed, syslog-shaped or not.
func TestFirstFrameFilterDropsOpeningFrames(t *testing.T) {
	h := newCollectHandler()
	cc := newConnCapture()
	var calls atomic.Int64
	server, addr := startTLSServer(t, RFC3164, h, func(s *Server) {
		s.SetFirstFrameFilter(func(_ *ConnInfo, frame []byte) bool {
			calls.Add(1)
			return LooksLikeSyslog(frame)
		})
		s.SetConnHook(cc.hook)
	})
	defer stop(t, server)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	stream := "GET / HTTP/1.1\r\nHost: 192.0.2.1:10003\r\n\r\n" +
		"<13>Nov  9 15:00:01 web01 app: hello\n" +
		"a continuation line without a PRI\n" +
		"GET / HTTP/1.1\n"
	if _, err := conn.Write([]byte(stream)); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	var got []string
	for range 3 {
		got = append(got, h.wait(t, 5*time.Second)["content"].(string))
	}
	want := []string{"hello", "a continuation line without a PRI", "GET / HTTP/1.1"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("parsed %q, want %q", got, want)
	}
	snap := cc.wait(t)
	if snap.FilteredFrames != 2 || snap.FilteredBytes != int64(len("GET / HTTP/1.1")+len("Host: 192.0.2.1:10003")) {
		t.Errorf("filtered frames=%d bytes=%d, want 2 and %d", snap.FilteredFrames, snap.FilteredBytes,
			len("GET / HTTP/1.1")+len("Host: 192.0.2.1:10003"))
	}
	if snap.FirstFiltered != "GET / HTTP/1.1" {
		t.Errorf("FirstFiltered = %q", snap.FirstFiltered)
	}
	if !strings.HasPrefix(snap.FirstFrame, "<13>Nov  9") || snap.Frames != 3 {
		t.Errorf("FirstFrame = %q, Frames = %d", snap.FirstFrame, snap.Frames)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("filter called %d times, want 3 (until the first accepted frame)", n)
	}
}

// A connection that sends nothing syslog-shaped delivers nothing, and stays
// open: the filter never closes a connection.
func TestFirstFrameFilterAllRejected(t *testing.T) {
	h := newCollectHandler()
	cc := newConnCapture()
	server, addr := startTLSServer(t, RFC3164, h, func(s *Server) {
		s.SetFirstFrameFilter(func(_ *ConnInfo, frame []byte) bool { return LooksLikeSyslog(frame) })
		s.SetConnHook(cc.hook)
	})
	defer stop(t, server)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// Still open: a later write goes through.
	time.Sleep(100 * time.Millisecond)
	if _, err := conn.Write([]byte("EHLO\r\n")); err != nil {
		t.Fatalf("connection closed by the filter: %v", err)
	}
	conn.Close()
	snap := cc.wait(t)
	if snap.Frames != 0 || snap.FilteredFrames != 3 {
		t.Errorf("frames=%d filtered=%d, want 0 and 3", snap.Frames, snap.FilteredFrames)
	}
	select {
	case lp := <-h.ch:
		t.Errorf("parsed %v, want nothing", lp)
	default:
	}
}

// A panicking filter accepts the frame instead of losing it.
func TestFirstFrameFilterPanicAccepts(t *testing.T) {
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC3164, h, func(s *Server) {
		s.SetFirstFrameFilter(func(*ConnInfo, []byte) bool { panic("policy bug") })
	})
	defer stop(t, server)

	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("<13>Nov  9 15:00:01 web01 app: kept\n")); err != nil {
		t.Fatal(err)
	}
	if got := h.wait(t, 5*time.Second)["content"]; got != "kept" {
		t.Errorf("content = %v", got)
	}
}

// Without a filter nothing changes: every frame is parsed.
func TestNoFirstFrameFilter(t *testing.T) {
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC3164, h)
	defer stop(t, server)
	conn, err := tls.Dial("tcp", addr, getClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\n")); err != nil {
		t.Fatal(err)
	}
	if got := h.wait(t, 5*time.Second)["content"]; got != "GET / HTTP/1.1" {
		t.Errorf("content = %v", got)
	}
}
