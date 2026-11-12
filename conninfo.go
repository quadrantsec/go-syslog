package syslog

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// Why a stream connection closed, in ConnInfo.
const (
	CloseEOF             = "eof"              // the client closed it
	CloseIdleTimeout     = "idle_timeout"     // nothing arrived within the read timeout
	CloseKilled          = "killed"           // the server is stopping
	CloseReset           = "reset"            // the client reset it
	CloseReadError       = "read_error"       // any other read error
	CloseHandshakeFailed = "handshake_failed" // the TLS handshake failed; see HandshakeFailure
	ClosePeerRejected    = "peer_rejected"    // the TLS peer name function refused the client
	ClosePanic           = "panic"            // a panic while handling it, recovered
)

// Framing of the last frame on a connection, in ConnInfo.
const (
	FramingOctet = "octet" // RFC 6587 octet counting
	FramingLF    = "lf"    // ended by a newline
	FramingNUL   = "nul"   // ended by a NUL
	FramingEOF   = "eof"   // the last message before the client closed, with no trailer
)

// lastFrameMax is how much of the last frame a ConnInfo keeps.
const lastFrameMax = 512

// ConnInfo describes one stream connection while it runs and after it
// closes: who it is, how its TLS handshake went, what it sent and why it
// ended. The server updates it from the connection's goroutines; Snapshot
// can read it from anywhere at any time.
type ConnInfo struct {
	// Peer is the TCP peer. Behind a proxy that's the proxy; it's what the
	// stored client field and the RFC 3164 hostname fill use.
	Peer net.Addr
	// Local is the server's end of the TCP connection.
	Local net.Addr
	// Started is when the connection was accepted.
	Started time.Time

	bytes, frames                                atomic.Int64
	droppedBytes, droppedFrames, truncatedFrames atomic.Int64
	lastFrameAt                                  atomic.Int64 // unix nanoseconds

	mu          sync.Mutex
	source      net.Addr // from a trusted PROXY protocol header
	tlsVersion  uint16
	cipherSuite uint16
	peerCN      string
	framing     string
	lastFrame   []byte
	closeReason string
	closeError  string
	closed      time.Time
}

// ConnSnapshot is a ConnInfo at one moment.
type ConnSnapshot struct {
	// Source is the client: the address from a trusted PROXY header, or
	// else the TCP peer.
	Source          string     `json:"source"`
	Peer            string     `json:"peer"`
	Local           string     `json:"local"`
	Proxied         bool       `json:"proxied"`
	StartedAt       time.Time  `json:"started_at"`
	DurationMS      int64      `json:"duration_ms"`
	TLSVersion      string     `json:"tls_version,omitempty"`
	CipherSuite     string     `json:"cipher_suite,omitempty"`
	PeerCN          string     `json:"peer_cn,omitempty"`
	Bytes           int64      `json:"bytes"`
	Frames          int64      `json:"frames"`
	DroppedBytes    int64      `json:"dropped_bytes"`
	DroppedFrames   int64      `json:"dropped_frames"`
	TruncatedFrames int64      `json:"truncated_frames"`
	Framing         string     `json:"framing,omitempty"`
	LastFrameAt     *time.Time `json:"last_frame_at,omitempty"`
	LastFrame       string     `json:"last_frame,omitempty"`
	Open            bool       `json:"open"`
	ClosedAt        *time.Time `json:"closed_at,omitempty"`
	CloseReason     string     `json:"close_reason,omitempty"`
	CloseError      string     `json:"close_error,omitempty"`
}

// newConnInfo starts the record for an accepted connection. It reads only
// the raw TCP addresses: asking a PROXY protocol connection for its
// addresses would read the header, and that must not happen on the accept
// loop.
func newConnInfo(conn net.Conn) *ConnInfo {
	raw := rawConn(conn)
	return &ConnInfo{Peer: raw.RemoteAddr(), Local: raw.LocalAddr(), Started: time.Now()}
}

// Source returns the client's address: from a trusted PROXY header, or else
// the TCP peer.
func (c *ConnInfo) Source() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.source != nil {
		return c.source
	}
	return c.Peer
}

// Snapshot returns the record as it is now. LastFrame is the start of a
// real message: treat it as log content.
func (c *ConnInfo) Snapshot() ConnSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := ConnSnapshot{
		Peer:            addrString(c.Peer),
		Local:           addrString(c.Local),
		Proxied:         c.source != nil,
		StartedAt:       c.Started.UTC(),
		PeerCN:          c.peerCN,
		Bytes:           c.bytes.Load(),
		Frames:          c.frames.Load(),
		DroppedBytes:    c.droppedBytes.Load(),
		DroppedFrames:   c.droppedFrames.Load(),
		TruncatedFrames: c.truncatedFrames.Load(),
		Framing:         c.framing,
		LastFrame:       string(c.lastFrame),
		Open:            c.closed.IsZero(),
		CloseReason:     c.closeReason,
		CloseError:      c.closeError,
	}
	s.Source = s.Peer
	if c.source != nil {
		s.Source = c.source.String()
	}
	if c.tlsVersion != 0 {
		s.TLSVersion = tls.VersionName(c.tlsVersion)
		s.CipherSuite = tls.CipherSuiteName(c.cipherSuite)
	}
	end := time.Now()
	if !c.closed.IsZero() {
		end = c.closed
		t := c.closed.UTC()
		s.ClosedAt = &t
	}
	s.DurationMS = end.Sub(c.Started).Milliseconds()
	if ns := c.lastFrameAt.Load(); ns != 0 {
		t := time.Unix(0, ns).UTC()
		s.LastFrameAt = &t
	}
	return s
}

func (c *ConnInfo) setSource(a net.Addr) {
	c.mu.Lock()
	c.source = a
	c.mu.Unlock()
}

func (c *ConnInfo) setTLS(state tls.ConnectionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tlsVersion, c.cipherSuite = state.Version, state.CipherSuite
	if len(state.PeerCertificates) > 0 {
		c.peerCN = state.PeerCertificates[0].Subject.CommonName
	}
}

func (c *ConnInfo) frame(msg []byte) {
	c.frames.Add(1)
	c.lastFrameAt.Store(time.Now().UnixNano())
	c.mu.Lock()
	c.lastFrame = append(c.lastFrame[:0], msg[:min(len(msg), lastFrameMax)]...)
	c.mu.Unlock()
}

func (c *ConnInfo) setFraming(f string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.framing = f
	c.mu.Unlock()
}

// dropped counts data the frame reader skipped or dropped.
func (c *ConnInfo) dropped(bytes, frames int) {
	if c == nil {
		return
	}
	c.droppedBytes.Add(int64(bytes))
	c.droppedFrames.Add(int64(frames))
}

func (c *ConnInfo) truncated(bytes int) {
	if c == nil {
		return
	}
	c.droppedBytes.Add(int64(bytes))
	c.truncatedFrames.Add(1)
}

// close records why the connection ended. The first call wins.
func (c *ConnInfo) close(reason string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed.IsZero() {
		return
	}
	c.closed = time.Now()
	c.closeReason = reason
	if err != nil {
		c.closeError = err.Error()
	}
}

// readCloseReason classifies the error that ended a connection's reads.
func readCloseReason(err error, stopping bool) string {
	var ne net.Error
	switch {
	case errors.Is(err, io.EOF):
		return CloseEOF
	case stopping || errors.Is(err, net.ErrClosed):
		return CloseKilled
	case errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return CloseIdleTimeout
	case errors.Is(err, syscall.ECONNRESET):
		return CloseReset
	}
	return CloseReadError
}

// countingReader counts the bytes read through it into n.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// rawConn returns the TCP connection under TLS and the PROXY protocol, so its
// addresses can be read without reading a PROXY header.
func rawConn(conn net.Conn) net.Conn {
	if t, ok := conn.(*tls.Conn); ok {
		conn = t.NetConn()
	}
	if p, ok := conn.(*proxyproto.Conn); ok {
		conn = p.Raw()
	}
	return conn
}

// proxyConn returns the PROXY protocol connection under conn, if there is one.
func proxyConn(conn net.Conn) *proxyproto.Conn {
	if t, ok := conn.(*tls.Conn); ok {
		conn = t.NetConn()
	}
	p, _ := conn.(*proxyproto.Conn)
	return p
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}
