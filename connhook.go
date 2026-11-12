package syslog

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	proxyproto "github.com/pires/go-proxyproto"
)

// ConnEvent is a stage in a stream connection's life, reported to a ConnHook.
type ConnEvent int

const (
	// ConnAccepted: the listener accepted the connection.
	ConnAccepted ConnEvent = iota
	// ConnHandshakeOK: the TLS handshake completed.
	ConnHandshakeOK
	// ConnHandshakeFailed: the TLS handshake failed. The hook gets the error;
	// HandshakeFailure classifies it.
	ConnHandshakeFailed
	// ConnClosed: the connection was closed. Every accepted connection gets
	// exactly one.
	ConnClosed
)

func (e ConnEvent) String() string {
	switch e {
	case ConnAccepted:
		return "accepted"
	case ConnHandshakeOK:
		return "handshake_ok"
	case ConnHandshakeFailed:
		return "handshake_failed"
	case ConnClosed:
		return "closed"
	}
	return "unknown"
}

// ConnHook is told about each stream connection's events, for counters,
// status pages and one-line connection logs. info is the same pointer for
// every event of a connection and stays readable (Snapshot) while it runs;
// at ConnClosed it is complete. It runs on the connection's goroutine, so it
// must be quick and must not block. err is set only for ConnHandshakeFailed.
type ConnHook func(ev ConnEvent, info *ConnInfo, err error)

// SetConnHook sets the hook for stream connection events. Set it before Boot.
func (s *Server) SetConnHook(hook ConnHook) {
	s.connHook = hook
}

// connEvent calls the hook. A panicking hook is logged and ignored: it's
// called from the connection's own panic recovery too, where a second panic
// would take down the whole process.
func (s *Server) connEvent(ev ConnEvent, info *ConnInfo, err error) {
	if s.connHook == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in connection hook, event=%s, error=%v", ev, r)
		}
	}()
	s.connHook(ev, info, err)
}

// SetQuietConnLogs stops the per-connection log lines (accepted, handshake
// complete or failed, peer refused, reading stopped, closing), for a caller
// that logs one line per connection from its ConnHook instead. Accept
// errors, panics and dropped or skipped data are still logged.
func (s *Server) SetQuietConnLogs(quiet bool) {
	s.quietConnLogs = quiet
}

// connLog logs a per-connection line unless SetQuietConnLogs is on.
func (s *Server) connLog(format string, args ...any) {
	if !s.quietConnLogs {
		log.Printf(format, args...)
	}
}

// HandshakeFailure classifies a failed TLS handshake for logs and counters:
// a short reason code and a hint at the usual cause. Go's server-side errors
// are easy to misread. For example, a TLS 1.3 client that rejects the
// server's certificate shows up as "bad record MAC", because the client's
// alert arrives where the server expects an encrypted record. reason is
// "other" and hint empty for errors it doesn't recognize.
func HandshakeFailure(err error) (reason, hint string) {
	if err == nil {
		return "", ""
	}
	var ne net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return "timeout", "the client sent no TLS hello before the handshake timeout: a silent client, or one that isn't speaking TLS"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "eof", "the client closed the connection during the handshake: often a TCP health check or a scanner"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "reset", "the client reset the connection during the handshake"
	}
	if errors.Is(err, proxyproto.ErrSuperfluousProxyHeader) {
		return "untrusted_proxy_header", "a PROXY protocol header from an address that isn't a trusted proxy; refused"
	}
	if strings.HasPrefix(err.Error(), "proxyproto:") {
		return "bad_proxy_header", "a malformed or unsupported PROXY protocol header from the trusted proxy"
	}
	msg := err.Error()
	for _, c := range handshakeFailures {
		if strings.Contains(msg, c.match) {
			return c.reason, c.hint
		}
	}
	return "other", ""
}

// handshakeFailures maps error text to a reason, most specific first.
var handshakeFailures = []struct{ match, reason, hint string }{
	{"bad record MAC", "bad_record_mac", "usually the client rejected our certificate (TLS 1.3 hides the reason); capping the port at TLS 1.2 makes the client say why"},
	{"remote error: tls: unknown certificate authority", "unknown_ca", "the client doesn't trust the CA that issued our certificate"},
	{"remote error: tls: bad certificate", "bad_certificate", "the client rejected our certificate"},
	{"remote error: tls: certificate unknown", "bad_certificate", "the client rejected our certificate"},
	{"remote error: tls: unsupported certificate", "bad_certificate", "the client rejected our certificate"},
	{"remote error: tls: certificate expired", "bad_certificate", "the client says our certificate expired"},
	{"remote error: tls: handshake failure", "client_abort", "the client gave up on the handshake: no common version or cipher, or it rejected our certificate"},
	{"remote error: tls: protocol version", "old_tls", "the client and this port share no TLS version"},
	{"client offered only unsupported versions", "old_tls", "the client only offers TLS versions this port refuses (TLS 1.0/1.1)"},
	{"no cipher suite supported by both client and server", "no_cipher", "the client and this port share no cipher suite"},
	{"client didn't provide a certificate", "no_client_cert", "mutual TLS: the client sent no certificate"},
	{"failed to verify certificate", "client_cert_invalid", "mutual TLS: the client's certificate didn't verify against the port's client CA"},
	{"first record does not look like a TLS handshake", "not_tls", "the client is sending plaintext, not TLS"},
	{"connection reset by peer", "reset", "the client reset the connection during the handshake"},
	{"use of closed network connection", "closed", "the server closed the connection (shutting down)"},
}
