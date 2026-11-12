package syslog

import (
	"net"
	"net/netip"

	proxyproto "github.com/pires/go-proxyproto"
)

// SetProxyProtocol accepts a PROXY protocol (v1 or v2) header on stream
// listeners, from the trusted addresses only, so a server behind a TCP proxy
// can see each client's address. Set it before ListenTCP or ListenTCPTLS.
//
//   - From a trusted address, the header is optional: connections without one
//     are handled as before, so the proxy can start sending it at any time.
//   - From any other address, a connection that sends a header is refused:
//     the header could claim any client address, and nothing else may
//     authenticate the sender.
//
// The client's address goes into ConnInfo.Source only. The stored client
// field, the RFC 3164 hostname fill and the log lines' remote address keep
// the TCP peer. Empty trusted turns it off.
func (s *Server) SetProxyProtocol(trusted []netip.Prefix) {
	s.proxyTrusted = trusted
}

// proxyListener wraps l to read PROXY headers, if SetProxyProtocol is on.
func (s *Server) proxyListener(l net.Listener) net.Listener {
	if len(s.proxyTrusted) == 0 {
		return l
	}
	timeout := s.handshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	return &proxyproto.Listener{
		Listener:          l,
		ConnPolicy:        s.proxyPolicy,
		ReadHeaderTimeout: timeout,
	}
}

// proxyPolicy uses the header from a trusted address, and refuses one from
// anywhere else.
func (s *Server) proxyPolicy(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
	if s.trustedProxy(opts.Upstream) {
		return proxyproto.USE, nil
	}
	return proxyproto.REJECT, nil
}

func (s *Server) trustedProxy(a net.Addr) bool {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	for _, p := range s.proxyTrusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// proxySource reads the client's address from a trusted PROXY header, or
// returns nil. It reads the header if nothing has yet, bounded by the
// listener's header timeout, so call it on the connection's goroutine.
func proxySource(conn net.Conn) net.Addr {
	p := proxyConn(conn)
	if p == nil {
		return nil
	}
	h := p.ProxyHeader()
	if h == nil || h.Command.IsLocal() || h.SourceAddr == nil {
		return nil
	}
	return h.SourceAddr
}
