package syslog

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

var osStderr = os.Stderr

var (
	loopback   = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	elsewhere  = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
	deviceAddr = &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4444}
	listenAddr = &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 10014}
)

// dialProxied connects to addr, sends a PROXY header of the given version
// (0 for none) claiming deviceAddr, and then starts TLS.
func dialProxied(t *testing.T, addr string, version byte) (*tls.Conn, net.Conn, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		hdr := &proxyproto.Header{
			Version:           version,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        deviceAddr,
			DestinationAddr:   listenAddr,
		}
		if _, err := hdr.WriteTo(raw); err != nil {
			t.Fatal(err)
		}
	}
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	conn := tls.Client(raw, getClientConfig())
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, raw, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, raw, nil
}

// Behind a trusted proxy the client's address reaches ConnInfo, but the
// stored client field and the RFC 3164 hostname fill keep the TCP peer.
func TestProxyHeaderFromTrustedProxy(t *testing.T) {
	for _, version := range []byte{1, 2} {
		infos := newInfoLog()
		h := newCollectHandler()
		server, addr := startTLSServer(t, RFC3164, h, func(s *Server) {
			s.SetConnHook(infos.hook)
			s.SetProxyProtocol(loopback)
		})
		conn, raw, err := dialProxied(t, addr, version)
		if err != nil {
			t.Fatalf("v%d: handshake behind a trusted proxy: %v", version, err)
		}
		if _, err := io.WriteString(conn, "<166>%FTD-6-430003: test\n"); err != nil {
			t.Fatal(err)
		}
		lp := h.wait(t, 3*time.Second)
		peer := raw.LocalAddr().String()
		if lp["client"] != peer || lp["hostname"] != "127.0.0.1" {
			t.Errorf("v%d: stored client %q, hostname %q; want the TCP peer %s", version, lp["client"], lp["hostname"], peer)
		}
		conn.Close()
		s := infos.waitClosed(t)
		if !s.Proxied || s.Source != deviceAddr.String() || s.Peer != peer {
			t.Errorf("v%d: source %s, peer %s, proxied %v; want source %s via %s", version, s.Source, s.Peer, s.Proxied, deviceAddr, peer)
		}
		stop(t, server)
	}
}

// A trusted proxy may send no header: the proxy can start sending it later.
func TestNoProxyHeaderFromTrustedProxy(t *testing.T) {
	infos := newInfoLog()
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h, func(s *Server) {
		s.SetConnHook(infos.hook)
		s.SetProxyProtocol(loopback)
	})
	defer stop(t, server)
	conn, raw, err := dialProxied(t, addr, 0)
	if err != nil {
		t.Fatalf("plain TLS through a PROXY-enabled listener: %v", err)
	}
	if _, err := io.WriteString(conn, octet(sampleFortiGate1)); err != nil {
		t.Fatal(err)
	}
	h.wait(t, 3*time.Second)
	conn.Close()
	if s := infos.waitClosed(t); s.Proxied || s.Source != raw.LocalAddr().String() {
		t.Errorf("source %s, proxied %v; want the TCP peer", s.Source, s.Proxied)
	}
}

// One-way TLS authenticates nothing about the sender, so a PROXY header from
// anyone but the trusted proxy could claim any address: it's refused.
func TestForgedProxyHeaderIsRefused(t *testing.T) {
	infos := newInfoLog()
	failed := make(chan error, 1)
	h := newCollectHandler()
	server, addr := startTLSServer(t, RFC5424, h, func(s *Server) {
		s.SetProxyProtocol(elsewhere) // 127.0.0.1 isn't trusted
		s.SetConnHook(func(ev ConnEvent, info *ConnInfo, err error) {
			if ev == ConnHandshakeFailed {
				failed <- err
			}
			infos.hook(ev, info, err)
		})
	})
	defer stop(t, server)

	if conn, _, err := dialProxied(t, addr, 2); err == nil {
		conn.Close()
		t.Fatal("handshake succeeded with a forged PROXY header from an untrusted address")
	}
	select {
	case err := <-failed:
		if reason, _ := HandshakeFailure(err); reason != "untrusted_proxy_header" {
			t.Errorf("reason %q for %v, want untrusted_proxy_header", reason, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no handshake failure reported")
	}
	if s := infos.waitClosed(t); s.Proxied || s.Source == deviceAddr.String() {
		t.Errorf("forged address reached ConnInfo: source %s", s.Source)
	}
	select {
	case lp := <-h.ch:
		t.Errorf("a message got through: %v", lp)
	default:
	}

	// Without a header, the same untrusted client is served as before.
	conn, _, err := dialProxied(t, addr, 0)
	if err != nil {
		t.Fatalf("plain TLS from an untrusted address: %v", err)
	}
	conn.Close()
}
