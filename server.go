package syslog

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"gopkg.in/mcuadros/go-syslog.v2/format"
)

var (
	RFC3164   = &format.RFC3164{}   // RFC3164: http://www.ietf.org/rfc/rfc3164.txt
	RFC5424   = &format.RFC5424{}   // RFC5424: http://www.ietf.org/rfc/rfc5424.txt
	RFC6587   = &format.RFC6587{}   // RFC6587: http://www.ietf.org/rfc/rfc6587.txt - octet counting variant
	Automatic = &format.Automatic{} // Automatically identify the format
)

const (
	datagramChannelBufferSize = 10
	datagramReadBufferSize    = 64 * 1024

	// DefaultHandshakeTimeout bounds the TLS handshake. A peer that connects
	// and never sends a ClientHello must not hold a goroutine forever.
	DefaultHandshakeTimeout = 10 * time.Second

	maxAcceptBackoff = time.Second
)

// A function type which gets the TLS peer name from the connection. Can return
// ok=false to terminate the connection
type TlsPeerNameFunc func(tlsConn *tls.Conn) (tlsPeer string, ok bool)

type Server struct {
	listeners               []net.Listener
	connections             []net.PacketConn
	wait                    sync.WaitGroup
	doneTcp                 chan bool
	datagramChannelSize     int
	datagramChannel         chan DatagramMessage
	format                  format.Format
	fallbackFormat          format.Format
	handler                 Handler
	lastErrorMu             sync.Mutex
	lastError               error
	readTimeoutMilliseconds int64
	handshakeTimeout        time.Duration
	maxFrameSize            int
	tlsPeerNameFunc         TlsPeerNameFunc
	datagramPool            sync.Pool

	// Open stream connections, so Kill can close them. Without this, Wait
	// blocks until every peer disconnects on its own.
	connsMu  sync.Mutex
	conns    map[net.Conn]struct{}
	stopping bool
	killOnce sync.Once
}

// NewServer returns a new Server
func NewServer() *Server {
	return &Server{tlsPeerNameFunc: defaultTlsPeerName, datagramPool: sync.Pool{
		New: func() any {
			buf := make([]byte, 65536)
			return &buf
		},
	},

		datagramChannelSize: datagramChannelBufferSize,
		handshakeTimeout:    DefaultHandshakeTimeout,
		maxFrameSize:        DefaultMaxFrameSize,
		conns:               make(map[net.Conn]struct{}),
	}
}

// Sets the syslog format (RFC3164 or RFC5424 or RFC6587)
func (s *Server) SetFormat(f format.Format) {
	s.format = f
}

// Sets a format to retry with when a message doesn't parse in the main
// format, for example Automatic behind RFC5424 so an RFC 3164 sender on an
// RFC 5424 port is still delivered instead of failing to parse.
func (s *Server) SetFallbackFormat(f format.Format) {
	s.fallbackFormat = f
}

// Sets the handler, this handler with receive every syslog entry
func (s *Server) SetHandler(handler Handler) {
	s.handler = handler
}

// Sets the connection timeout for TCP connections, in milliseconds
func (s *Server) SetTimeout(millseconds int64) {
	s.readTimeoutMilliseconds = millseconds
}

// Sets how long a TLS client gets to complete its handshake. Zero disables the
// limit.
func (s *Server) SetHandshakeTimeout(d time.Duration) {
	s.handshakeTimeout = d
}

// Sets the largest syslog message accepted on a stream connection, in bytes.
// Longer messages are truncated (non-transparent framing) or dropped (octet
// counting).
func (s *Server) SetMaxFrameSize(n int) {
	s.maxFrameSize = n
}

// Set the function that extracts a TLS peer name from the TLS connection
func (s *Server) SetTlsPeerNameFunc(tlsPeerNameFunc TlsPeerNameFunc) {
	s.tlsPeerNameFunc = tlsPeerNameFunc
}

func (s *Server) SetDatagramChannelSize(size int) {
	s.datagramChannelSize = size
}

// Default TLS peer name function - returns the CN of the certificate
func defaultTlsPeerName(tlsConn *tls.Conn) (tlsPeer string, ok bool) {
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) <= 0 {
		return "", true
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	return cn, true
}

// Configure the server for listen on an UDP addr
func (s *Server) ListenUDP(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	connection, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	_ = connection.SetReadBuffer(datagramReadBufferSize)

	s.connections = append(s.connections, connection)
	return nil
}

// Configure the server for listen on an unix socket
func (s *Server) ListenUnixgram(addr string) error {
	unixAddr, err := net.ResolveUnixAddr("unixgram", addr)
	if err != nil {
		return err
	}

	connection, err := net.ListenUnixgram("unixgram", unixAddr)
	if err != nil {
		return err
	}
	_ = connection.SetReadBuffer(datagramReadBufferSize)

	s.connections = append(s.connections, connection)
	return nil
}

// Configure the server for listen on a TCP addr
func (s *Server) ListenTCP(addr string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	s.doneTcp = make(chan bool)
	s.listeners = append(s.listeners, listener)
	return nil
}

// Configure the server for listen on a TCP addr for TLS
func (s *Server) ListenTCPTLS(addr string, config *tls.Config) error {
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}

	s.doneTcp = make(chan bool)
	s.listeners = append(s.listeners, listener)
	return nil
}

// Starts the server, all the go routines goes to live
func (s *Server) Boot() error {
	if s.format == nil {
		return errors.New("please set a valid format")
	}

	if s.handler == nil {
		return errors.New("please set a valid handler")
	}

	for _, listener := range s.listeners {
		s.goAcceptConnection(listener)
	}

	if len(s.connections) > 0 {
		s.goParseDatagrams()
	}

	for _, connection := range s.connections {
		s.goReceiveDatagrams(connection)
	}

	return nil
}

func (s *Server) goAcceptConnection(listener net.Listener) {
	s.wait.Go(func() {
		var backoff time.Duration
		for {
			connection, err := listener.Accept()
			if err != nil {
				if s.isStopping() || errors.Is(err, net.ErrClosed) {
					return
				}
				// Usually a temporary error such as too many open files.
				// Back off instead of spinning on it.
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else if backoff *= 2; backoff > maxAcceptBackoff {
					backoff = maxAcceptBackoff
				}
				log.Printf("Failed to accept connection, "+
					"proto=%s, addr=%s, error=%v",
					listener.Addr().Network(), listener.Addr(), err,
				)
				time.Sleep(backoff)
				continue
			}
			backoff = 0
			log.Printf("Accepted connection, proto=%s, remote=%s, local=%s",
				listener.Addr().Network(), connection.RemoteAddr(), connection.LocalAddr(),
			)

			// Handshake and read on the connection's own goroutine. Doing
			// the handshake here would block Accept for every other
			// connection on the listener until this peer spoke.
			s.wait.Go(func() { s.goReadConnection(connection) })
		}
	})
}

func (s *Server) goReadConnection(connection net.Conn) {
	if !s.trackConn(connection) {
		connection.Close()
		return
	}
	reader := bufio.NewReader(connection)

	remoteAddr := connection.RemoteAddr()
	var client string
	if remoteAddr != nil {
		client = remoteAddr.String()
	}

	tlsPeer := ""
	if tlsConn, ok := connection.(*tls.Conn); ok {
		// Handshake now so we get the TLS peer information. Bound it, then
		// clear the deadline so the syslog read gets the read timeout.
		if s.handshakeTimeout > 0 {
			_ = tlsConn.SetDeadline(time.Now().Add(s.handshakeTimeout))
		}
		err := tlsConn.Handshake()
		_ = tlsConn.SetDeadline(time.Time{})
		if err != nil {
			log.Printf("Failed to complete TLS handshake, closing connection, "+
				"remote=%s, local=%s, error=%v",
				tlsConn.RemoteAddr(), tlsConn.LocalAddr(), err,
			)
			s.untrackConn(connection)
			connection.Close()
			return
		}
		log.Printf("TLS handshake complete, remote=%s, local=%s",
			tlsConn.RemoteAddr(), tlsConn.LocalAddr(),
		)
		if s.tlsPeerNameFunc != nil {
			var ok bool
			tlsPeer, ok = s.tlsPeerNameFunc(tlsConn)
			if !ok {
				log.Printf("Failed to get TLS peer name, closing connection, "+
					"remote=%s, local=%s", tlsConn.RemoteAddr(), tlsConn.LocalAddr(),
				)
				s.untrackConn(connection)
				connection.Close()
				return
			}
		}
	}

	readCloser := &ReadCloser{reader, connection}

	s.wait.Add(1)
	go s.read(readCloser, client, tlsPeer)
}

func (s *Server) read(readCloser *ReadCloser, client string, tlsPeer string) {
	defer s.wait.Done()
	conn, _ := readCloser.closer.(net.Conn)
	frames := newFrameReader(readCloser.Reader, s.maxFrameSize)
	frames.logf = func(format string, args ...any) {
		log.Printf(format+", remote=%s, local=%s", append(args, connAddrs(conn)...)...)
	}
	for !s.isStopping() {
		if s.readTimeoutMilliseconds > 0 {
			_ = readCloser.closer.SetReadDeadline(time.Now().Add(time.Duration(s.readTimeoutMilliseconds) * time.Millisecond))
		}
		msg, err := frames.next()
		if len(msg) > 0 {
			s.parser(msg, client, tlsPeer)
		}
		// Stop reading on error
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Println("EOF when reading token")
			} else {
				log.Printf("Error when reading token: %v", err)
			}
			break
		}
	}
	// Close connection
	if conn != nil {
		s.untrackConn(conn)
		addrs := connAddrs(conn)
		log.Printf("Closing connection, proto=%s, remote=%s, local=%s",
			connNetwork(conn), addrs[0], addrs[1],
		)
	}
	readCloser.closer.Close()
}

// connAddrs returns the remote and local address of conn, tolerating nil.
func connAddrs(conn net.Conn) []any {
	var remote, local any = "", ""
	if conn != nil {
		if a := conn.RemoteAddr(); a != nil {
			remote = a
		}
		if a := conn.LocalAddr(); a != nil {
			local = a
		}
	}
	return []any{remote, local}
}

func connNetwork(conn net.Conn) string {
	if conn != nil {
		if a := conn.LocalAddr(); a != nil {
			return a.Network()
		}
	}
	return ""
}

// trackConn records an open connection. It returns false once the server is
// stopping, and the caller must close the connection.
func (s *Server) trackConn(conn net.Conn) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.stopping {
		return false
	}
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	delete(s.conns, conn)
}

func (s *Server) isStopping() bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	return s.stopping
}

// closeConns marks the server as stopping and closes every open connection.
func (s *Server) closeConns() {
	s.connsMu.Lock()
	s.stopping = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.connsMu.Unlock()
	for _, conn := range conns {
		// Close the socket under TLS directly: tls.Conn.Close first writes
		// a close_notify alert, which can wait on a peer that isn't reading.
		// The read goroutine then fails and runs its own cleanup.
		if tlsConn, ok := conn.(*tls.Conn); ok {
			tlsConn.NetConn().Close()
			continue
		}
		conn.Close()
	}
}

func (s *Server) parser(line []byte, client string, tlsPeer string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic when parsing syslog entry, "+
				"entry=%s, error=%v",
				string(line), r,
			)
		}
	}()
	used := s.format
	parser := used.GetParser(line)
	err := parser.Parse()
	if err != nil && s.fallbackFormat != nil {
		if fallback := s.fallbackFormat.GetParser(line); fallback.Parse() == nil {
			used, parser, err = s.fallbackFormat, fallback, nil
		}
	}
	if err != nil {
		s.lastErrorMu.Lock()
		s.lastError = err
		s.lastErrorMu.Unlock()
	}

	logParts := parser.Dump()
	logParts["client"] = client
	if logParts["hostname"] == "" && (used == RFC3164 || used == Automatic) {
		if i := strings.Index(client, ":"); i > 1 {
			logParts["hostname"] = client[:i]
		} else {
			logParts["hostname"] = client
		}
	}
	logParts["tls_peer"] = tlsPeer

	s.handler.Handle(logParts, int64(len(line)), err)
}

// Returns the last error
func (s *Server) GetLastError() error {
	s.lastErrorMu.Lock()
	defer s.lastErrorMu.Unlock()
	return s.lastError
}

// Kill the server
func (s *Server) Kill() error {
	var firstErr error
	s.killOnce.Do(func() {
		// Mark stopping first, so a connection accepted while the
		// listeners close is refused instead of left open.
		s.closeConns()
		for _, connection := range s.connections {
			if err := connection.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		for _, listener := range s.listeners {
			if err := listener.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		// Only need to close channel once to broadcast to all waiting
		if s.doneTcp != nil {
			close(s.doneTcp)
		}
		if s.datagramChannel != nil {
			close(s.datagramChannel)
		}
	})
	return firstErr
}

// Waits until the server stops
func (s *Server) Wait() {
	s.wait.Wait()
}

type TimeoutCloser interface {
	Close() error
	SetReadDeadline(t time.Time) error
}

type ReadCloser struct {
	*bufio.Reader
	closer TimeoutCloser
}

type DatagramMessage struct {
	message []byte
	client  string
}

func (s *Server) goReceiveDatagrams(packetconn net.PacketConn) {
	s.wait.Go(func() {
		for {
			buf := *s.datagramPool.Get().(*[]byte)
			n, addr, err := packetconn.ReadFrom(buf)
			if err == nil {
				// Ignore trailing control characters and NULs
				for ; (n > 0) && (buf[n-1] < 32); n-- {
				}
				if n > 0 {
					var address string
					if addr != nil {
						address = addr.String()
					}
					s.datagramChannel <- DatagramMessage{buf[:n], address}
				}
			} else {
				// there has been an error. Either the server has been killed
				// or may be getting a transitory error due to (e.g.) the
				// interface being shutdown in which case sleep() to avoid busy wait.
				var opError *net.OpError
				if errors.As(err, &opError) && !opError.Temporary() && !opError.Timeout() {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	})
}

func (s *Server) goParseDatagrams() {
	s.datagramChannel = make(chan DatagramMessage, s.datagramChannelSize)

	s.wait.Go(func() {
		for msg := range s.datagramChannel {
			if sf := s.format.GetSplitFunc(); sf != nil {
				if _, token, err := sf(msg.message, true); err == nil {
					s.parser(token, msg.client, "")
				}
			} else {
				s.parser(msg.message, msg.client, "")
			}
			buf := msg.message[:cap(msg.message)]
			s.datagramPool.Put(&buf)
		}
	})
}
