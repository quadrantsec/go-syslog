package syslog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	. "gopkg.in/check.v1"
)

// testPKI is a throwaway CA and one leaf certificate (CN and SAN
// "dummycert1"), used as both the server and the client certificate.
var testPKI = sync.OnceValue(func() struct {
	pool *x509.CertPool
	cert tls.Certificate
} {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-syslog test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "dummycert1"},
		DNSNames:     []string{"dummycert1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return struct {
		pool *x509.CertPool
		cert tls.Certificate
	}{pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
})

func getServerConfig() *tls.Config {
	pki := testPKI()
	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{pki.cert},
		ClientCAs:    pki.pool,
	}
}

func getClientConfig() *tls.Config {
	pki := testPKI()
	return &tls.Config{
		Certificates: []tls.Certificate{pki.cert},
		ServerName:   "dummycert1",
		RootCAs:      pki.pool,
	}
}

func (s *ServerSuite) TestTLS(c *C) {
	handler := new(HandlerMock)
	server := NewServer()
	server.SetFormat(RFC3164)
	server.SetHandler(handler)
	c.Assert(server.ListenTCPTLS("0.0.0.0:5143", getServerConfig()), IsNil)

	c.Assert(server.Boot(), IsNil)
	go func(server *Server) {
		time.Sleep(100 * time.Millisecond)
		conn, err := tls.Dial("tcp", "127.0.0.1:5143", getClientConfig())
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		if _, err := io.WriteString(conn, fmt.Sprintf("%s\n", exampleSyslog)); err != nil {
			panic(err)
		}
		// Kill closes open connections, so give the message time to arrive.
		time.Sleep(200 * time.Millisecond)
		_ = server.Kill()
	}(server)
	server.Wait()

	c.Check(handler.LastLogParts["hostname"], Equals, "hostname")
	c.Check(handler.LastLogParts["tag"], Equals, "tag")
	c.Check(handler.LastLogParts["content"], Equals, "content")
	c.Check(handler.LastLogParts["tls_peer"], Equals, "dummycert1")
	c.Check(handler.LastMessageLength, Equals, int64(len(exampleSyslog)))
	c.Check(handler.LastError, IsNil)
}
