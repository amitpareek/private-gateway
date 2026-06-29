// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The pgproxy server is a proxy for the Postgres wire protocol.
//
// This file is kept close to the upstream version at
// https://github.com/tailscale/tailscale/blob/main/cmd/pgproxy/pgproxy.go
// All Fly.io / application_name / HTTP-proxy customizations live in
// fly.go, credentials-manager.go, and httpproxy.go to make future
// upstream merges straightforward.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	debugPort  = flag.Int("debug-port", 80, "Listening port for the debug/metrics + dev page endpoint (Fly 6PN)")
	upstreamCA = flag.String("upstream-ca-file", "", "File containing the PEM-encoded CA certificate for the upstream server")
	// EXT: --port and --upstream-addr from upstream are replaced by
	// the repeatable --upstream flag declared in fly.go.
)

func main() {
	flag.Parse()
	if *upstreamCA == "" {
		log.Fatal("missing --upstream-ca-file")
	}

	// EXT BEGIN: debug listener + dev page, served over Fly 6PN. The
	// per-upstream proxy creation, Expvar publication, and connection
	// listeners are driven by runProxies in fly.go (one proxy per
	// configured database).
	var debugMux *http.ServeMux
	if *debugPort != 0 {
		debugMux = http.NewServeMux()
		debugMux.Handle("/debug/vars", expvar.Handler())
		srv := &http.Server{Handler: debugMux}
		dln, err := net.Listen("tcp", fmt.Sprintf(":%d", *debugPort))
		if err != nil {
			log.Fatal(err)
		}
		go func() { log.Fatal(srv.Serve(dln)) }()
	}

	runProxies(*upstreamCA, debugMux)
	select {}
	// EXT END
}

// proxy is a postgres wire protocol proxy, which strictly enforces
// the security of the TLS connection to its upstream regardless of
// what the client's TLS configuration is.
type proxy struct {
	upstreamAddr     string // "my.database.com:5432"
	upstreamHost     string // "my.database.com"
	upstreamCertPool *x509.CertPool
	downstreamCert   []tls.Certificate
	cfg              upstreamConfig // EXT: full entry; cfg.managed() picks the serve path

	activeSessions  expvar.Int
	startedSessions expvar.Int
	errors          *expvar.Map
}

// newProxy returns a proxy that forwards connections to
// upstreamAddr. The upstream's TLS session is verified using the CA
// cert(s) in upstreamCAPath.
func newProxy(upstreamAddr, upstreamCAPath string) (*proxy, error) {
	bs, err := os.ReadFile(upstreamCAPath)
	if err != nil {
		return nil, err
	}
	upstreamCertPool := x509.NewCertPool()
	if !upstreamCertPool.AppendCertsFromPEM(bs) {
		return nil, fmt.Errorf("invalid CA cert in %q", upstreamCAPath)
	}

	h, _, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		return nil, err
	}
	downstreamCert, err := mkSelfSigned(h)
	if err != nil {
		return nil, err
	}

	return &proxy{
		upstreamAddr:     upstreamAddr,
		upstreamHost:     h,
		upstreamCertPool: upstreamCertPool,
		downstreamCert:   []tls.Certificate{downstreamCert},
		errors:           new(expvar.Map),
	}, nil
}

// Expvar returns p's monitoring metrics.
func (p *proxy) Expvar() expvar.Var {
	ret := new(expvar.Map)
	ret.Set("sessions_active", &p.activeSessions)
	ret.Set("sessions_started", &p.startedSessions)
	ret.Set("session_errors", p.errors)
	return ret
}

// Serve accepts postgres client connections on ln and proxies them to
// the configured upstream. ln can be any net.Listener, but all client
// connections must originate from Fly 6PN addresses (see classifyPeer).
func (p *proxy) Serve(ln net.Listener) error {
	var lastSessionID int64
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		id := time.Now().UnixNano()
		if id == lastSessionID {
			// Bluntly enforce SID uniqueness, even if collisions are
			// fantastically unlikely (but OSes vary in how much timer
			// precision they expose to the OS, so id might be rounded
			// e.g. to the same millisecond)
			id++
		}
		lastSessionID = id
		go func(sessionID int64) {
			if err := p.serve(sessionID, c); err != nil {
				log.Printf("%d: session ended with error: %v", sessionID, err)
			}
		}(id)
	}
}

var (
	// sslStart is the magic bytes that postgres clients use to indicate
	// that they want to do a TLS handshake. Servers should respond with
	// the single byte "S" before starting a normal TLS handshake.
	sslStart = [8]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	// EXT: the fixed plaintextStart constant is replaced by
	// isPlaintextStartup (credentials-manager.go), which accepts any v3
	// StartupMessage length instead of exactly 86 bytes.
)

// serve proxies the postgres client on c to the proxy's upstream,
// enforcing strict TLS to the upstream.
func (p *proxy) serve(sessionID int64, c net.Conn) error {
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// EXT BEGIN: peer classification + identity (Fly 6PN PTR/TXT, or
	// Tailscale WhoIs). fromTS drives application_name appending below.
	user, machine, injectAppName, fromTS, err := p.identifyClient(ctx, c)
	if err != nil {
		return err
	}
	// EXT: per-db allow-list, Tailscale-only. Fly 6PN clients bypass it;
	// a Tailscale user must be on the entry's allow list (empty = anyone).
	if fromTS && !p.cfg.allows(user) {
		p.errors.Add("unauthorized-user", 1)
		return fmt.Errorf("tailscale user %q not allowed for db %q", user, p.cfg.Name)
	}
	// EXT END

	log.Printf("%d: session start, from %s (machine %s, user %s)", sessionID, c.RemoteAddr(), machine, user)
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		log.Printf("%d: session end, from %s (machine %s, user %s), lasted %s", sessionID, c.RemoteAddr(), machine, user, elapsed.Round(time.Millisecond))
	}()

	// EXT BEGIN: managed upstreams authenticate to the upstream with
	// configured credentials; everything below is the passthrough path.
	if p.cfg.managed() {
		return p.serveManaged(ctx, sessionID, c, injectAppName, fromTS)
	}
	// EXT END

	// Read the client's opening message, to figure out if it's trying
	// to TLS or not.
	var buf [8]byte
	if _, err := io.ReadFull(c, buf[:len(sslStart)]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("initial magic read: %v", err)
	}
	var clientIsTLS bool
	switch {
	case buf == sslStart:
		clientIsTLS = true
	case isPlaintextStartup(buf): // EXT: any v3 startup length
		clientIsTLS = false
	default:
		p.errors.Add("client-bad-protocol", 1)
		return fmt.Errorf("unrecognized initial packet = % 02x", buf)
	}

	// Dial & verify upstream connection.
	var d net.Dialer
	d.Timeout = 10 * time.Second
	upc, err := d.Dial("tcp", p.upstreamAddr)
	if err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("upstream dial: %v", err)
	}
	defer upc.Close()
	if _, err := upc.Write(sslStart[:]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("upstream write of start-ssl magic: %v", err)
	}
	if _, err := io.ReadFull(upc, buf[:1]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("reading upstream start-ssl response: %v", err)
	}
	if buf[0] != 'S' {
		p.errors.Add("upstream-bad-protocol", 1)
		return fmt.Errorf("upstream didn't acknowledge start-ssl, said %q", buf[0])
	}
	tlsConf := &tls.Config{
		ServerName: p.upstreamHost,
		RootCAs:    p.upstreamCertPool,
		MinVersion: tls.VersionTLS12,
	}
	uptc := tls.Client(upc, tlsConf)
	if err = uptc.HandshakeContext(ctx); err != nil {
		p.errors.Add("upstream-tls", 1)
		return fmt.Errorf("upstream TLS handshake: %v", err)
	}

	// Accept the client conn and set it up the way the client wants.
	var clientConn net.Conn
	if clientIsTLS {
		io.WriteString(c, "S") // yeah, we're good to speak TLS
		s := tls.Server(c, &tls.Config{
			ServerName:   p.upstreamHost,
			Certificates: p.downstreamCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err = s.HandshakeContext(ctx); err != nil {
			p.errors.Add("client-tls", 1)
			return fmt.Errorf("client TLS handshake: %v", err)
		}
		clientConn = s
	} else {
		// EXT: upstream now receives the rewritten StartupMessage from
		// forwardStartup below, so we no longer relay plaintextStart here.
		clientConn = c
	}

	// EXT BEGIN: read the client's Postgres StartupMessage, inject
	// application_name attribution if absent, and forward the rewritten
	// message to upstream before kicking off io.Copy.
	if !clientIsTLS {
		// The 8 bytes we already read in `buf` are the first 8 bytes
		// of the plaintext StartupMessage; reuse them.
		buf2 := buf // copy onto the stack for the prefix slice
		if err := p.forwardStartup(clientConn, uptc, injectAppName, buf2[:], true, fromTS); err != nil {
			return err
		}
	} else {
		if err := p.forwardStartup(clientConn, uptc, injectAppName, nil, false, fromTS); err != nil {
			return err
		}
	}
	// EXT END

	// Finally, proxy the client to the upstream.
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(uptc, clientConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, uptc)
		errc <- err
	}()
	if err := <-errc; err != nil {
		// Don't increment error counts here, because the most common
		// cause of termination is client or server closing the
		// connection normally, and it'll obscure "interesting"
		// handshake errors.
		return fmt.Errorf("session terminated with error: %v", err)
	}
	return nil
}

// mkSelfSigned creates and returns a self-signed TLS certificate for
// hostname.
func mkSelfSigned(hostname string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	pub := priv.Public()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"pgproxy"},
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(crand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        cert,
	}, nil
}
