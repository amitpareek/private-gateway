// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"expvar"
	"io"
	"log"
	"net"
	"time"
)

// tcpProxy forwards raw TCP from a Fly 6PN (or tailnet) listener to one
// fixed upstream, byte for byte. It exists for upstreams that are neither
// Postgres nor HTTP and that are IP-allowlisted to this app's fixed Fly
// egress IP — Sportradar MTS (AMQP over TLS) being the first.
//
// It is deliberately dumb. Unlike the Postgres proxy it parses nothing,
// injects nothing, and terminates no TLS: the client's handshake reaches the
// real upstream and the real upstream's certificate comes back, so end-to-end
// TLS is preserved and this proxy needs no certificate of its own. A client
// pointed at <gateway>:<listen> must therefore verify the upstream's real
// hostname rather than the address it dialed (for the MTS .NET SDK that is
// SetSslServerName).
//
// A raw TCP stream carries no destination metadata, so routing is by listen
// port: one listener, one target. Multiplexing several upstreams onto one
// port would need TLS SNI sniffing or SOCKS5; neither is worth it until two
// targets actually collide on a port.
type tcpProxy struct {
	cfg tcpTarget

	activeSessions  expvar.Int
	startedSessions expvar.Int
	errors          *expvar.Map
}

func newTCPProxy(cfg tcpTarget) *tcpProxy {
	return &tcpProxy{cfg: cfg, errors: new(expvar.Map)}
}

func (t *tcpProxy) Expvar() expvar.Var {
	s := new(expvar.Map)
	s.Set("sessions_active", &t.activeSessions)
	s.Set("sessions_started", &t.startedSessions)
	s.Set("session_errors", t.errors)
	return s
}

// tcpDialTimeout bounds only the connection setup to the upstream. There is
// deliberately no idle or overall deadline: MTS feed and ticket connections
// are long-lived and sit idle between bets, so any idle timeout here would
// drop them mid-session.
const tcpDialTimeout = 10 * time.Second

// tcpKeepAlive is set on both legs so a peer that vanishes without a FIN
// (a machine going away, a NAT dropping state) is eventually noticed on an
// otherwise idle connection.
const tcpKeepAlive = 30 * time.Second

// Serve accepts connections on ln and pipes each to the configured target.
// Source gating matches the Postgres listeners: Fly 6PN always, the tailnet
// when Tailscale is enabled (see classifyPeer).
func (t *tcpProxy) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go t.handle(c)
	}
}

func (t *tcpProxy) handle(src net.Conn) {
	defer src.Close()

	remote := src.RemoteAddr().String()
	if classifyPeer(remote) == peerReject {
		t.errors.Add("disallowed-source", 1)
		log.Printf("tcp %q: rejected connection from %s", t.cfg.Name, remote)
		return
	}

	dialer := &net.Dialer{Timeout: tcpDialTimeout, KeepAlive: tcpKeepAlive}
	dst, err := dialer.Dial("tcp", t.cfg.Target)
	if err != nil {
		t.errors.Add("dial-failed", 1)
		log.Printf("tcp %q: dial %s: %v", t.cfg.Name, t.cfg.Target, err)
		return
	}
	defer dst.Close()

	setKeepAlive(src)

	t.startedSessions.Add(1)
	t.activeSessions.Add(1)
	defer t.activeSessions.Add(-1)
	start := time.Now()
	log.Printf("tcp %q: %s -> %s", t.cfg.Name, remote, t.cfg.Target)
	defer func() {
		log.Printf("tcp %q: %s -> %s ended after %s", t.cfg.Name, remote, t.cfg.Target, time.Since(start).Round(time.Millisecond))
	}()

	// Whichever direction ends first tears down both, as in httpproxy.go.
	// Nothing in scope relies on TCP half-close.
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(dst, src)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(src, dst)
		errc <- err
	}()
	if err := <-errc; err != nil {
		t.errors.Add("network-error", 1)
	}
}

// setKeepAlive enables TCP keepalives on an accepted connection. The dialer
// handles the upstream leg; this covers the client leg.
func setKeepAlive(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tc.SetKeepAlive(true); err != nil {
		return
	}
	tc.SetKeepAlivePeriod(tcpKeepAlive)
}
