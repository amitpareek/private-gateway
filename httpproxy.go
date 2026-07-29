// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"expvar"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// httpProxy is an HTTPS CONNECT forward proxy gated to Fly 6PN
// sources, plus tailnet sources when --http-proxy-allow-tailscale is
// set. It exists so other Fly apps can make outbound HTTPS
// requests through this binary's fixed Fly egress IP, e.g. to
// IP-allowlisted vendors.
//
// Why the tailnet needs an explicit opt-in: a tailnet client reaching
// us over the subnet route is SNATed to the router's 6PN address and so
// already classifies as peerFly. The ones this flag admits are those
// arriving at our Tailscale IP directly — which is where the DNS
// self-rewrite sends the bare <app>.internal name (see dnsIsSelf). So
// without the flag that name, the one the dev page hands out, gets a
// 403; qualified names such as <region>.<app>.internal still work
// unflagged, since they relay to 6PN and reach us over the subnet route.
type httpProxy struct {
	activeSessions  expvar.Int
	startedSessions expvar.Int
	errors          *expvar.Map
}

func newHTTPProxy() *httpProxy {
	return &httpProxy{errors: new(expvar.Map)}
}

// allowPeer reports whether a classified peer may use the proxy. Fly 6PN
// is always allowed; the tailnet only with --http-proxy-allow-tailscale.
func (h *httpProxy) allowPeer(k peerKind) bool {
	switch k {
	case peerFly:
		return true
	case peerTailscale:
		return *httpProxyAllowTailscale
	}
	return false
}

func (h *httpProxy) Expvar() expvar.Var {
	s := new(expvar.Map)
	s.Set("sessions_active", &h.activeSessions)
	s.Set("sessions_started", &h.startedSessions)
	s.Set("session_errors", h.errors)
	return s
}

func (h *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.allowPeer(classifyPeer(r.RemoteAddr)) {
		h.errors.Add("disallowed-source", 1)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodConnect {
		h.errors.Add("bad-method", 1)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		h.errors.Add("hijack-unsupported", 1)
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}

	dst, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		h.errors.Add("dial-failed", 1)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer dst.Close()

	src, _, err := hj.Hijack()
	if err != nil {
		h.errors.Add("hijack-failed", 1)
		return
	}
	defer src.Close()

	if _, err := src.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		h.errors.Add("network-error", 1)
		return
	}

	h.startedSessions.Add(1)
	h.activeSessions.Add(1)
	defer h.activeSessions.Add(-1)
	start := time.Now()
	log.Printf("http-proxy: CONNECT %s from %s", r.Host, r.RemoteAddr)
	defer func() {
		log.Printf("http-proxy: CONNECT %s from %s ended after %s", r.Host, r.RemoteAddr, time.Since(start).Round(time.Millisecond))
	}()

	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(dst, src)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(src, dst)
		errc <- err
	}()
	<-errc
}
