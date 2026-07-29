// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPProxyAllowPeer covers the source gate: Fly 6PN is always
// admitted, the tailnet only under --http-proxy-allow-tailscale, and
// everything else never.
func TestHTTPProxyAllowPeer(t *testing.T) {
	defer func(v bool) { *httpProxyAllowTailscale = v }(*httpProxyAllowTailscale)
	for _, tt := range []struct {
		kind    peerKind
		allowTS bool
		want    bool
	}{
		{peerFly, false, true},
		{peerFly, true, true},
		{peerTailscale, false, false},
		{peerTailscale, true, true},
		{peerReject, false, false},
		{peerReject, true, false}, // the flag must not admit untrusted sources
	} {
		defer func(v bool) { *httpProxyAllowTailscale = v }(*httpProxyAllowTailscale)
		*httpProxyAllowTailscale = tt.allowTS
		if got := newHTTPProxy().allowPeer(tt.kind); got != tt.want {
			t.Errorf("allowPeer(%v) with allow-tailscale=%v = %v, want %v",
				tt.kind, tt.allowTS, got, tt.want)
		}
	}
}

// TestHTTPProxyRejectsDisallowedSource checks the wire behavior a client
// sees — 403 with the "forbidden" body — and that the expvar counter moves.
func TestHTTPProxyRejectsDisallowedSource(t *testing.T) {
	defer func(v bool) { *httpProxyAllowTailscale = v }(*httpProxyAllowTailscale)
	*httpProxyAllowTailscale = false
	defer func(v bool) { *tailscaleEnabled = v }(*tailscaleEnabled)
	*tailscaleEnabled = true

	h := newHTTPProxy()
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	req.RemoteAddr = "100.64.1.2:54321" // tailnet, not opted in
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := h.errors.Get("disallowed-source"); got == nil || got.String() != "1" {
		t.Errorf("disallowed-source counter = %v, want 1", got)
	}
}

// TestHTTPProxyAllowedTailscalePeerPassesGate checks that an opted-in
// tailnet peer gets past the source gate. It stops at the method check
// rather than dialing out, which is enough to prove the gate opened.
func TestHTTPProxyAllowedTailscalePeerPassesGate(t *testing.T) {
	defer func(v bool) { *httpProxyAllowTailscale = v }(*httpProxyAllowTailscale)
	*httpProxyAllowTailscale = true
	defer func(v bool) { *tailscaleEnabled = v }(*tailscaleEnabled)
	*tailscaleEnabled = true

	h := newHTTPProxy()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "100.64.1.2:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d (gate should pass, method should fail)",
			rec.Code, http.StatusMethodNotAllowed)
	}
	if got := h.errors.Get("disallowed-source"); got != nil && got.String() != "0" {
		t.Errorf("disallowed-source counter = %v, want unset/0", got)
	}
}
