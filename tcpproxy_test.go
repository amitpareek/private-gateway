// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseDestinationTCPTargets(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    int
		wantErr string
	}{
		{"empty is allowed", "", 0, ""},
		{"whitespace is allowed", "   \n ", 0, ""},
		{"single entry", `[{"name":"mts","listen":9001,"target":"h.example.com:5671"}]`, 1, ""},
		{"two entries", `[{"name":"a","listen":9001,"target":"h:1"},{"name":"b","listen":9002,"target":"h:2"}]`, 2, ""},
		{"bad JSON", `[{`, 0, "invalid JSON"},
		{"empty name", `[{"name":"","listen":9001,"target":"h:1"}]`, 0, "empty name"},
		{"port zero", `[{"name":"a","listen":0,"target":"h:1"}]`, 0, "invalid listen port"},
		{"port too high", `[{"name":"a","listen":70000,"target":"h:1"}]`, 0, "invalid listen port"},
		{"target without port", `[{"name":"a","listen":9001,"target":"h.example.com"}]`, 0, "must be host:port"},
		{"duplicate name", `[{"name":"a","listen":9001,"target":"h:1"},{"name":"a","listen":9002,"target":"h:2"}]`, 0, "duplicate name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseDestinationTCPTargetsJSON(c.raw)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", c.wantErr)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != c.want {
				t.Fatalf("got %d entries, want %d", len(got), c.want)
			}
		})
	}
}

// TestValidateListenPorts covers the whole point of the unified table: a
// clash between *different* kinds of listener must be caught before any bind,
// naming both claimants, rather than surfacing later as a bare EADDRINUSE.
func TestValidateListenPorts(t *testing.T) {
	pg := func(name string, port int) upstreamConfig {
		return upstreamConfig{Name: name, Listen: port, Target: "up:5432"}
	}
	tcp := func(name string, port int) tcpTarget {
		return tcpTarget{Name: name, Listen: port, Target: "up:5671"}
	}

	cases := []struct {
		name      string
		pgs       []upstreamConfig
		tcps      []tcpTarget
		httpAddr  string
		debugPort int
		wantErr   []string // all must appear in the message
	}{
		{
			name:      "empty config is fine",
			httpAddr:  "[::]:8080",
			debugPort: 80,
		},
		{
			name:      "the live shape passes",
			pgs:       []upstreamConfig{pg("rw", 5432), pg("ro", 5433)},
			tcps:      []tcpTarget{tcp("mts", 9001)},
			httpAddr:  "[::]:8080",
			debugPort: 80,
		},
		{
			name:      "pg below its range",
			pgs:       []upstreamConfig{pg("rw", 5399)},
			httpAddr:  "[::]:8080",
			debugPort: 80,
			wantErr:   []string{`pg db "rw"`, "5399", "5400-6000"},
		},
		{
			name:      "pg above its range",
			pgs:       []upstreamConfig{pg("rw", 6001)},
			httpAddr:  "[::]:8080",
			debugPort: 80,
			wantErr:   []string{`pg db "rw"`, "6001", "5400-6000"},
		},
		{
			name:      "tcp below its range",
			tcps:      []tcpTarget{tcp("mts", 8999)},
			httpAddr:  "[::]:8080",
			debugPort: 80,
			wantErr:   []string{`tcp target "mts"`, "8999", "9000-9999"},
		},
		{
			name:      "tcp above its range",
			tcps:      []tcpTarget{tcp("mts", 10000)},
			httpAddr:  "[::]:8080",
			debugPort: 80,
			wantErr:   []string{`tcp target "mts"`, "10000", "9000-9999"},
		},
		{
			name:      "a pg entry on the CONNECT port is rejected by the range check",
			pgs:       []upstreamConfig{pg("rw", 8080)},
			httpAddr:  "[::]:8080",
			debugPort: 80,
			wantErr:   []string{`pg db "rw"`, "8080"},
		},
		{
			name:      "two tcp targets on one port name both",
			tcps:      []tcpTarget{tcp("mts", 9001), tcp("feed", 9001)},
			httpAddr:  "[::]:8080",
			debugPort: 80,
			wantErr:   []string{"9001", `tcp target "mts"`, `tcp target "feed"`},
		},
		{
			name:      "two pg entries on one port name both",
			pgs:       []upstreamConfig{pg("rw", 5432), pg("ro", 5432)},
			httpAddr:  "[::]:8080",
			debugPort: 80,
			wantErr:   []string{"5432", `pg db "rw"`, `pg db "ro"`},
		},
		{
			name:      "CONNECT proxy moved onto a tcp target's port",
			tcps:      []tcpTarget{tcp("mts", 9001)},
			httpAddr:  "[::]:9001",
			debugPort: 80,
			wantErr:   []string{"9001", `tcp target "mts"`, "CONNECT proxy"},
		},
		{
			name:      "debug port moved onto a pg entry's port",
			pgs:       []upstreamConfig{pg("rw", 5432)},
			httpAddr:  "[::]:8080",
			debugPort: 5432,
			wantErr:   []string{"5432", `pg db "rw"`, "debug/dev page"},
		},
		{
			name:      "debug port on the DNS forwarder's port",
			httpAddr:  "[::]:8080",
			debugPort: 53,
			wantErr:   []string{"53", "DNS forwarder", "debug/dev page"},
		},
		{
			name:      "CONNECT proxy disabled is not a claim",
			httpAddr:  "",
			debugPort: 80,
		},
		{
			name:      "malformed CONNECT address",
			httpAddr:  "not-an-address",
			debugPort: 80,
			wantErr:   []string{"--http-proxy-listen"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateListenPorts(c.pgs, c.tcps, c.httpAddr, c.debugPort)
			if len(c.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %v, got nil", c.wantErr)
			}
			for _, want := range c.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should mention %q", err, want)
				}
			}
		})
	}
}

// TestTCPProxyPipesBothDirections runs a real tcpProxy in front of a local
// echo server and checks bytes survive intact in both directions. The client
// dials over loopback, so the peer classifier must be satisfied first — see
// the note on withLoopbackTrusted.
func TestTCPProxyPipesBothDirections(t *testing.T) {
	upstream := newEchoServer(t)

	tp := newTCPProxy(tcpTarget{Name: "test", Listen: 0, Target: upstream})

	// Trust loopback *before* the serve goroutine exists, so the classifier
	// state is published to it rather than mutated underneath it. In
	// production these globals are set once from flags at startup, before
	// any listener runs; only a test can race them.
	restore := withLoopbackTrusted(t)

	ln := listenLoopback(t)
	go tp.Serve(ln)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("MTS ticket \x00\x01\x02 binary safe")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip corrupted the stream:\n got %q\nwant %q", got, payload)
	}

	if n := tp.startedSessions.Value(); n != 1 {
		t.Errorf("startedSessions = %d, want 1", n)
	}

	// Drain before restoring the globals: the handler has already passed
	// classifyPeer (the round trip proves it), so once it exits there is no
	// reader left to race the restore.
	c.Close()
	ln.Close()
	waitForIdle(t, tp)
	restore()
}

// waitForIdle blocks until no session is in flight, so a test can safely
// restore process-global state the handlers read.
func waitForIdle(t *testing.T, tp *tcpProxy) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tp.activeSessions.Value() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("sessions still active after 2s: %d", tp.activeSessions.Value())
}

// TestTCPProxyRejectsUntrustedSource is the security-relevant case: an
// unclassified peer must be dropped without the upstream ever being dialed.
func TestTCPProxyRejectsUntrustedSource(t *testing.T) {
	// A target that would fail loudly if it were ever dialed.
	tp := newTCPProxy(tcpTarget{Name: "test", Listen: 0, Target: "192.0.2.1:1"})
	ln := listenLoopback(t)
	go tp.Serve(ln)

	// No withLoopbackTrusted here: loopback classifies as peerReject.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("expected a clean close for a rejected peer, got %v", err)
	}
	if n := tp.startedSessions.Value(); n != 0 {
		t.Errorf("startedSessions = %d, want 0 — a rejected peer must not open a session", n)
	}
}

// newEchoServer starts a loopback echo server and returns its address.
func newEchoServer(t *testing.T) string {
	t.Helper()
	ln := listenLoopback(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// withLoopbackTrusted makes 127.0.0.0/8 classify as a trusted peer for the
// duration of a test, by pointing the Tailscale v4 range at loopback. That
// keeps the test honest about going through classifyPeer rather than
// bypassing it, without needing a real 6PN or tailnet address.
func withLoopbackTrusted(t *testing.T) func() {
	t.Helper()
	origPrefix := tailscaleV4
	origEnabled := *tailscaleEnabled
	tailscaleV4 = netip.MustParsePrefix("127.0.0.0/8")
	*tailscaleEnabled = true
	return func() {
		tailscaleV4 = origPrefix
		*tailscaleEnabled = origEnabled
	}
}
