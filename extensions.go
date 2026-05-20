// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// extensions.go contains the Fly.io + application_name attribution
// changes layered on top of upstream pgproxy. Keeping them out of
// pgproxy.go makes upstream merges straightforward; pgproxy.go itself
// is left as close to tailscale.com/cmd/pgproxy/pgproxy.go as
// possible, with a handful of clearly-marked `EXT` hooks.
//
// Added flags (declared below):
//
//	--fly-listen         Kernel TCP listen address for Fly 6PN Postgres
//	                     clients. Default "[::]:5432". Empty disables.
//	--http-proxy-listen  Kernel TCP listen address for the HTTPS CONNECT
//	                     forward proxy. Default "[::]:8080". Empty disables.
//	                     Source-IP gated to Fly 6PN regardless of bind.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var (
	flyListen       = flag.String("fly-listen", "[::]:5432", "Kernel TCP listen address for Fly 6PN Postgres clients. Empty disables.")
	httpProxyListen = flag.String("http-proxy-listen", "[::]:8080", "Kernel TCP listen address for the HTTPS CONNECT forward proxy. Empty disables.")
)

// startExtensions brings up the kernel-side listeners that the
// upstream pgproxy does not provide: the Fly 6PN PG listener and the
// HTTP CONNECT forward proxy. Source-IP classification (see
// classifyPeer) is the actual access control on both.
func startExtensions(p *proxy) {
	if *flyListen != "" {
		ln, err := net.Listen("tcp", *flyListen)
		if err != nil {
			log.Fatalf("listening on %s: %v", *flyListen, err)
		}
		log.Printf("serving Fly 6PN access to %s on %s", *upstreamAddr, *flyListen)
		go func() { log.Fatal(p.Serve(ln)) }()
	}
	if *httpProxyListen != "" {
		hp := newHTTPProxy()
		expvar.Publish("http_proxy", hp.Expvar())
		ln, err := net.Listen("tcp", *httpProxyListen)
		if err != nil {
			log.Fatalf("listening on %s: %v", *httpProxyListen, err)
		}
		srv := &http.Server{Handler: hp}
		log.Printf("serving HTTP CONNECT proxy on %s", *httpProxyListen)
		go func() { log.Fatal(srv.Serve(ln)) }()
	}
}

// peerKind classifies the source of an inbound connection.
type peerKind int

const (
	peerReject peerKind = iota
	peerTailscale
	peerFly
)

func (k peerKind) String() string {
	switch k {
	case peerTailscale:
		return "tailscale"
	case peerFly:
		return "fly"
	default:
		return "reject"
	}
}

var (
	flyPrefix   = netip.MustParsePrefix("fdaa::/16")
	tailscaleV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// classifyPeer returns the peerKind for a remote address string of
// the form "host:port" or "[ipv6]:port".
func classifyPeer(remote string) peerKind {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return peerReject
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return peerReject
	}
	ip = ip.Unmap()
	switch {
	case flyPrefix.Contains(ip):
		return peerFly
	case tailscaleV4.Contains(ip), tailscaleV6.Contains(ip):
		return peerTailscale
	}
	return peerReject
}

// identifyClient resolves the peer identity and returns the strings
// to log plus the application_name to inject. For Tailscale peers
// the implementation mirrors upstream pgproxy's WhoIs flow; for Fly
// 6PN peers it does PTR + TXT lookups (see lookupFlyIdent).
func (p *proxy) identifyClient(ctx context.Context, c net.Conn) (user, machine, appName string, err error) {
	switch classifyPeer(c.RemoteAddr().String()) {
	case peerTailscale:
		whois, werr := p.client.WhoIs(ctx, c.RemoteAddr().String())
		if werr != nil {
			p.errors.Add("whois-failed", 1)
			return "", "", "", fmt.Errorf("getting client identity: %v", werr)
		}
		if whois.Node != nil {
			if whois.Node.Hostinfo.ShareeNode() {
				machine = "external-device"
			} else {
				machine = strings.TrimSuffix(whois.Node.Name, ".")
			}
		}
		if whois.UserProfile != nil {
			user = whois.UserProfile.LoginName
			if user == "tagged-devices" && whois.Node != nil {
				user = strings.Join(whois.Node.Tags, ",")
			}
		}
		if user == "" || machine == "" {
			p.errors.Add("no-ts-identity", 1)
			return "", "", "", fmt.Errorf("couldn't identify source user and machine (user %q, machine %q)", user, machine)
		}
		return user, machine, user, nil
	case peerFly:
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		ip, _ := netip.ParseAddr(host)
		ident := lookupFlyIdent(ctx, ip)
		return ident, "fly", ident, nil
	default:
		p.errors.Add("disallowed-source", 1)
		return "", "", "", fmt.Errorf("rejecting connection from disallowed source %s", c.RemoteAddr())
	}
}

// forwardStartup reads the Postgres StartupMessage from the client
// side, injects application_name (if absent) using injectAppName,
// and writes the rewritten message to upstream.
//
// In the plaintext path the first 8 bytes of the message have already
// been consumed for protocol detection; pass them in via prefix with
// hadPrefix=true. In the TLS path the message is read fresh.
func (p *proxy) forwardStartup(clientConn io.Reader, upstream io.Writer, injectAppName string, prefix []byte, hadPrefix bool) error {
	var raw []byte
	var err error
	if hadPrefix {
		raw, err = readStartupMessageWithPrefix(clientConn, prefix)
	} else {
		raw, err = readStartupMessage(clientConn)
	}
	if err != nil {
		p.errors.Add("bad-startup", 1)
		return fmt.Errorf("reading client startup: %v", err)
	}
	out, err := rewriteStartup(raw, injectAppName)
	if err != nil {
		p.errors.Add("bad-startup", 1)
		return fmt.Errorf("rewriting client startup: %v", err)
	}
	if _, err := upstream.Write(out); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("forwarding rewritten startup: %v", err)
	}
	return nil
}

// readStartupMessage reads a length-prefixed Postgres StartupMessage
// (or CancelRequest) from r and returns the full message bytes.
func readStartupMessage(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	return readStartupMessageWithPrefix(r, lenBuf[:])
}

// readStartupMessageWithPrefix is like readStartupMessage but uses
// prefix as the first bytes already read from the stream.
func readStartupMessageWithPrefix(r io.Reader, prefix []byte) ([]byte, error) {
	if len(prefix) < 4 {
		return nil, fmt.Errorf("prefix too short")
	}
	length := int(binary.BigEndian.Uint32(prefix[:4]))
	if length < 8 || length > 65536 {
		return nil, fmt.Errorf("startup length out of range: %d", length)
	}
	out := make([]byte, length)
	n := copy(out, prefix)
	if n > length {
		return nil, fmt.Errorf("prefix longer than message")
	}
	if _, err := io.ReadFull(r, out[n:]); err != nil {
		return nil, err
	}
	return out, nil
}

const pgProtoV3 = uint32(0x00030000)

// rewriteStartup parses a Postgres StartupMessage and, if it is a
// protocol-3 startup that does not already carry application_name,
// appends application_name=injectAppName. Non-v3 messages (e.g.
// CancelRequest) and v3 messages that already include
// application_name are returned unchanged.
func rewriteStartup(raw []byte, injectAppName string) ([]byte, error) {
	if len(raw) < 8 {
		return nil, fmt.Errorf("startup too short: %d", len(raw))
	}
	length := int(binary.BigEndian.Uint32(raw[:4]))
	if length != len(raw) {
		return nil, fmt.Errorf("startup length mismatch: header=%d actual=%d", length, len(raw))
	}
	proto := binary.BigEndian.Uint32(raw[4:8])
	if proto != pgProtoV3 {
		return raw, nil
	}
	if injectAppName == "" {
		return raw, nil
	}
	if length < 9 || raw[length-1] != 0 {
		return nil, fmt.Errorf("startup not null-terminated")
	}
	body := raw[8 : length-1]
	var keys, vals []string
	for len(body) > 0 {
		i := bytes.IndexByte(body, 0)
		if i < 0 {
			return nil, fmt.Errorf("malformed key in startup")
		}
		key := string(body[:i])
		body = body[i+1:]
		if key == "" {
			break
		}
		j := bytes.IndexByte(body, 0)
		if j < 0 {
			return nil, fmt.Errorf("malformed value for key %q", key)
		}
		val := string(body[:j])
		body = body[j+1:]
		keys = append(keys, key)
		vals = append(vals, val)
	}
	for _, k := range keys {
		if k == "application_name" {
			return raw, nil
		}
	}
	keys = append(keys, "application_name")
	vals = append(vals, injectAppName)

	var out bytes.Buffer
	out.Grow(length + len("application_name") + len(injectAppName) + 8)
	out.Write([]byte{0, 0, 0, 0}) // length placeholder
	var protoBuf [4]byte
	binary.BigEndian.PutUint32(protoBuf[:], pgProtoV3)
	out.Write(protoBuf[:])
	for i := range keys {
		out.WriteString(keys[i])
		out.WriteByte(0)
		out.WriteString(vals[i])
		out.WriteByte(0)
	}
	out.WriteByte(0)
	b := out.Bytes()
	binary.BigEndian.PutUint32(b[:4], uint32(len(b)))
	return b, nil
}

// Fly identity caching.

type flyIdentEntry struct {
	ident     string
	expiresAt time.Time
}

type vmsTable struct {
	mu        sync.Mutex
	byID      map[string]string
	expiresAt time.Time
}

var (
	flyIdentCache sync.Map // netip.Addr -> flyIdentEntry
	flyVmsCache   sync.Map // app string -> *vmsTable
)

const flyCacheTTL = 5 * time.Minute

// lookupFlyIdent returns the "region.app" identifier for a Fly 6PN
// source IP. On any lookup failure it returns "fly-unknown" rather
// than an error, so DNS hiccups never block a connection.
func lookupFlyIdent(ctx context.Context, ip netip.Addr) string {
	if v, ok := flyIdentCache.Load(ip); ok {
		e := v.(flyIdentEntry)
		if time.Now().Before(e.expiresAt) {
			return e.ident
		}
	}
	ident := resolveFlyIdent(ctx, ip)
	flyIdentCache.Store(ip, flyIdentEntry{ident: ident, expiresAt: time.Now().Add(flyCacheTTL)})
	return ident
}

// resolveFlyIdent does the actual PTR + TXT lookups. PTR shape:
// "<machineID>.vm.<app>.internal." TXT shape (vms.<app>.internal):
// space-separated "<id> <region>" entries, optionally combined into
// comma-separated bundles within a single record.
func resolveFlyIdent(ctx context.Context, ip netip.Addr) string {
	lctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(lctx, ip.String())
	if err != nil || len(names) == 0 {
		return "fly-unknown"
	}
	parts := strings.Split(strings.TrimSuffix(names[0], "."), ".")
	if len(parts) < 4 || parts[len(parts)-1] != "internal" || parts[len(parts)-3] != "vm" {
		return "fly-unknown"
	}
	id := parts[len(parts)-4]
	app := parts[len(parts)-2]
	if app == "" {
		return "fly-unknown"
	}
	region := lookupFlyRegion(ctx, app, id)
	if region == "" {
		return app
	}
	return region + "." + app
}

// lookupFlyRegion returns the region for the given machine ID in app
// by consulting vms.<app>.internal. Returns "" if unknown.
func lookupFlyRegion(ctx context.Context, app, id string) string {
	if v, ok := flyVmsCache.Load(app); ok {
		t := v.(*vmsTable)
		t.mu.Lock()
		fresh := time.Now().Before(t.expiresAt)
		r := t.byID[id]
		t.mu.Unlock()
		if fresh && r != "" {
			return r
		}
	}
	lctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(lctx, "vms."+app+".internal")
	if err != nil {
		return ""
	}
	byID := parseVmsTXT(txts)
	flyVmsCache.Store(app, &vmsTable{byID: byID, expiresAt: time.Now().Add(flyCacheTTL)})
	return byID[id]
}

// parseVmsTXT parses TXT records of the form "<id> <region>", with
// multiple entries optionally comma-separated within a single record.
func parseVmsTXT(txts []string) map[string]string {
	out := map[string]string{}
	for _, record := range txts {
		for _, entry := range strings.Split(record, ",") {
			fields := strings.Fields(strings.TrimSpace(entry))
			if len(fields) >= 2 {
				out[fields[0]] = fields[1]
			}
		}
	}
	return out
}
