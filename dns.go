// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// dns.go is the .internal DNS forwarder (Go companion to fly-router.sh).
//
// A tiny DNS forwarder that answers on [::]:53 (UDP+TCP). For most names
// it relays the query verbatim to --dns-resolver (which defaults to Fly's
// internal resolver [fdaa::3]:53 on Fly, off elsewhere), so tailnet
// clients resolve *.internal to 6PN addresses reachable via the subnet route.
//
// Special case ("Option I", auto-enabled on Fly via FLY_APP_NAME): for
// THIS app's own bare <app>.internal name, instead of returning the 6PN
// address it answers with this node's *Tailscale* IP. Tailnet clients then
// reach private-gateway directly over Tailscale on every port — no subnet route, no
// SNAT — so their real source IP is preserved and WhoIs can attribute them.
// Fly 6PN apps are unaffected: they query Fly's resolver, not us, and still
// get the 6PN address. No tailscale.com dependency — we read our own
// Tailscale IP off the local interfaces.
//
// Only the bare name is rewritten (see dnsIsSelf): region- and
// machine-qualified names are relayed, so <region>.<app>.internal still
// selects a region instead of collapsing onto whichever node answered.
//
// It also implements the <app>.<env> alias scheme: see aliasTarget and
// resolveAlias. Source gating, attribution and the rest of the Fly glue
// stay in fly.go.
//
// Flags declared here:
//
//	--dns-resolver     Upstream resolver for *.internal. Fly default; off elsewhere.
//	--alias-domain     Pseudo-suffix mapping <app>.<env> to <app>.<internal>. Off by default.
//	--internal-domain  Internal domain appended after stripping --alias-domain. Fly: "internal".
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// dnsListen is where the forwarder binds. [::] covers every interface,
// including the Tailscale one once tailscaled brings it up, so split-DNS
// queries aimed at the node's Tailscale IP are received.
const dnsListen = "[::]:53"

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

// flyResolver is Fly's internal DNS resolver — the default --dns-resolver
// when running on Fly.
const flyResolver = "[fdaa::3]:53"

var dnsResolver = flag.String("dns-resolver", "",
	`Upstream DNS resolver to forward *.internal queries to, served on `+dnsListen+` (UDP+TCP). Defaults to `+flyResolver+` on Fly; empty (off) elsewhere.`)

// --alias-domain / --internal-domain drive the <app>.<env> alias feature:
// a query for <app>.<ALIAS_DOMAIN> is rewritten to <app>.<INTERNAL_DOMAIN>,
// resolved via --dns-resolver, and answered under the original alias name.
// This lets a tailnet client reach an app by an environment-tagged name
// (e.g. core.prod, core.stage) that Tailscale split DNS routes to the
// right gateway. Empty --alias-domain disables the feature.
var (
	aliasDomainFlag    = flag.String("alias-domain", "", "Pseudo-suffix (e.g. \"prod\", \"stage\") that maps <app>.<alias-domain> to <app>.<internal-domain>, resolved via --dns-resolver. Empty disables the alias feature.")
	internalDomainFlag = flag.String("internal-domain", "", "Real internal domain appended to the short name after stripping --alias-domain (e.g. \"internal\"). Defaults to \"internal\" on Fly; empty (bare service name, e.g. Docker DNS) elsewhere.")
)

// aliasSuffix / internalDomain are the resolved (trimmed, lowercased,
// dot-stripped) forms of the flags above, set once in startDNSForwarder.
// aliasSuffix empty means the alias feature is off.
var (
	aliasSuffix    string
	internalDomain string
)

// dnsSelfSuffix is "<FLY_APP_NAME>.internal" when we can self-rewrite,
// else empty. Set once in startDNSForwarder.
var dnsSelfSuffix string

// startDNSForwarder launches the DNS forwarder if a resolver is set (or
// defaulted on Fly). It is a no-op otherwise. Listener errors are fatal
// (a misconfigured :53 bind should fail loudly at startup, not silently).
func startDNSForwarder() {
	resolver := strings.TrimSpace(*dnsResolver)
	if resolver == "" && onFly {
		resolver = flyResolver // hardcoded Fly default; generic name lets others override
	}
	if resolver == "" {
		return
	}

	// Resolve the <app>.<env> alias config. INTERNAL_DOMAIN defaults to
	// "internal" on Fly (where <app>.internal is the native name); off Fly
	// it stays empty (bare service names, e.g. Docker DNS). An empty
	// aliasSuffix leaves the alias feature off (resolveAlias is a no-op).
	aliasSuffix = strings.ToLower(strings.Trim(strings.TrimSpace(*aliasDomainFlag), "."))
	internalDomain = strings.ToLower(strings.Trim(strings.TrimSpace(*internalDomainFlag), "."))
	if internalDomain == "" && onFly {
		internalDomain = "internal"
	}
	if aliasSuffix != "" {
		log.Printf("dns: alias domain %q -> internal domain %q (resolver %s)", aliasSuffix, internalDomain, resolver)
	}

	// Auto-detect: on Fly we know our own app name (FLY_APP_NAME is
	// injected), so answer our own *.internal with our Tailscale IP. Off
	// Fly (no FLY_APP_NAME) this stays empty and we just forward; before
	// tailscaled assigns an IP, selfTailscaleAddr falls back to forwarding.
	if app := strings.TrimSpace(os.Getenv("FLY_APP_NAME")); app != "" {
		dnsSelfSuffix = strings.ToLower(app) + ".internal"
		log.Printf("dns: answering %s with this node's Tailscale IP (tailnet reaches private-gateway directly over Tailscale)", dnsSelfSuffix)
	}

	pc, err := net.ListenPacket("udp", dnsListen)
	if err != nil {
		log.Fatalf("dns udp listen on %s: %v", dnsListen, err)
	}
	go serveDNSUDP(pc, resolver)

	ln, err := net.Listen("tcp", dnsListen)
	if err != nil {
		log.Fatalf("dns tcp listen on %s: %v", dnsListen, err)
	}
	go serveDNSTCP(ln, resolver)

	log.Printf("serving .internal DNS on %s -> %s", dnsListen, resolver)
}

// dnsIsSelf reports whether name (lowercased, no trailing dot) is this
// app's own *bare* <app>.internal name — the only name the self-rewrite
// answers with this node's Tailscale IP.
//
// Deliberately an exact match. Qualified names under it keep their normal
// Fly meaning and are relayed to --dns-resolver, so they resolve to the
// 6PN address of the machine(s) they name:
//
//	<region>.<app>.internal    -> machines in that region
//	<id>.vm.<app>.internal     -> that specific machine
//	vms.<app>.internal         -> the TXT inventory identifyClient reads
//
// Rewriting those too (the previous behavior) collapsed every name onto
// whichever node happened to answer the query, so `fra.<app>.internal`
// could return the sin node and region selection was impossible. The bare
// name still gives per-user attribution; a caller that asks for a region
// has named a machine explicitly and gets it.
func dnsIsSelf(name string) bool {
	if dnsSelfSuffix == "" {
		return false
	}
	return name == dnsSelfSuffix
}

// parseDNSQuestion parses the first question: the QNAME (lowercased, no
// trailing dot), the QTYPE, and the offset just past the question
// (header + qname + qtype + qclass). ok is false if the message is
// malformed.
func parseDNSQuestion(msg []byte) (name string, qtype uint16, qend int, ok bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) < 1 {
		return "", 0, 0, false
	}
	var sb strings.Builder
	off := 12
	for {
		if off >= len(msg) {
			return "", 0, 0, false
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || off+l > len(msg) { // questions carry no compression pointers
			return "", 0, 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(msg[off : off+l])
		off += l
	}
	if off+4 > len(msg) {
		return "", 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(msg[off : off+2])
	return strings.ToLower(sb.String()), qtype, off + 4, true
}

// selfTailscaleAddr returns this node's Tailscale address matching qtype
// (A→IPv4 100.64/10, AAAA→IPv6 fd7a:115c:a1e0::/48), discovered from the
// local interfaces. ok is false if no such address exists yet (e.g.
// tailscaled hasn't finished coming up) — callers then fall back to
// forwarding so resolution still works.
func selfTailscaleAddr(qtype uint16) (netip.Addr, bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		switch qtype {
		case dnsTypeA:
			if tailscaleV4.Contains(ip) {
				return ip, true
			}
		case dnsTypeAAAA:
			if tailscaleV6.Contains(ip) {
				return ip, true
			}
		}
	}
	return netip.Addr{}, false
}

// dnsAnswer builds a NOERROR response for query with a single A/AAAA
// answer record pointing at addr (TTL 30s). qend is the offset past the
// question (from parseDNSQuestion). Thin wrapper over dnsAnswerMulti.
func dnsAnswer(query []byte, qtype uint16, addr netip.Addr, qend int) []byte {
	return dnsAnswerMulti(query, qtype, []netip.Addr{addr}, qend)
}

// dnsAnswerMulti builds a NOERROR response for query with one A/AAAA
// answer record per addr (TTL 30s), all under the queried name via the
// 0xC0 0x0C compression pointer. Multiple records let multi-instance apps
// keep load-balancing. Each addr must match qtype (4 bytes for A, 16 for
// AAAA). Returns nil if qend is out of range or addrs is empty.
func dnsAnswerMulti(query []byte, qtype uint16, addrs []netip.Addr, qend int) []byte {
	if qend < 12 || qend > len(query) || len(addrs) == 0 {
		return nil
	}
	resp := make([]byte, 0, qend+16*len(addrs))
	resp = append(resp, query[:qend]...)                      // header + question
	resp[2] = 0x80 | (query[2] & 0x01)                        // QR=1, preserve RD
	resp[3] = 0x80                                            // RA=1, RCODE=0 (NOERROR)
	binary.BigEndian.PutUint16(resp[4:6], 1)                  // QDCOUNT
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(addrs))) // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)                 // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0)                // ARCOUNT
	for _, addr := range addrs {
		ipb := addr.AsSlice()           // 4 bytes for A, 16 for AAAA
		resp = append(resp, 0xC0, 0x0C) // answer name: pointer to the question at offset 12
		resp = binary.BigEndian.AppendUint16(resp, qtype)
		resp = binary.BigEndian.AppendUint16(resp, 1)  // CLASS IN
		resp = binary.BigEndian.AppendUint32(resp, 30) // TTL
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(ipb)))
		resp = append(resp, ipb...)
	}
	return resp
}

// aliasTarget maps an alias-domain query name to the internal name to
// resolve, or returns ok=false if name is not under aliasSuffix. name is
// lowercased with no trailing dot (from parseDNSQuestion). It strips the
// ".<aliasSuffix>" suffix (requiring at least one label before it) and, if
// internalDomain is set, appends ".<internalDomain>":
//
//	core.prod  (alias "prod", internal "internal") -> core.internal
//	core.stage (alias "stage", internal "")        -> core
func aliasTarget(name string) (target string, ok bool) {
	if aliasSuffix == "" {
		return "", false
	}
	suffix := "." + aliasSuffix
	if !strings.HasSuffix(name, suffix) {
		return "", false
	}
	short := name[:len(name)-len(suffix)]
	if short == "" { // bare "<aliasSuffix>" has no app label
		return "", false
	}
	if internalDomain != "" {
		return short + "." + internalDomain, true
	}
	return short, true
}

// resolveAlias answers an <app>.<ALIAS_DOMAIN> A/AAAA query by resolving
// the rewritten internal name via resolverAddr and returning the result
// under the ORIGINAL alias name. Returns nil (caller forwards) when the
// alias feature is off, the query isn't an A/AAAA alias query, or
// resolution yields no matching-family address.
func resolveAlias(query []byte, resolverAddr string) []byte {
	if aliasSuffix == "" {
		return nil
	}
	name, qtype, qend, ok := parseDNSQuestion(query)
	if !ok || (qtype != dnsTypeA && qtype != dnsTypeAAAA) {
		return nil
	}
	target, ok := aliasTarget(name)
	if !ok {
		return nil
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, resolverAddr)
		},
	}
	network := "ip6"
	if qtype == dnsTypeA {
		network = "ip4"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupNetIP(ctx, network, target)
	if err != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if qtype == dnsTypeA && ip.Is4() {
			addrs = append(addrs, ip)
		} else if qtype == dnsTypeAAAA && !ip.Is4() {
			addrs = append(addrs, ip)
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	return dnsAnswerMulti(query, qtype, addrs, qend)
}

// dnsSelfAnswer returns a self-rewrite answer for query if it's an
// A/AAAA query for one of this app's own names and we know our Tailscale
// address; otherwise nil (caller forwards).
func dnsSelfAnswer(query []byte) []byte {
	name, qtype, qend, ok := parseDNSQuestion(query)
	if !ok || !dnsIsSelf(name) || (qtype != dnsTypeA && qtype != dnsTypeAAAA) {
		return nil
	}
	addr, ok := selfTailscaleAddr(qtype)
	if !ok {
		return nil
	}
	return dnsAnswer(query, qtype, addr, qend)
}

// serveDNSUDP answers each UDP query: self names get this node's
// Tailscale IP (when self-to-tailscale is on), everything else is
// forwarded to resolverAddr.
func serveDNSUDP(pc net.PacketConn, resolverAddr string) {
	defer pc.Close()
	for {
		buf := make([]byte, 4096) // fits EDNS0-advertised sizes
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		go func(query []byte, src net.Addr) {
			if resp := dnsSelfAnswer(query); resp != nil {
				pc.WriteTo(resp, src)
				return
			}
			if resp := resolveAlias(query, resolverAddr); resp != nil {
				pc.WriteTo(resp, src)
				return
			}
			resp, err := forwardDNSUDP(query, resolverAddr)
			if err != nil {
				log.Printf("dns udp forward: %v", err)
				return
			}
			if _, err := pc.WriteTo(resp, src); err != nil {
				log.Printf("dns udp reply: %v", err)
			}
		}(buf[:n], src)
	}
}

func forwardDNSUDP(query []byte, resolverAddr string) ([]byte, error) {
	c, err := net.Dial("udp", resolverAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := c.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

// serveDNSTCP answers DNS-over-TCP, applying the same self-rewrite as
// UDP. Messages are length-prefixed (RFC 1035 §4.2.2).
func serveDNSTCP(ln net.Listener, resolverAddr string) {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleDNSTCP(c, resolverAddr)
	}
}

func handleDNSTCP(c net.Conn, resolverAddr string) {
	defer c.Close()
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		msg, err := readDNSTCP(c)
		if err != nil {
			return
		}
		if resp := dnsSelfAnswer(msg); resp != nil {
			if writeDNSTCP(c, resp) != nil {
				return
			}
			continue
		}
		if resp := resolveAlias(msg, resolverAddr); resp != nil {
			if writeDNSTCP(c, resp) != nil {
				return
			}
			continue
		}
		resp, err := forwardDNSTCP(msg, resolverAddr)
		if err != nil {
			log.Printf("dns tcp forward: %v", err)
			return
		}
		if writeDNSTCP(c, resp) != nil {
			return
		}
	}
}

func readDNSTCP(r io.Reader) ([]byte, error) {
	var ln [2]byte
	if _, err := io.ReadFull(r, ln[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(ln[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeDNSTCP(w io.Writer, msg []byte) error {
	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(len(msg)))
	if _, err := w.Write(ln[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func forwardDNSTCP(msg []byte, resolverAddr string) ([]byte, error) {
	c, err := net.Dial("tcp", resolverAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeDNSTCP(c, msg); err != nil {
		return nil, err
	}
	return readDNSTCP(c)
}
