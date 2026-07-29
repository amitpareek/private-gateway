// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// buildDNSQuery builds a minimal AAAA query for name (id 0x1234, RD set).
func buildDNSQuery(name string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	b.Write([]byte{0x00, 0x1c, 0x00, 0x01}) // QTYPE=AAAA, QCLASS=IN
	return b.Bytes()
}

func TestParseDNSQuestionAndIsSelf(t *testing.T) {
	dnsSelfSuffix = "pgproxy.internal"
	defer func() { dnsSelfSuffix = "" }()
	cases := []struct {
		q    string
		want bool
	}{
		{"pgproxy.internal", true},
		{"PGPROXY.INTERNAL", true}, // case-insensitive
		// Qualified names are NOT self: they relay to Fly's resolver so
		// they resolve to the machine(s) they name, preserving region
		// and per-machine selection.
		{"sin.pgproxy.internal", false},
		{"148e21.vm.pgproxy.internal", false},
		{"vms.pgproxy.internal", false},
		{"other-app.internal", false},
		{"notpgproxy.internal", false}, // suffix must be on a label boundary
	}
	for _, c := range cases {
		name, qtype, qend, ok := parseDNSQuestion(buildDNSQuery(c.q))
		if !ok {
			t.Fatalf("parseDNSQuestion(%q) failed to parse", c.q)
		}
		if qtype != dnsTypeAAAA {
			t.Errorf("%q: qtype = %d, want %d", c.q, qtype, dnsTypeAAAA)
		}
		if qend < 12 {
			t.Errorf("%q: qend = %d, want >= 12", c.q, qend)
		}
		if got := dnsIsSelf(name); got != c.want {
			t.Errorf("dnsIsSelf(%q) = %v, want %v (parsed %q)", c.q, got, c.want, name)
		}
	}
}

func TestDNSAnswer(t *testing.T) {
	q := buildDNSQuery("pgproxy.internal") // AAAA
	_, qtype, qend, _ := parseDNSQuestion(q)
	ts := netip.MustParseAddr("fd7a:115c:a1e0::1234")
	resp := dnsAnswer(q, qtype, ts, qend)
	if resp == nil {
		t.Fatal("dnsAnswer returned nil")
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Errorf("query ID not echoed")
	}
	if resp[2]&0x80 == 0 {
		t.Errorf("QR bit not set")
	}
	if resp[3]&0x0f != 0 {
		t.Errorf("RCODE = %d, want 0 (NOERROR)", resp[3]&0x0f)
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Errorf("ANCOUNT = %d, want 1", binary.BigEndian.Uint16(resp[6:8]))
	}
	// answer: name ptr (0xC00C) + type + class + ttl(4) + rdlen(2) + 16-byte AAAA
	ans := resp[qend:]
	if len(ans) != 2+2+2+4+2+16 {
		t.Fatalf("answer length = %d, want %d", len(ans), 2+2+2+4+2+16)
	}
	if ans[0] != 0xC0 || ans[1] != 0x0C {
		t.Errorf("answer name not a compression pointer to the question")
	}
	if got := binary.BigEndian.Uint16(ans[2:4]); got != dnsTypeAAAA {
		t.Errorf("answer type = %d, want AAAA(%d)", got, dnsTypeAAAA)
	}
	rdata := ans[12:]
	if got, _ := netip.AddrFromSlice(rdata); got != ts {
		t.Errorf("answer rdata = %v, want %v", got, ts)
	}
}

func TestDNSIsSelfDisabledByDefault(t *testing.T) {
	dnsSelfSuffix = ""
	if dnsIsSelf("pgproxy.internal") {
		t.Errorf("self-match should be off when dnsSelfSuffix is empty")
	}
}

func TestAliasTarget(t *testing.T) {
	defer func() { aliasSuffix, internalDomain = "", "" }()
	cases := []struct {
		name, alias, internal, want string
		ok                          bool
	}{
		{"core.prod", "prod", "internal", "core.internal", true},         // Fly: append internal domain
		{"bo.prod", "prod", "internal", "bo.internal", true},             //
		{"core.stage", "stage", "", "core", true},                        // Docker: bare service name
		{"vms.core.prod", "prod", "internal", "vms.core.internal", true}, // multi-label short name
		{"core.internal", "prod", "internal", "", false},                 // not under the alias domain
		{"prod", "prod", "internal", "", false},                          // bare suffix, no app label
		{"core.production", "prod", "internal", "", false},               // suffix must be a whole label
		{"core.prod", "", "internal", "", false},                         // feature off (empty aliasSuffix)
	}
	for _, c := range cases {
		aliasSuffix, internalDomain = c.alias, c.internal
		got, ok := aliasTarget(c.name)
		if ok != c.ok || got != c.want {
			t.Errorf("aliasTarget(%q) [alias=%q internal=%q] = (%q,%v), want (%q,%v)",
				c.name, c.alias, c.internal, got, ok, c.want, c.ok)
		}
	}
}

func TestAliasTargetCaseInsensitive(t *testing.T) {
	aliasSuffix, internalDomain = "prod", "internal"
	defer func() { aliasSuffix, internalDomain = "", "" }()
	// parseDNSQuestion lowercases the QNAME, so an uppercase query still matches.
	name, _, _, ok := parseDNSQuestion(buildDNSQuery("CORE.PROD"))
	if !ok {
		t.Fatal("parseDNSQuestion failed")
	}
	if got, ok := aliasTarget(name); !ok || got != "core.internal" {
		t.Errorf("aliasTarget(%q) = (%q,%v), want (core.internal,true)", name, got, ok)
	}
}

func TestDNSAnswerMulti(t *testing.T) {
	q := buildDNSQuery("core.prod") // AAAA
	_, qtype, qend, _ := parseDNSQuestion(q)
	addrs := []netip.Addr{
		netip.MustParseAddr("fdaa::1"),
		netip.MustParseAddr("fdaa::2"),
	}
	resp := dnsAnswerMulti(q, qtype, addrs, qend)
	if resp == nil {
		t.Fatal("dnsAnswerMulti returned nil")
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 2 {
		t.Fatalf("ANCOUNT = %d, want 2", got)
	}
	const rec = 2 + 2 + 2 + 4 + 2 + 16 // ptr + type + class + ttl + rdlen + AAAA
	ans := resp[qend:]
	if len(ans) != 2*rec {
		t.Fatalf("answer length = %d, want %d", len(ans), 2*rec)
	}
	for i, want := range addrs {
		off := i * rec
		if ans[off] != 0xC0 || ans[off+1] != 0x0C {
			t.Errorf("record %d: name not a compression pointer", i)
		}
		if got, _ := netip.AddrFromSlice(ans[off+12 : off+12+16]); got != want {
			t.Errorf("record %d rdata = %v, want %v", i, got, want)
		}
	}
	if dnsAnswerMulti(q, qtype, nil, qend) != nil {
		t.Error("dnsAnswerMulti with no addrs should return nil")
	}
}

// TestResolveAliasIntegration stands up a tiny stub resolver and checks the
// full path: core.prod -> resolve core.internal via the stub -> answer under
// the original core.prod name.
func TestResolveAliasIntegration(t *testing.T) {
	aliasSuffix, internalDomain = "prod", "internal"
	defer func() { aliasSuffix, internalDomain = "", "" }()

	want := netip.MustParseAddr("fdaa:0:1::42")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub resolver listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			name, qtype, qend, ok := parseDNSQuestion(q)
			if ok && name == "core.internal" && qtype == dnsTypeAAAA {
				pc.WriteTo(dnsAnswer(q, qtype, want, qend), src)
				continue
			}
			// NXDOMAIN for anything else.
			if ok {
				resp := append([]byte(nil), q[:qend]...)
				resp[2] = 0x80 | (q[2] & 0x01)
				resp[3] = 0x83 // RA=1, RCODE=3 (NXDOMAIN)
				binary.BigEndian.PutUint16(resp[6:8], 0)
				pc.WriteTo(resp, src)
			}
		}
	}()

	resp := resolveAlias(buildDNSQuery("core.prod"), pc.LocalAddr().String())
	if resp == nil {
		t.Fatal("resolveAlias returned nil")
	}
	name, qtype, qend, ok := parseDNSQuestion(resp)
	if !ok || name != "core.prod" || qtype != dnsTypeAAAA {
		t.Fatalf("response question = (%q,%d,ok=%v), want (core.prod, AAAA)", name, qtype, ok)
	}
	ans := resp[qend:]
	if ans[0] != 0xC0 || ans[1] != 0x0C {
		t.Error("answer name is not a compression pointer to the alias question")
	}
	if got, _ := netip.AddrFromSlice(ans[12:28]); got != want {
		t.Errorf("answer rdata = %v, want %v", got, want)
	}
}

func TestResolveAliasDisabled(t *testing.T) {
	aliasSuffix, internalDomain = "", ""
	if resolveAlias(buildDNSQuery("core.prod"), "127.0.0.1:53") != nil {
		t.Error("resolveAlias should return nil when the feature is off")
	}
}
