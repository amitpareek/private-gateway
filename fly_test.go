// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestParseDestinationPgDbs_ManagedEntry(t *testing.T) {
	list, err := parseDestinationPgDbsJSON(`[
		{"name":"rw","listen":5432,"target":"db.example.com:5432",
		 "dbname":"main","user":"app","password":"s3cret"}
	]`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d entries, want 1", len(list))
	}
	u := list[0]
	if u.DBName != "main" || u.User != "app" || u.Password != "s3cret" {
		t.Errorf("credentials not parsed: %+v", u)
	}
	if !u.managed() {
		t.Errorf("entry with user+password should be managed")
	}
}

func TestParseDestinationPgDbs_PassthroughEntry(t *testing.T) {
	list, err := parseDestinationPgDbsJSON(`[
		{"name":"admin","listen":5439,"target":"db.example.com:5432"}
	]`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if list[0].managed() {
		t.Errorf("entry without credentials should be passthrough")
	}
}

func TestParseDestinationPgDbs_CredentialValidation(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		errPart string
	}{
		{
			name:    "user without password",
			json:    `[{"name":"a","listen":5432,"target":"h:5432","user":"app"}]`,
			errPart: "password",
		},
		{
			name:    "password without user",
			json:    `[{"name":"a","listen":5432,"target":"h:5432","password":"x"}]`,
			errPart: "user",
		},
		{
			name:    "dbname without user",
			json:    `[{"name":"a","listen":5432,"target":"h:5432","dbname":"main"}]`,
			errPart: "dbname",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseDestinationPgDbsJSON(c.json)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.errPart)
			}
			if !strings.Contains(err.Error(), c.errPart) {
				t.Errorf("error %q does not mention %q", err, c.errPart)
			}
		})
	}
}

func TestParseStartupParams(t *testing.T) {
	raw := buildStartup("user", "root", "database", "mydb", "client_encoding", "UTF8")
	params, err := parseStartupParams(raw)
	if err != nil {
		t.Fatalf("parseStartupParams: %v", err)
	}
	want := map[string]string{"user": "root", "database": "mydb", "client_encoding": "UTF8"}
	if len(params) != len(want) {
		t.Fatalf("got %v, want %v", params, want)
	}
	for k, v := range want {
		if params[k] != v {
			t.Errorf("%q = %q, want %q", k, params[k], v)
		}
	}
}

func TestParseStartupParams_RejectsNonV3(t *testing.T) {
	// CancelRequest layout.
	var raw [16]byte
	binary.BigEndian.PutUint32(raw[0:4], 16)
	binary.BigEndian.PutUint32(raw[4:8], 80877102)
	if _, err := parseStartupParams(raw[:]); err == nil {
		t.Errorf("expected error for non-v3 startup")
	}
}

func TestParseStartupParams_RejectsMalformed(t *testing.T) {
	bad := make([]byte, 20)
	binary.BigEndian.PutUint32(bad[:4], 50) // length lies
	binary.BigEndian.PutUint32(bad[4:8], pgProtoV3)
	if _, err := parseStartupParams(bad); err == nil {
		t.Errorf("expected error for length mismatch")
	}
}

func TestChooseDatabase(t *testing.T) {
	cases := []struct {
		name                        string
		clientUser, clientDB, defDB string
		want                        string
	}{
		{"explicit db honored", "root", "mydb", "main", "mydb"},
		{"db equal to user is driver auto-fill -> default", "root", "root", "main", "main"},
		{"no db -> default", "root", "", "main", "main"},
		{"no db, no default -> empty (upstream defaults to role)", "root", "", "", ""},
		{"db equal to user, no default -> empty", "root", "root", "", ""},
		{"explicit db named like default user", "app", "app2", "main", "app2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := chooseDatabase(c.clientUser, c.clientDB, c.defDB); got != c.want {
				t.Errorf("chooseDatabase(%q,%q,%q) = %q, want %q", c.clientUser, c.clientDB, c.defDB, got, c.want)
			}
		})
	}
}

func TestIsPlaintextStartup(t *testing.T) {
	mk := func(length, proto uint32) [8]byte {
		var b [8]byte
		binary.BigEndian.PutUint32(b[0:4], length)
		binary.BigEndian.PutUint32(b[4:8], proto)
		return b
	}
	cases := []struct {
		name string
		buf  [8]byte
		want bool
	}{
		{"legacy 86-byte startup", mk(86, pgProtoV3), true},
		{"short startup (sslmode=disable, small params)", mk(41, pgProtoV3), true},
		{"long startup", mk(312, pgProtoV3), true},
		{"ssl request magic", sslStart, false},
		{"cancel request", mk(16, 80877102), false},
		{"absurd length", mk(1<<30, pgProtoV3), false},
		{"too-small length", mk(7, pgProtoV3), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPlaintextStartup(c.buf); got != c.want {
				t.Errorf("isPlaintextStartup(% 02x) = %v, want %v", c.buf, got, c.want)
			}
		})
	}
}

func TestWriteManagedHandshake(t *testing.T) {
	var buf bytes.Buffer
	params := map[string]string{"server_version": "16.4", "client_encoding": "UTF8"}
	if err := writeManagedHandshake(&buf, params, 4242, 991199, 'I'); err != nil {
		t.Fatalf("writeManagedHandshake: %v", err)
	}

	fe := pgproto3.NewFrontend(&buf, nil)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive auth: %v", err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationOk); !ok {
		t.Fatalf("first message = %T, want AuthenticationOk", msg)
	}

	gotParams := map[string]string{}
	for i := 0; i < len(params); i++ {
		msg, err = fe.Receive()
		if err != nil {
			t.Fatalf("receive param %d: %v", i, err)
		}
		ps, ok := msg.(*pgproto3.ParameterStatus)
		if !ok {
			t.Fatalf("message %d = %T, want ParameterStatus", i, msg)
		}
		gotParams[ps.Name] = ps.Value
	}
	for k, v := range params {
		if gotParams[k] != v {
			t.Errorf("param %q = %q, want %q", k, gotParams[k], v)
		}
	}

	msg, err = fe.Receive()
	if err != nil {
		t.Fatalf("receive keydata: %v", err)
	}
	kd, ok := msg.(*pgproto3.BackendKeyData)
	if !ok {
		t.Fatalf("message = %T, want BackendKeyData", msg)
	}
	if kd.ProcessID != 4242 || kd.SecretKey != 991199 {
		t.Errorf("BackendKeyData = %d/%d, want 4242/991199", kd.ProcessID, kd.SecretKey)
	}

	msg, err = fe.Receive()
	if err != nil {
		t.Fatalf("receive rfq: %v", err)
	}
	rfq, ok := msg.(*pgproto3.ReadyForQuery)
	if !ok {
		t.Fatalf("message = %T, want ReadyForQuery", msg)
	}
	if rfq.TxStatus != 'I' {
		t.Errorf("TxStatus = %c, want I", rfq.TxStatus)
	}
	if buf.Len() != 0 {
		t.Errorf("%d trailing bytes after handshake", buf.Len())
	}
}

func TestWriteManagedError(t *testing.T) {
	var buf bytes.Buffer
	if err := writeManagedError(&buf, "upstream authentication failed"); err != nil {
		t.Fatalf("writeManagedError: %v", err)
	}
	fe := pgproto3.NewFrontend(&buf, nil)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("message = %T, want ErrorResponse", msg)
	}
	if er.Severity != "FATAL" || !strings.Contains(er.Message, "upstream authentication failed") {
		t.Errorf("ErrorResponse = %+v", er)
	}
}

func TestDevPage_NeverRendersPasswords(t *testing.T) {
	cfgs := []upstreamConfig{
		{Name: "rw", Listen: 5432, Target: "ep-x.neon.tech:5432",
			DBName: "maindb", User: "app_user", Password: "hunter2-secret"},
		{Name: "admin", Listen: 5439, Target: "ep-x.neon.tech:5432"},
	}
	html := string(renderDevPageHTML("pgproxy.internal", cfgs))
	if strings.Contains(html, "hunter2-secret") {
		t.Fatalf("dev page leaks a configured password")
	}
	if !strings.Contains(html, "app_user") {
		t.Errorf("dev page should show the managed user name")
	}
	if !strings.Contains(html, "postgres://pgproxy.internal:5432/maindb") {
		t.Errorf("dev page should show a copy-paste connection string for managed entries")
	}
	if !strings.Contains(html, "managed") || !strings.Contains(html, "passthrough") {
		t.Errorf("dev page should label entry modes")
	}
}

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
		{"sin.pgproxy.internal", true},
		{"148e21.vm.pgproxy.internal", true},
		{"PGPROXY.INTERNAL", true}, // case-insensitive
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

func TestUpstreamConfigAllows(t *testing.T) {
	open := upstreamConfig{} // no Allow → anyone
	if !open.allows("alice@x.com") || !open.allows("") {
		t.Errorf("empty Allow should permit anyone")
	}
	restricted := upstreamConfig{Allow: []string{"alice@x.com", " Bob@X.com "}}
	for _, u := range []string{"alice@x.com", "ALICE@x.com", "bob@x.com"} {
		if !restricted.allows(u) {
			t.Errorf("allows(%q) = false, want true", u)
		}
	}
	for _, u := range []string{"carol@x.com", "tailscale-unknown", ""} {
		if restricted.allows(u) {
			t.Errorf("allows(%q) = true, want false", u)
		}
	}
}
