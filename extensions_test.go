// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestParseAdvertiseRoutes(t *testing.T) {
	got, err := parseAdvertiseRoutes(" fdaa::/16 , 10.0.0.0/8 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"fdaa::/16", "10.0.0.0/8"}
	if len(got) != len(want) {
		t.Fatalf("got %d routes, want %d (%v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("route %d = %q, want %q", i, got[i].String(), w)
		}
	}

	if r, err := parseAdvertiseRoutes("   "); err != nil || r != nil {
		t.Errorf("empty input: got (%v, %v), want (nil, nil)", r, err)
	}

	if _, err := parseAdvertiseRoutes("not-a-cidr"); err == nil {
		t.Errorf("expected error for invalid CIDR")
	}
}

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
	html := string(renderDevPageHTML("pg.tail.ts.net", "pgproxy.internal", cfgs))
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
