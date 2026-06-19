// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildStartup encodes a v3 StartupMessage from the given key/value pairs.
func buildStartup(kv ...string) []byte {
	if len(kv)%2 != 0 {
		panic("buildStartup: kv must be even-length")
	}
	var body bytes.Buffer
	var proto [4]byte
	binary.BigEndian.PutUint32(proto[:], pgProtoV3)
	body.Write(proto[:])
	for i := 0; i < len(kv); i += 2 {
		body.WriteString(kv[i])
		body.WriteByte(0)
		body.WriteString(kv[i+1])
		body.WriteByte(0)
	}
	body.WriteByte(0) // terminator
	out := make([]byte, 4+body.Len())
	binary.BigEndian.PutUint32(out[:4], uint32(len(out)))
	copy(out[4:], body.Bytes())
	return out
}

// parseStartupKV is a test helper that re-parses a startup message into kv.
func parseStartupKV(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	length := int(binary.BigEndian.Uint32(raw[:4]))
	if length != len(raw) {
		t.Fatalf("length mismatch: header=%d actual=%d", length, len(raw))
	}
	body := raw[8 : length-1]
	got := map[string]string{}
	for len(body) > 0 {
		i := bytes.IndexByte(body, 0)
		if i < 0 {
			t.Fatalf("malformed key")
		}
		key := string(body[:i])
		body = body[i+1:]
		if key == "" {
			break
		}
		j := bytes.IndexByte(body, 0)
		if j < 0 {
			t.Fatalf("malformed value")
		}
		got[key] = string(body[:j])
		body = body[j+1:]
	}
	return got
}

func TestRewriteStartup_InjectsWhenAbsent(t *testing.T) {
	in := buildStartup("user", "alice", "database", "mydb")
	out, err := rewriteStartup(in, "myapp", false)
	if err != nil {
		t.Fatalf("rewriteStartup: %v", err)
	}
	kv := parseStartupKV(t, out)
	if kv["application_name"] != "myapp" {
		t.Errorf("application_name = %q, want %q", kv["application_name"], "myapp")
	}
	if kv["user"] != "alice" || kv["database"] != "mydb" {
		t.Errorf("original keys lost: %v", kv)
	}
}

func TestRewriteStartup_PreservesExisting(t *testing.T) {
	in := buildStartup("user", "alice", "application_name", "client-set")
	out, err := rewriteStartup(in, "myapp", false)
	if err != nil {
		t.Fatalf("rewriteStartup: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Errorf("message was modified when application_name already present")
	}
	kv := parseStartupKV(t, out)
	if kv["application_name"] != "client-set" {
		t.Errorf("application_name = %q, want %q", kv["application_name"], "client-set")
	}
}

func TestRewriteStartup_PassthroughNonV3(t *testing.T) {
	// CancelRequest: length=16, code=80877102, then pid, secret.
	var raw [16]byte
	binary.BigEndian.PutUint32(raw[0:4], 16)
	binary.BigEndian.PutUint32(raw[4:8], 80877102)
	binary.BigEndian.PutUint32(raw[8:12], 12345)
	binary.BigEndian.PutUint32(raw[12:16], 67890)
	out, err := rewriteStartup(raw[:], "myapp", false)
	if err != nil {
		t.Fatalf("rewriteStartup: %v", err)
	}
	if !bytes.Equal(raw[:], out) {
		t.Errorf("CancelRequest was modified")
	}
}

func TestRewriteStartup_EmptyInjectIsNoop(t *testing.T) {
	in := buildStartup("user", "alice")
	out, err := rewriteStartup(in, "", false)
	if err != nil {
		t.Fatalf("rewriteStartup: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Errorf("message modified despite empty injectAppName")
	}
}

func TestRewriteStartup_RejectsMalformed(t *testing.T) {
	// Length claims 50 but slice is only 20 bytes.
	bad := make([]byte, 20)
	binary.BigEndian.PutUint32(bad[:4], 50)
	binary.BigEndian.PutUint32(bad[4:8], pgProtoV3)
	if _, err := rewriteStartup(bad, "myapp", false); err == nil {
		t.Errorf("expected error for length mismatch")
	}

	// v3 but no terminating null: the 8-byte body is fully occupied
	// and its last byte is 'z', not 0.
	noTerm := make([]byte, 16)
	binary.BigEndian.PutUint32(noTerm[:4], 16)
	binary.BigEndian.PutUint32(noTerm[4:8], pgProtoV3)
	copy(noTerm[8:], []byte("user\x00xyz"))
	if _, err := rewriteStartup(noTerm, "myapp", false); err == nil {
		t.Errorf("expected error for missing terminator")
	}
}

func TestParseVmsTXT(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want map[string]string
	}{
		{
			name: "single record, comma-separated",
			in:   []string{"1a2b3c4d ord,5e6f7a8b iad"},
			want: map[string]string{"1a2b3c4d": "ord", "5e6f7a8b": "iad"},
		},
		{
			name: "multiple records",
			in:   []string{"1a2b3c4d ord", "5e6f7a8b iad"},
			want: map[string]string{"1a2b3c4d": "ord", "5e6f7a8b": "iad"},
		},
		{
			name: "extra whitespace",
			in:   []string{"  1a2b3c4d   ord  ,  5e6f7a8b iad"},
			want: map[string]string{"1a2b3c4d": "ord", "5e6f7a8b": "iad"},
		},
		{
			name: "garbage skipped",
			in:   []string{"junk,1a2b3c4d ord"},
			want: map[string]string{"1a2b3c4d": "ord"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseVmsTXT(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("%q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestClassifyPeer(t *testing.T) {
	// On Fly with Tailscale enabled: 6PN trusted, Tailscale trusted.
	defer func(prev bool) { onFly = prev }(onFly)
	defer func(prev bool) { *tailscaleEnabled = prev }(*tailscaleEnabled)
	onFly = true
	*tailscaleEnabled = true
	cases := []struct {
		addr string
		want peerKind
	}{
		{"[fdaa:0:1:2::3]:5432", peerFly},
		{"100.64.1.2:5432", peerTailscale},          // tailscale CGNAT
		{"[fd7a:115c:a1e0::1]:5432", peerTailscale}, // tailscale ULA
		{"192.0.2.1:5432", peerReject},
		{"[2001:db8::1]:5432", peerReject},
		{"garbage", peerReject},
	}
	for _, c := range cases {
		if got := classifyPeer(c.addr); got != c.want {
			t.Errorf("classifyPeer(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestClassifyPeer_OffFlyRejects6PN(t *testing.T) {
	// Off Fly (but Tailscale enabled): 6PN NOT trusted; Tailscale still is.
	defer func(prev bool) { onFly = prev }(onFly)
	defer func(prev bool) { *tailscaleEnabled = prev }(*tailscaleEnabled)
	onFly = false
	*tailscaleEnabled = true
	if got := classifyPeer("[fdaa:0:1:2::3]:5432"); got != peerReject {
		t.Errorf("off-Fly fdaa = %v, want reject", got)
	}
	if got := classifyPeer("100.64.1.2:5432"); got != peerTailscale {
		t.Errorf("off-Fly tailscale = %v, want tailscale", got)
	}
}

func TestClassifyPeer_TailscaleDisabledRejectsTailscale(t *testing.T) {
	// Tailscale disabled (no TS_AUTHKEY): its ranges are not trusted.
	defer func(prev bool) { *tailscaleEnabled = prev }(*tailscaleEnabled)
	*tailscaleEnabled = false
	if got := classifyPeer("100.64.1.2:5432"); got != peerReject {
		t.Errorf("tailscale-disabled 100.64 = %v, want reject", got)
	}
	if got := classifyPeer("[fd7a:115c:a1e0::1]:5432"); got != peerReject {
		t.Errorf("tailscale-disabled fd7a = %v, want reject", got)
	}
}

func TestRewriteStartup_TailscaleAppendsToClientName(t *testing.T) {
	in := buildStartup("user", "alice", "application_name", "psql")
	out, err := rewriteStartup(in, "amit@example.com", true) // fromTS
	if err != nil {
		t.Fatalf("rewriteStartup: %v", err)
	}
	kv := parseStartupKV(t, out)
	if kv["application_name"] != "psql (amit@example.com)" {
		t.Errorf("application_name = %q, want %q", kv["application_name"], "psql (amit@example.com)")
	}
	if kv["user"] != "alice" {
		t.Errorf("user lost: %v", kv)
	}
}

func TestRewriteStartup_TailscaleInjectsWhenAbsent(t *testing.T) {
	in := buildStartup("user", "alice")
	out, err := rewriteStartup(in, "amit@example.com", true)
	if err != nil {
		t.Fatalf("rewriteStartup: %v", err)
	}
	if kv := parseStartupKV(t, out); kv["application_name"] != "amit@example.com" {
		t.Errorf("application_name = %q, want %q", kv["application_name"], "amit@example.com")
	}
}

func TestFinalAppName(t *testing.T) {
	cases := []struct {
		client, id string
		ts         bool
		want       string
	}{
		{"psql", "amit", true, "psql (amit)"}, // TS: append
		{"psql", "amit", false, "psql"},       // non-TS: preserve client value
		{"", "amit", true, "amit"},            // absent: use identity
		{"", "amit", false, "amit"},           // absent: Fly inject
		{"psql", "", true, "psql"},            // no identity: unchanged
		{"", "", true, ""},                    // nothing to set
	}
	for _, c := range cases {
		if got := finalAppName(c.client, c.id, c.ts); got != c.want {
			t.Errorf("finalAppName(%q,%q,%v) = %q, want %q", c.client, c.id, c.ts, got, c.want)
		}
	}
}
