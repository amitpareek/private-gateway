// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// testServerCert returns a self-signed CA-style TLS certificate for
// localhost plus its PEM encoding, for use as both the fake upstream's
// server cert and the proxy's --upstream-ca-file content.
func testServerCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"pgproxy-test"}},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, caPEM
}

// fakePG is a minimal in-process Postgres server: TLS-only, cleartext
// password auth, answers simple queries with canned responses.
type fakePG struct {
	addr     string
	password string // accepted password
	mu       sync.Mutex
	startups []map[string]string
	gotPw    []string
	queries  []string
}

func (f *fakePG) lastStartup() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.startups) == 0 {
		return nil
	}
	return f.startups[len(f.startups)-1]
}

func (f *fakePG) recordedQueries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func startFakePG(t *testing.T, cert tls.Certificate, acceptPassword string) *fakePG {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakePG{addr: ln.Addr().String(), password: acceptPassword}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(t, c, cert)
		}
	}()
	return f
}

func (f *fakePG) handle(t *testing.T, c net.Conn, cert tls.Certificate) {
	defer c.Close()
	var magic [8]byte
	if _, err := io.ReadFull(c, magic[:]); err != nil || magic != sslStart {
		t.Errorf("fakePG: expected SSLRequest, got % 02x (err %v)", magic, err)
		return
	}
	if _, err := c.Write([]byte("S")); err != nil {
		return
	}
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tc.Handshake(); err != nil {
		t.Errorf("fakePG: TLS handshake: %v", err)
		return
	}
	be := pgproto3.NewBackend(tc, tc)
	sm, err := be.ReceiveStartupMessage()
	if err != nil {
		t.Errorf("fakePG: startup: %v", err)
		return
	}
	startup, ok := sm.(*pgproto3.StartupMessage)
	if !ok {
		t.Errorf("fakePG: got %T, want StartupMessage", sm)
		return
	}
	f.mu.Lock()
	f.startups = append(f.startups, startup.Parameters)
	f.mu.Unlock()

	be.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := be.Flush(); err != nil {
		return
	}
	be.SetAuthType(pgproto3.AuthTypeCleartextPassword)
	msg, err := be.Receive()
	if err != nil {
		return
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		t.Errorf("fakePG: got %T, want PasswordMessage", msg)
		return
	}
	f.mu.Lock()
	f.gotPw = append(f.gotPw, pw.Password)
	f.mu.Unlock()
	if pw.Password != f.password {
		be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL",
			Code: "28P01", Message: "password authentication failed for user " + startup.Parameters["user"]})
		be.Flush()
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.4"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: 991199})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return
	}

	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			f.mu.Lock()
			f.queries = append(f.queries, m.String)
			f.mu.Unlock()
			if strings.HasPrefix(m.String, "--") || m.String == ";" {
				be.Send(&pgproto3.EmptyQueryResponse{})
			} else {
				be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			}
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		default:
			t.Errorf("fakePG: unexpected message %T", msg)
			return
		}
	}
}

// startManagedProxy runs a managed-mode proxy in front of target,
// listening on a fresh localhost port, and returns its address.
func startManagedProxy(t *testing.T, cfg upstreamConfig, caPEM []byte) string {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := newProxy(cfg.Target, caFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.cfg = cfg
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for sid := int64(1); ; sid++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(sid int64, c net.Conn) {
				defer c.Close()
				if err := p.serveManaged(context.Background(), sid, c, "fly-test-app"); err != nil {
					// Sessions may outlive the test body; never t.Logf here.
					log.Printf("test proxy: serveManaged: %v", err)
				}
			}(sid, c)
		}
	}()
	return ln.Addr().String()
}

func managedTestSetup(t *testing.T) (*fakePG, string) {
	cert, caPEM := testServerCert(t)
	fake := startFakePG(t, cert, "s3cret")
	target := "localhost:" + fake.addr[strings.LastIndex(fake.addr, ":")+1:]
	proxyAddr := startManagedProxy(t, upstreamConfig{
		Name: "rw", Listen: 0, Target: target,
		DBName: "maindb", User: "app_user", Password: "s3cret",
	}, caPEM)
	return fake, proxyAddr
}

func TestManaged_PlaintextClient_InjectsCredsAndSplices(t *testing.T) {
	fake, proxyAddr := managedTestSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Credential-less client: random user, no password, picks its own db.
	conn, err := pgconn.Connect(ctx, "postgres://whatever@"+proxyAddr+"/clientdb?sslmode=disable")
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close(ctx)

	su := fake.lastStartup()
	if su["user"] != "app_user" {
		t.Errorf("upstream user = %q, want app_user (client user must be ignored)", su["user"])
	}
	if su["database"] != "clientdb" {
		t.Errorf("upstream database = %q, want clientdb (client-chosen)", su["database"])
	}
	if su["application_name"] != "fly-test-app" {
		t.Errorf("upstream application_name = %q, want fly-test-app", su["application_name"])
	}

	// Upstream session state must be replayed to the client.
	if conn.PID() != 4242 {
		t.Errorf("client PID = %d, want 4242 (upstream BackendKeyData)", conn.PID())
	}
	if v := conn.ParameterStatus("server_version"); v != "16.4" {
		t.Errorf("server_version = %q, want 16.4", v)
	}

	// And the splice must carry queries end to end.
	if _, err := conn.Exec(ctx, "SELECT 1").ReadAll(); err != nil {
		t.Fatalf("query through splice: %v", err)
	}
	found := false
	for _, q := range fake.recordedQueries() {
		if q == "SELECT 1" {
			found = true
		}
	}
	if !found {
		t.Errorf("upstream never saw the spliced query; got %v", fake.recordedQueries())
	}
}

func TestManaged_DefaultDatabaseWhenClientOmitsIt(t *testing.T) {
	fake, proxyAddr := managedTestSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// No db in the URL: pgconn auto-fills database=user, which the
	// proxy must treat as "not specified".
	conn, err := pgconn.Connect(ctx, "postgres://whatever@"+proxyAddr+"?sslmode=disable")
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close(ctx)

	if su := fake.lastStartup(); su["database"] != "maindb" {
		t.Errorf("upstream database = %q, want maindb (config default)", su["database"])
	}
}

func TestManaged_ClientAppNameWins(t *testing.T) {
	fake, proxyAddr := managedTestSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgconn.Connect(ctx, "postgres://whatever@"+proxyAddr+"/clientdb?sslmode=disable&application_name=my-svc")
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close(ctx)

	if su := fake.lastStartup(); su["application_name"] != "my-svc" {
		t.Errorf("upstream application_name = %q, want my-svc", su["application_name"])
	}
}

func TestManaged_TLSClient(t *testing.T) {
	fake, proxyAddr := managedTestSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// sslmode=require: TLS to the proxy without cert verification
	// (the proxy serves a self-signed cert, as upstream pgproxy does).
	conn, err := pgconn.Connect(ctx, "postgres://whatever@"+proxyAddr+"/clientdb?sslmode=require")
	if err != nil {
		t.Fatalf("TLS client connect: %v", err)
	}
	defer conn.Close(ctx)

	if su := fake.lastStartup(); su["user"] != "app_user" {
		t.Errorf("upstream user = %q, want app_user", su["user"])
	}
	if _, err := conn.Exec(ctx, "SELECT 1").ReadAll(); err != nil {
		t.Fatalf("query through TLS splice: %v", err)
	}
}

func TestManaged_UpstreamAuthFailureSurfacesAsError(t *testing.T) {
	cert, caPEM := testServerCert(t)
	fake := startFakePG(t, cert, "different-password")
	target := "localhost:" + fake.addr[strings.LastIndex(fake.addr, ":")+1:]
	proxyAddr := startManagedProxy(t, upstreamConfig{
		Name: "rw", Listen: 0, Target: target,
		DBName: "maindb", User: "app_user", Password: "wrong",
	}, caPEM)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := pgconn.Connect(ctx, "postgres://whatever@"+proxyAddr+"/clientdb?sslmode=disable")
	if err == nil {
		t.Fatal("expected connect error, got nil")
	}
	if !strings.Contains(err.Error(), "upstream") {
		t.Errorf("error should mention the upstream failure, got: %v", err)
	}
}
