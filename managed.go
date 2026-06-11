// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// managed.go implements "managed" upstreams: entries in
// --destination-pg-dbs that carry credentials. For those, the proxy
// authenticates to the upstream itself (SCRAM/md5/cleartext via
// pgconn) and clients connect credential-less. The client's startup
// user is ignored; only the database name is honored.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// serveManaged handles one client connection to a managed upstream.
// The client connects credential-less: the proxy reads its
// StartupMessage, discards the client's user, picks the database via
// chooseDatabase, authenticates to the upstream itself with the
// configured credentials (pgconn speaks SCRAM/md5/cleartext), replays
// the resulting session state to the client, and then splices bytes
// like the passthrough path.
func (p *proxy) serveManaged(ctx context.Context, sessionID int64, c net.Conn, injectAppName string) error {
	var buf [8]byte
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("initial magic read: %v", err)
	}

	var clientConn net.Conn
	var raw []byte
	var err error
	switch {
	case buf == sslStart:
		io.WriteString(c, "S")
		s := tls.Server(c, &tls.Config{
			ServerName:   p.upstreamHost,
			Certificates: p.downstreamCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err := s.HandshakeContext(ctx); err != nil {
			p.errors.Add("client-tls", 1)
			return fmt.Errorf("client TLS handshake: %v", err)
		}
		clientConn = s
		raw, err = readStartupMessage(clientConn)
	case isPlaintextStartup(buf):
		clientConn = c
		raw, err = readStartupMessageWithPrefix(c, buf[:])
	default:
		p.errors.Add("client-bad-protocol", 1)
		return fmt.Errorf("unrecognized initial packet = % 02x", buf)
	}
	if err != nil {
		p.errors.Add("bad-startup", 1)
		return fmt.Errorf("reading client startup: %v", err)
	}

	params, err := parseStartupParams(raw)
	if err != nil {
		p.errors.Add("bad-startup", 1)
		return fmt.Errorf("parsing client startup: %v", err)
	}
	db := chooseDatabase(params["user"], params["database"], p.cfg.DBName)
	appName := params["application_name"]
	if appName == "" {
		appName = injectAppName
	}

	cfg, err := pgconn.ParseConfig("postgres://" + p.upstreamAddr + "/?sslmode=disable")
	if err != nil {
		return fmt.Errorf("building upstream config: %v", err)
	}
	cfg.User = p.cfg.User
	cfg.Password = p.cfg.Password
	cfg.Database = db
	cfg.TLSConfig = &tls.Config{
		ServerName: p.upstreamHost,
		RootCAs:    p.upstreamCertPool,
		MinVersion: tls.VersionTLS12,
	}
	cfg.Fallbacks = nil
	cfg.ConnectTimeout = 10 * time.Second
	cfg.RuntimeParams = map[string]string{}
	for k, v := range params {
		switch k {
		case "user", "database", "application_name", "replication":
			// Handled above (or, for replication, not supported).
		default:
			cfg.RuntimeParams[k] = v
		}
	}
	if appName != "" {
		cfg.RuntimeParams["application_name"] = appName
	}

	upstream, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		p.errors.Add("upstream-connect", 1)
		writeManagedError(clientConn, fmt.Sprintf("pgproxy: upstream connection failed: %v", err))
		return fmt.Errorf("upstream connect: %v", err)
	}
	if err := upstream.SyncConn(ctx); err != nil {
		upstream.Close(ctx)
		return fmt.Errorf("syncing upstream conn: %v", err)
	}
	hj, err := upstream.Hijack()
	if err != nil {
		upstream.Close(ctx)
		return fmt.Errorf("hijacking upstream conn: %v", err)
	}
	defer hj.Conn.Close()
	log.Printf("%d: connected upstream as user %q database %q", sessionID, cfg.User, cfg.Database)

	if err := writeManagedHandshake(clientConn, hj.ParameterStatuses, hj.PID, hj.SecretKey, hj.TxStatus); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("replaying handshake to client: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(hj.Conn, clientConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, hj.Conn)
		errc <- err
	}()
	if err := <-errc; err != nil {
		return fmt.Errorf("session terminated with error: %v", err)
	}
	return nil
}

// parseStartupParams parses a Postgres v3 StartupMessage into its
// key/value parameters. Non-v3 packets (SSLRequest, CancelRequest,
// older protocols) and malformed messages return an error.
func parseStartupParams(raw []byte) (map[string]string, error) {
	if len(raw) < 9 {
		return nil, fmt.Errorf("startup too short: %d", len(raw))
	}
	length := int(binary.BigEndian.Uint32(raw[:4]))
	if length != len(raw) {
		return nil, fmt.Errorf("startup length mismatch: header=%d actual=%d", length, len(raw))
	}
	if proto := binary.BigEndian.Uint32(raw[4:8]); proto != pgProtoV3 {
		return nil, fmt.Errorf("not a v3 startup message (protocol %08x)", proto)
	}
	if raw[length-1] != 0 {
		return nil, fmt.Errorf("startup not null-terminated")
	}
	params := map[string]string{}
	body := raw[8 : length-1]
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
		params[key] = string(body[:j])
		body = body[j+1:]
	}
	return params, nil
}

// chooseDatabase picks the upstream database for a managed
// connection. The client's database param wins, except when it is
// absent or equal to the client's user: drivers that weren't given a
// database auto-fill it with the username (psql, libpq, pgx,
// node-postgres all do), so database==user means "not specified" and
// the configured default applies. An empty result lets the upstream
// default the database to the role name.
func chooseDatabase(clientUser, clientDB, defaultDB string) string {
	if clientDB != "" && clientDB != clientUser {
		return clientDB
	}
	return defaultDB
}

// writeManagedHandshake replays the upstream session state to the
// client after the proxy authenticated on its behalf:
// AuthenticationOk, the upstream's ParameterStatus set, its real
// BackendKeyData, and ReadyForQuery.
func writeManagedHandshake(w io.Writer, params map[string]string, pid, secret uint32, txStatus byte) error {
	var buf []byte
	var err error
	if buf, err = (&pgproto3.AuthenticationOk{}).Encode(buf); err != nil {
		return err
	}
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if buf, err = (&pgproto3.ParameterStatus{Name: name, Value: params[name]}).Encode(buf); err != nil {
			return err
		}
	}
	if buf, err = (&pgproto3.BackendKeyData{ProcessID: pid, SecretKey: secret}).Encode(buf); err != nil {
		return err
	}
	if buf, err = (&pgproto3.ReadyForQuery{TxStatus: txStatus}).Encode(buf); err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// writeManagedError sends the client a FATAL ErrorResponse, so a
// failed upstream connection surfaces as a normal Postgres error
// instead of an unexplained hangup.
func writeManagedError(w io.Writer, msg string) error {
	buf, err := (&pgproto3.ErrorResponse{
		Severity:            "FATAL",
		SeverityUnlocalized: "FATAL",
		Code:                "28000", // invalid_authorization_specification
		Message:             msg,
	}).Encode(nil)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// isPlaintextStartup reports whether the first 8 bytes of a client
// connection look like a plaintext v3 StartupMessage: a plausible
// length followed by the v3 protocol version. (The previous check
// compared against a fixed 86-byte constant, which rejected
// sslmode=disable clients whose startup wasn't exactly 86 bytes.)
func isPlaintextStartup(buf [8]byte) bool {
	length := binary.BigEndian.Uint32(buf[0:4])
	if length < 8 || length > 65536 {
		return false
	}
	return binary.BigEndian.Uint32(buf[4:8]) == pgProtoV3
}
