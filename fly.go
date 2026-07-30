// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// fly.go is the Fly.io integration layer: ALL Fly-specific Go that
// customizes upstream pgproxy lives here, so pgproxy.go stays close to
// tailscale.com/cmd/pgproxy/pgproxy.go with only a few EXT hooks.
// (Postgres credential injection lives in credentials-manager.go; the
// HTTPS CONNECT proxy in httpproxy.go; the .internal DNS forwarder and the
// <app>.<env> alias scheme in dns.go.)
//
// Contents, in order:
//   - multi-database config: upstreamConfig + --destination-pg-dbs parsing
//   - runProxies: the bootstrap that wires the per-DB listeners, the dev
//     page, the HTTP CONNECT proxy, and the DNS forwarder
//   - the dev / reference page (renderDevPage*)
//   - source gating (classifyPeer) + application_name attribution:
//     Fly 6PN clients by PTR/TXT, Tailscale clients by WhoIs against the
//     local tailscaled socket (whoisTailscale, raw LocalAPI — no
//     tailscale.com import), plus StartupMessage rewriting to inject it
//
// Added flags:
//
//	--destination-pg-dbs   JSON array of {name, listen, target} databases.
//	--fly-listen-host      Host for Fly 6PN listeners. Default "[::]".
//	--http-proxy-listen    HTTPS CONNECT proxy addr. Default "[::]:8080".
//	--tailscaled-socket    Local tailscaled API socket for WhoIs.
//	--tailscale-enabled    Whether Tailscale is up (set by entrypoint.sh).
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// upstreamConfig describes one named Postgres upstream. The proxy
// listens on Listen (Fly 6PN) and forwards to
// Target. If User and Password are set the entry is "managed": the
// proxy itself authenticates to the upstream with those credentials
// and clients connect credential-less (their startup user is
// ignored; only the database name is honored). Without credentials
// the entry is a passthrough, exactly like upstream pgproxy.
type upstreamConfig struct {
	Name     string `json:"name"`
	Listen   int    `json:"listen"`
	Target   string `json:"target"`             // host:port
	DBName   string `json:"dbname,omitempty"`   // managed: default database
	User     string `json:"user,omitempty"`     // managed: upstream role
	Password string `json:"password,omitempty"` // managed: upstream password
}

// managed reports whether the proxy holds credentials for this
// upstream and should authenticate on the client's behalf.
func (u upstreamConfig) managed() bool { return u.User != "" }

var (
	destinationPgDbs = flag.String("destination-pg-dbs", "", `JSON array of {"name","listen","target"} entries. Empty is allowed.`)
	flyListenHost    = flag.String("fly-listen-host", "[::]", "Host (no port) to bind Fly 6PN listeners on. Empty disables Fly listeners.")
	httpProxyListen  = flag.String("http-proxy-listen", "[::]:8080", "Kernel TCP listen address for the HTTPS CONNECT forward proxy. Empty disables.")
	tailscaledSocket = flag.String("tailscaled-socket", "/var/run/tailscale/tailscaled.sock", "Path to the local tailscaled API socket, used to WhoIs Tailscale clients for application_name. No-op if absent.")
	tailscaleEnabled = flag.Bool("tailscale-enabled", false, "Whether Tailscale is running (set by entrypoint from TS_AUTHKEY presence). When false, Tailscale source ranges are not trusted.")

	// Opt-in, and deliberately not implied by --tailscale-enabled: the
	// CONNECT proxy lends out this app's fixed Fly egress IP, so widening
	// it to the whole tailnet is a policy choice, not a consequence of
	// running Tailscale. Only meaningful when --tailscale-enabled.
	httpProxyAllowTailscale = flag.Bool("http-proxy-allow-tailscale", false, "Also allow tailnet clients (Tailscale source ranges) to use the HTTPS CONNECT proxy, not just Fly 6PN. Off by default.")
)

// parseDestinationPgDbs parses the --destination-pg-dbs flag value as
// a JSON array of upstreamConfig and validates each entry. An empty
// or whitespace value yields a nil list and no error.
func parseDestinationPgDbs() ([]upstreamConfig, error) {
	return parseDestinationPgDbsJSON(*destinationPgDbs)
}

func parseDestinationPgDbsJSON(raw string) ([]upstreamConfig, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	var list []upstreamConfig
	if err := json.Unmarshal([]byte(s), &list); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	seenName := map[string]bool{}
	seenPort := map[int]string{}
	for i := range list {
		u := &list[i]
		u.Name = strings.TrimSpace(u.Name)
		u.Target = strings.TrimSpace(u.Target)
		if u.Name == "" {
			return nil, fmt.Errorf("entry %d: empty name", i)
		}
		if u.Listen <= 0 || u.Listen > 65535 {
			return nil, fmt.Errorf("entry %q: invalid listen port %d", u.Name, u.Listen)
		}
		if _, _, err := net.SplitHostPort(u.Target); err != nil {
			return nil, fmt.Errorf("entry %q: target must be host:port (%v)", u.Name, err)
		}
		u.DBName = strings.TrimSpace(u.DBName)
		u.User = strings.TrimSpace(u.User)
		if u.User != "" && u.Password == "" {
			return nil, fmt.Errorf("entry %q: user set without password", u.Name)
		}
		if u.User == "" && u.Password != "" {
			return nil, fmt.Errorf("entry %q: password set without user", u.Name)
		}
		if u.DBName != "" && u.User == "" {
			return nil, fmt.Errorf("entry %q: dbname only applies to managed entries; set user+password too", u.Name)
		}
		if seenName[u.Name] {
			return nil, fmt.Errorf("duplicate name %q", u.Name)
		}
		seenName[u.Name] = true
		if prev, ok := seenPort[u.Listen]; ok {
			return nil, fmt.Errorf("port %d used by both %q and %q", u.Listen, prev, u.Name)
		}
		seenPort[u.Listen] = u.Name
	}
	return list, nil
}

// runProxies parses --destination-pg-dbs, creates one proxy per
// entry (sharing the upstream CA), starts the Fly 6PN listener for
// each, registers the dev page on the debug mux, and brings up the
// HTTP CONNECT proxy. It is tolerant of an empty database list — first
// launch will commonly have none until secrets are set.
func runProxies(upstreamCAPath string, debugMux *http.ServeMux) {
	cfgs, err := parseDestinationPgDbs()
	if err != nil {
		log.Fatalf("--destination-pg-dbs: %v", err)
	}
	if len(cfgs) == 0 {
		log.Printf("no Postgres databases configured. Set DESTINATION_PG_DBS to a JSON array (see the dev page on the debug port).")
	}
	if *flyListenHost == "" {
		log.Printf("warning: --fly-listen-host is empty, so no Postgres listeners will be started.")
	}

	for _, u := range cfgs {
		p, err := newProxy(u.Target, upstreamCAPath)
		if err != nil {
			log.Fatalf("db %q: %v", u.Name, err)
		}
		p.cfg = u
		if u.managed() {
			log.Printf("db %q: managed mode, upstream user %q default db %q", u.Name, u.User, u.DBName)
		}
		expvar.Publish("pgproxy_"+u.Name, p.Expvar())

		if *flyListenHost != "" {
			addr := net.JoinHostPort(strings.Trim(*flyListenHost, "[]"), strconv.Itoa(u.Listen))
			flyLn, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatalf("fly listen for %q on %s: %v", u.Name, addr, err)
			}
			log.Printf("db %q: Fly 6PN %s -> %s", u.Name, addr, u.Target)
			go func(p *proxy, ln net.Listener) { log.Fatal(p.Serve(ln)) }(p, flyLn)
		}
	}

	if debugMux != nil {
		debugMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			renderDevPage(w, cfgs)
		})
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

	// EXT: serve *.internal DNS for tailnet clients (forwarder defined
	// below). The real tailscaled subnet route is set up in fly-router.sh.
	startDNSForwarder()
}

// renderDevPage writes a small HTML reference page listing the
// configured databases with their Fly 6PN connection URLs and target
// host:port. It also documents how to add/modify databases and how to
// use the HTTP CONNECT proxy. Passwords are never displayed.
func renderDevPage(w http.ResponseWriter, cfgs []upstreamConfig) {
	flyApp := os.Getenv("FLY_APP_NAME")
	flyHost := "private-gateway.internal"
	if flyApp != "" {
		flyHost = flyApp + ".internal"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(renderDevPageHTML(flyHost, cfgs))
}

func renderDevPageHTML(flyHost string, cfgs []upstreamConfig) []byte {
	sorted := append([]upstreamConfig(nil), cfgs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Listen < sorted[j].Listen })

	// Build a sample JSON config preserving whatever is already
	// configured, so devs can copy it and edit. Passwords are
	// replaced with a placeholder; they must never reach the page.
	sample := append([]upstreamConfig(nil), sorted...)
	for i := range sample {
		if sample[i].Password != "" {
			sample[i].Password = "<password>"
		}
	}
	if len(sample) == 0 {
		sample = []upstreamConfig{
			{Name: "rw", Listen: 5432, Target: "ep-xxx.aws.neon.tech:5432",
				DBName: "main", User: "app_user", Password: "<password>"},
			{Name: "admin", Listen: 5439, Target: "ep-xxx.aws.neon.tech:5432"},
		}
	}
	sampleJSON, _ := json.MarshalIndent(sample, "", "  ")

	var b bytes.Buffer
	b.WriteString(`<!doctype html>
<html><head><meta charset="utf-8"><title>private-gateway</title>
<style>
body { font-family: -apple-system, system-ui, sans-serif; max-width: 780px; margin: 2em auto; padding: 0 1em; color: #222; line-height: 1.45; }
h1 { margin-bottom: 0.1em; }
h2 { margin-top: 1.8em; border-bottom: 1px solid #eee; padding-bottom: 4px; }
code { background: #f3f3f3; padding: 1px 5px; border-radius: 3px; font-size: 0.95em; }
pre { background: #f3f3f3; padding: 10px 12px; border-radius: 4px; overflow-x: auto; font-size: 0.9em; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 4px 8px; vertical-align: top; }
th { color: #666; font-weight: normal; width: 8em; }
.note { color: #555; font-size: 0.95em; }
.target { color: #555; }
.warn { background: #fff5d6; padding: 10px 12px; border-radius: 4px; border: 1px solid #f0d990; }
</style></head><body>
<h1>private-gateway</h1>
<p class="note">Reachable to Fly apps over 6PN (and to the tailnet via a separate Tailscale subnet router).</p>

<h2>Databases</h2>
`)

	if len(sorted) == 0 {
		b.WriteString(`<div class="warn">
<strong>No databases configured yet.</strong> Set <code>DESTINATION_PG_DBS</code>
as a Fly secret to add some — see <em>Configure</em> below.
</div>
`)
	} else {
		for _, u := range sorted {
			mode := "passthrough"
			if u.managed() {
				mode = "managed"
			}
			fmt.Fprintf(&b, "<h3>%s <span class=\"note\">port %d · %s</span></h3>\n", html.EscapeString(u.Name), u.Listen, mode)
			b.WriteString("<table>\n")
			if u.managed() {
				connPath := ""
				if u.DBName != "" {
					connPath = "/" + u.DBName
				}
				fmt.Fprintf(&b, "<tr><th>Fly 6PN</th><td><code>postgres://%s:%d%s</code></td></tr>\n", html.EscapeString(flyHost), u.Listen, html.EscapeString(connPath))
				fmt.Fprintf(&b, "<tr><th>Upstream user</th><td><code>%s</code> <span class=\"note\">(injected by the proxy; no client credentials needed)</span></td></tr>\n", html.EscapeString(u.User))
				if u.DBName != "" {
					fmt.Fprintf(&b, "<tr><th>Default db</th><td><code>%s</code> <span class=\"note\">(override with any db name in the connection string)</span></td></tr>\n", html.EscapeString(u.DBName))
				}
			} else {
				fmt.Fprintf(&b, "<tr><th>Fly 6PN</th><td><code>%s:%d</code> <span class=\"note\">(client must supply real upstream credentials)</span></td></tr>\n", html.EscapeString(flyHost), u.Listen)
			}
			fmt.Fprintf(&b, "<tr><th>Target</th><td class=\"target\"><code>%s</code></td></tr>\n", html.EscapeString(u.Target))
			b.WriteString("</table>\n")
		}
	}

	b.WriteString(`<h2>Configure</h2>
<p>Databases are configured via a single Fly secret named
<code>DESTINATION_PG_DBS</code> containing a JSON array. Each entry
has a name, a local listen port, and an upstream target (host:port).
With <code>user</code> + <code>password</code> (+ optional default
<code>dbname</code>) the entry is <strong>managed</strong>: the proxy
authenticates to the upstream itself and clients connect with no
credentials at all — the client's username is ignored, and only the
database name in its connection string is honored. Without
credentials the entry is a <strong>passthrough</strong> and clients
must hold real upstream credentials.
Add, rename, or remove databases by editing the secret and redeploying:</p>
<pre>fly secrets set DESTINATION_PG_DBS='`)
	b.WriteString(html.EscapeString(string(sampleJSON)))
	b.WriteString(`'
fly deploy
</pre>
<p class="note">Pick a unique <code>listen</code> port per entry. Conventional
choices: <code>5432</code> for the primary writer, <code>5433</code> for the first
read-only, <code>5434</code> and up for additional read replicas. After
deploying, the entry shows up in <em>Databases</em> above and is
reachable at <code>` + html.EscapeString(flyHost) + `:&lt;listen&gt;</code> from Fly
apps (or via a Tailscale subnet router pointed at Fly 6PN).</p>

<h2>HTTP CONNECT proxy</h2>
<p>For outbound HTTPS calls that need to come from this app's fixed
Fly egress IP (e.g. IP-allowlisted vendors), use the binary's HTTPS
<code>CONNECT</code> forward proxy on <code>` + html.EscapeString(flyHost) + `:8080</code>.
Access is gated to ` + httpProxyAccessNote() + `; other sources get <code>403</code>.</p>
<pre>curl -x http://` + html.EscapeString(flyHost) + `:8080 https://some-vendor.example.com/</pre>

<h2>application_name attribution</h2>
<p>Unless your client sets <code>application_name</code> explicitly,
the proxy injects one derived from the peer's identity:</p>
<ul>
<li>Fly 6PN clients: <code>&lt;region&gt;.&lt;app&gt;</code>
(derived from PTR + <code>vms.&lt;app&gt;.internal</code> TXT).</li>
</ul>
<p>This shows up in <code>pg_stat_activity.application_name</code> on Neon, so
you can attribute traffic and spot noisy neighbors.</p>

<p class="note">Metrics and debug endpoints under <a href="/debug/vars">/debug/vars</a>.</p>
</body></html>
`)
	return b.Bytes()
}

// httpProxyAccessNote names the sources the CONNECT proxy admits, for the
// dev page. Mirrors httpProxy.allowPeer.
func httpProxyAccessNote() string {
	if *httpProxyAllowTailscale {
		return "Fly 6PN and the tailnet"
	}
	return "Fly 6PN"
}

// peerKind classifies the source of an inbound connection.
type peerKind int

const (
	peerReject peerKind = iota
	peerFly
	peerTailscale
)

func (k peerKind) String() string {
	switch k {
	case peerFly:
		return "fly"
	case peerTailscale:
		return "tailscale"
	default:
		return "reject"
	}
}

var (
	flyPrefix   = netip.MustParsePrefix("fdaa::/16")
	tailscaleV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// onFly reports whether we're running on Fly (the platform injects
// FLY_APP_NAME). Used to auto-enable Fly-specific behavior — trusting the
// 6PN source range, the .internal DNS forwarder default, the self-rewrite
// — without any toggle. It's a var so tests can override it.
var onFly = os.Getenv("FLY_APP_NAME") != ""

// classifyPeer returns the peerKind for a remote address string of the
// form "host:port" or "[ipv6]:port". Trusted sources are auto-detected:
// Tailscale ranges are accepted when Tailscale is enabled (TS_AUTHKEY was
// set, surfaced as --tailscale-enabled), and Fly 6PN (fdaa::/16) is
// accepted only when running on Fly. Everything else is rejected.
//
// Note on attribution: traffic forwarded through the subnet router from
// the tailnet is SNATed to a 6PN address, so it classifies as peerFly.
// To be identified as a specific Tailscale user, a client must reach
// private-gateway at its Tailscale IP directly — which is why the forwarder
// answers private-gateway's own *.internal names with our Tailscale IP.
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
	case onFly && flyPrefix.Contains(ip):
		return peerFly
	case *tailscaleEnabled && (tailscaleV4.Contains(ip) || tailscaleV6.Contains(ip)):
		return peerTailscale
	}
	return peerReject
}

// identifyClient resolves the peer identity and returns the strings to
// log plus the application_name to inject. Fly 6PN clients are named by
// reverse lookup (<region>.<app>); direct Tailscale clients are named by
// WhoIs against the local tailscaled (see whoisTailscale). Identity is
// best-effort: a failed lookup yields a fallback label, never a rejected
// connection.
func (p *proxy) identifyClient(ctx context.Context, c net.Conn) (user, machine, appName string, fromTS bool, err error) {
	switch classifyPeer(c.RemoteAddr().String()) {
	case peerFly:
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		ip, _ := netip.ParseAddr(host)
		ident := lookupFlyIdent(ctx, ip)
		return ident, "fly", ident, false, nil
	case peerTailscale:
		login, node := whoisTailscale(ctx, c.RemoteAddr().String())
		if login == "" {
			p.errors.Add("whois-failed", 1)
			login = "tailscale-unknown"
		}
		if node == "" {
			node = "tailscale"
		}
		return login, node, login, true, nil
	default:
		p.errors.Add("disallowed-source", 1)
		return "", "", "", false, fmt.Errorf("rejecting connection from disallowed source %s", c.RemoteAddr())
	}
}

// finalAppName decides the application_name sent upstream. For Tailscale
// clients we always append the tailnet identity, so a human behind a
// client-set name (e.g. psql) is still attributable — "psql" becomes
// "psql (amit@example.com)". For other clients we only fill it in when
// the client left it blank (preserving an app's own name).
func finalAppName(clientVal, identity string, fromTS bool) string {
	if identity == "" {
		return clientVal
	}
	if clientVal == "" {
		return identity
	}
	if fromTS {
		return clientVal + " (" + identity + ")"
	}
	return clientVal
}

// whoisTailscale asks the local tailscaled (over its unix API socket)
// who owns remoteAddr, returning the login name (or comma-joined tags)
// and the node name. It speaks the LocalAPI directly over plain HTTP so
// the binary keeps no tailscale.com dependency. Best-effort: any error
// yields empty strings.
func whoisTailscale(ctx context.Context, remoteAddr string) (login, node string) {
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", *tailscaledSocket)
		},
	}}
	cctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, "GET",
		"http://local-tailscaled.sock/localapi/v0/whois?addr="+url.QueryEscape(remoteAddr), nil)
	if err != nil {
		return "", ""
	}
	req.Host = "local-tailscaled.sock"
	resp, err := hc.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}
	// Decode only the fields we need from the LocalAPI WhoIs response.
	var raw struct {
		Node *struct {
			Name string   `json:"Name"`
			Tags []string `json:"Tags"`
		} `json:"Node"`
		UserProfile *struct {
			LoginName string `json:"LoginName"`
		} `json:"UserProfile"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", ""
	}
	if raw.UserProfile != nil {
		login = raw.UserProfile.LoginName
	}
	if raw.Node != nil {
		node = strings.TrimSuffix(raw.Node.Name, ".")
		if login == "tagged-devices" && len(raw.Node.Tags) > 0 {
			login = strings.Join(raw.Node.Tags, ",")
		}
	}
	return login, node
}

// forwardStartup reads the Postgres StartupMessage from the client side,
// sets application_name via finalAppName (fill-if-blank, or append the
// tailnet identity for Tailscale clients), and writes it to upstream.
func (p *proxy) forwardStartup(clientConn io.Reader, upstream io.Writer, injectAppName string, prefix []byte, hadPrefix, fromTS bool) error {
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
	out, err := rewriteStartup(raw, injectAppName, fromTS)
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

func readStartupMessage(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	return readStartupMessageWithPrefix(r, lenBuf[:])
}

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

func rewriteStartup(raw []byte, injectAppName string, fromTS bool) ([]byte, error) {
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
		return raw, nil // no identity to set or append
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

	// Compute the desired application_name and replace/append/skip.
	idx := -1
	existing := ""
	for i, k := range keys {
		if k == "application_name" {
			idx, existing = i, vals[i]
			break
		}
	}
	newVal := finalAppName(existing, injectAppName, fromTS)
	switch {
	case idx >= 0 && newVal == existing:
		return raw, nil // present and unchanged
	case idx >= 0:
		vals[idx] = newVal // replace (TS append case)
	default:
		keys = append(keys, "application_name")
		vals = append(vals, newVal)
	}

	var out bytes.Buffer
	out.Grow(length + len("application_name") + len(injectAppName) + 8)
	out.Write([]byte{0, 0, 0, 0})
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
