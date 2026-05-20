// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// extensions.go contains the Fly.io + multi-database +
// application_name + HTTP-proxy customizations layered on top of
// upstream pgproxy. Keeping them out of pgproxy.go makes upstream
// merges manageable; pgproxy.go itself stays close to
// tailscale.com/cmd/pgproxy/pgproxy.go with a handful of EXT hooks.
//
// Added flags (declared below):
//
//	--destination-pg-dbs  JSON array of {name, listen, target}
//	                      describing the Postgres databases this
//	                      proxy fronts. Empty allowed: the proxy
//	                      will still serve the dev page and HTTP
//	                      CONNECT proxy.
//	--fly-listen-host     Host (no port) to bind Fly 6PN listeners
//	                      on; each entry provides its own port.
//	                      Default "[::]". Empty disables Fly listeners.
//	--http-proxy-listen   Kernel TCP listen address for the HTTPS
//	                      CONNECT forward proxy. Default "[::]:8080".
//	                      Empty disables. Gated to Fly 6PN sources.
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
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

// upstreamConfig describes one named Postgres upstream. The proxy
// listens on Listen (on both Tailscale and Fly 6PN) and forwards to
// Target.
type upstreamConfig struct {
	Name   string `json:"name"`
	Listen int    `json:"listen"`
	Target string `json:"target"` // host:port
}

var (
	destinationPgDbs = flag.String("destination-pg-dbs", "", `JSON array of {"name","listen","target"} entries. Empty is allowed.`)
	flyListenHost    = flag.String("fly-listen-host", "[::]", "Host (no port) to bind Fly 6PN listeners on. Empty disables Fly listeners.")
	httpProxyListen  = flag.String("http-proxy-listen", "[::]:8080", "Kernel TCP listen address for the HTTPS CONNECT forward proxy. Empty disables.")
)

// parseDestinationPgDbs parses the --destination-pg-dbs flag value as
// a JSON array of upstreamConfig and validates each entry. An empty
// or whitespace value yields a nil list and no error.
func parseDestinationPgDbs() ([]upstreamConfig, error) {
	s := strings.TrimSpace(*destinationPgDbs)
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
// entry (sharing the upstream CA + tsclient), starts the Tailscale
// and Fly 6PN listeners for each, registers the dev page on the
// debug mux, and brings up the HTTP CONNECT proxy. It is tolerant of
// an empty database list — first launch will commonly have none
// until secrets are set.
func runProxies(ts *tsnet.Server, tsclient *local.Client, upstreamCAPath string, debugMux *http.ServeMux) {
	cfgs, err := parseDestinationPgDbs()
	if err != nil {
		log.Fatalf("--destination-pg-dbs: %v", err)
	}
	if len(cfgs) == 0 {
		log.Printf("no Postgres databases configured. Set DESTINATION_PG_DBS to a JSON array (see the dev page on the debug port).")
	}

	for _, u := range cfgs {
		p, err := newProxy(u.Target, upstreamCAPath, tsclient)
		if err != nil {
			log.Fatalf("db %q: %v", u.Name, err)
		}
		expvar.Publish("pgproxy_"+u.Name, p.Expvar())

		tsLn, err := ts.Listen("tcp", fmt.Sprintf(":%d", u.Listen))
		if err != nil {
			log.Fatalf("tailscale listen for %q on :%d: %v", u.Name, u.Listen, err)
		}
		log.Printf("db %q: Tailscale :%d -> %s", u.Name, u.Listen, u.Target)
		go func(p *proxy, ln net.Listener) { log.Fatal(p.Serve(ln)) }(p, tsLn)

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
			renderDevPage(w, ts, cfgs)
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
}

// renderDevPage writes a small HTML reference page listing the
// configured databases with their Tailscale and Fly 6PN connection
// URLs and target host:port. It also documents how to add/modify
// databases and how to use the HTTP CONNECT proxy. Credentials are
// never displayed — pgproxy never sees them.
func renderDevPage(w http.ResponseWriter, ts *tsnet.Server, cfgs []upstreamConfig) {
	tsHost := ts.Hostname
	if tsclient, err := ts.LocalClient(); err == nil {
		if st, err := tsclient.Status(context.Background()); err == nil && st != nil && st.Self != nil {
			if dn := strings.TrimSuffix(st.Self.DNSName, "."); dn != "" {
				tsHost = dn
			}
		}
	}
	flyApp := os.Getenv("FLY_APP_NAME")
	flyHost := "pgproxy.internal"
	if flyApp != "" {
		flyHost = flyApp + ".internal"
	}

	sorted := append([]upstreamConfig(nil), cfgs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Listen < sorted[j].Listen })

	// Build a sample JSON config preserving whatever is already
	// configured, so devs can copy it and edit.
	sample := sorted
	if len(sample) == 0 {
		sample = []upstreamConfig{
			{Name: "rw", Listen: 5432, Target: "ep-xxx.aws.neon.tech:5432"},
			{Name: "readonly", Listen: 5433, Target: "ep-yyy-pooler.aws.neon.tech:5432"},
		}
	}
	sampleJSON, _ := json.MarshalIndent(sample, "", "  ")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b bytes.Buffer
	b.WriteString(`<!doctype html>
<html><head><meta charset="utf-8"><title>pgproxy</title>
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
<h1>pgproxy</h1>
<p class="note">Reachable to Fly apps over 6PN and to humans over Tailscale.</p>

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
			fmt.Fprintf(&b, "<h3>%s <span class=\"note\">port %d</span></h3>\n", html.EscapeString(u.Name), u.Listen)
			b.WriteString("<table>\n")
			fmt.Fprintf(&b, "<tr><th>Fly 6PN</th><td><code>%s:%d</code></td></tr>\n", html.EscapeString(flyHost), u.Listen)
			fmt.Fprintf(&b, "<tr><th>Tailscale</th><td><code>%s:%d</code></td></tr>\n", html.EscapeString(tsHost), u.Listen)
			fmt.Fprintf(&b, "<tr><th>Target</th><td class=\"target\"><code>%s</code></td></tr>\n", html.EscapeString(u.Target))
			b.WriteString("</table>\n")
		}
	}

	b.WriteString(`<h2>Configure</h2>
<p>Databases are configured via a single Fly secret named
<code>DESTINATION_PG_DBS</code> containing a JSON array. Each entry
has a name, a local listen port, and an upstream target (host:port).
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
apps or <code>` + html.EscapeString(tsHost) + `:&lt;listen&gt;</code> from Tailscale.</p>

<h2>HTTP CONNECT proxy</h2>
<p>For outbound HTTPS calls that need to come from this app's fixed
Fly egress IP (e.g. IP-allowlisted vendors), use the binary's HTTPS
<code>CONNECT</code> forward proxy on <code>` + html.EscapeString(flyHost) + `:8080</code>.
Access is gated to Fly 6PN; Tailscale clients get <code>403</code>.</p>
<pre>curl -x http://` + html.EscapeString(flyHost) + `:8080 https://some-vendor.example.com/</pre>

<h2>application_name attribution</h2>
<p>Unless your client sets <code>application_name</code> explicitly,
the proxy injects one derived from the peer's identity:</p>
<ul>
<li>Fly 6PN clients: <code>&lt;region&gt;.&lt;app&gt;</code>
(derived from PTR + <code>vms.&lt;app&gt;.internal</code> TXT).</li>
<li>Tailscale clients: your tailnet login (or tag list).</li>
</ul>
<p>This shows up in <code>pg_stat_activity.application_name</code> on Neon, so
you can attribute traffic and spot noisy neighbors.</p>

<p class="note">Metrics and debug endpoints under <a href="/debug/vars">/debug/vars</a>.</p>
</body></html>
`)
	w.Write(b.Bytes())
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
// to log plus the application_name to inject.
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
