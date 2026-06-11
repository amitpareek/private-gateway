# pgproxy

The pgproxy server is a proxy for the Postgres wire protocol. [Read
more in our blog
post](https://tailscale.com/blog/introducing-pgproxy/) about it!

The proxy runs an in-process Tailscale instance, accepts postgres
client connections over Tailscale only, and proxies them to the
configured upstream postgres server.

This proxy exists because postgres clients default to very insecure
connection settings: either they "prefer" but do not require TLS; or
they set sslmode=require, which merely requires that a TLS handshake
took place, but don't verify the server's TLS certificate or the
presented TLS hostname.  In other words, sslmode=require enforces that
a TLS session is created, but that session can trivially be
machine-in-the-middled to steal credentials, data, inject malicious
queries, and so forth.

Because this flaw is in the client's validation of the TLS session,
you have no way of reliably detecting the misconfiguration
server-side. You could fix the configuration of all the clients you
know of, but the default makes it very easy to accidentally regress.

Instead of trying to verify client configuration over time, this proxy
removes the need for postgres clients to be configured correctly: the
upstream database is configured to only accept connections from the
proxy, and the proxy is only available to clients over Tailscale.

Therefore, clients must use the proxy to connect to the database. The
client<>proxy connection is secured end-to-end by Tailscale, which the
proxy enforces by verifying that the connecting client is a known
current Tailscale peer. The proxy<>server connection is established by
the proxy itself, using strict TLS verification settings, and the
client is only allowed to communicate with the server once we've
established that the upstream connection is safe to use.

A couple side benefits: because clients can only connect via
Tailscale, you can use Tailscale ACLs as an extra layer of defense on
top of the postgres user/password authentication. And, the proxy can
maintain an audit log of who connected to the database, complete with
the strongly authenticated Tailscale identity of the client.

## Fly.io 6PN mode

This fork extends pgproxy to also accept connections over Fly.io's
private 6PN IPv6 network (`fdaa::/16`), so a single deployment on Fly
can serve both human operators (over Tailscale) and other Fly apps in
the same org (over `pgproxy.internal`).

Peer classification is by source IP range:

- `fdaa::/16` — Fly 6PN peer. `WhoIs` is skipped; the app name is
  derived from a PTR lookup on the source IPv6 address.
- `100.64.0.0/10` and `fd7a:115c:a1e0::/48` — Tailscale peer.
  `WhoIs` is required, same as upstream pgproxy.
- Anything else — rejected (counter `errors{kind=disallowed-source}`).

Authentication to pgproxy itself: there is none. For passthrough
entries auth is delegated to the upstream Postgres server; for
managed entries (see below) the proxy itself logs in upstream with
configured credentials, so network reachability is the only gate.
Access control is enforced by the source-IP classifier on every
accepted connection; Fly does not expose internal TCP ports publicly
by default.

### Per-connection attribution (`application_name`)

The proxy parses the Postgres `StartupMessage` and, if the client did
not set `application_name`, injects one derived from the peer's
identity:

- Tailscale peer: the Tailscale login name (or comma-joined tags for
  a tagged device).
- Fly peer: `<region>.<app>`, derived from the PTR record
  `<machine-id>.vm.<app>.internal` plus a TXT lookup of
  `vms.<app>.internal` to map the machine ID to its region. Both
  results are cached for 5 minutes. If the region lookup fails the
  proxy falls back to just `<app>`; if the PTR fails it falls back
  to `fly-unknown`.

This shows up in `pg_stat_activity.application_name` on Neon, so you
can attribute connection load to a specific app or user. If the
client supplied its own `application_name`, the proxy leaves it
alone.

### HTTP CONNECT forward proxy

pgproxy also runs an HTTPS `CONNECT` forward proxy on
`--http-proxy-listen` (default `[::]:8080`). Only Fly 6PN sources
are accepted; everything else gets `403`. This is intended for
other Fly apps that need to make outbound HTTPS calls through the
deployment's fixed Fly egress IP (e.g. to vendors that require IP
allowlisting). Set `--http-proxy-listen=""` to disable.

### Multiple databases

Databases are configured via a single Fly secret named
`DESTINATION_PG_DBS` containing a JSON array. Each entry has a
name, a local listen port, an upstream `host:port`, and (optionally)
managed credentials:

```sh
fly secrets set DESTINATION_PG_DBS='[
  {"name":"rw","listen":5432,
   "target":"ep-xxx.aws.neon.tech:5432",
   "dbname":"main","user":"app_user","password":"s3cret"},
  {"name":"readonly","listen":5433,
   "target":"ep-yyy-pooler.aws.neon.tech:5432",
   "dbname":"main","user":"app_ro","password":"s3cret2"},
  {"name":"admin","listen":5439,
   "target":"ep-xxx.aws.neon.tech:5432"}
]'
```

Clients pick which DB by port (`pgproxy.internal:5432` vs `:5433`).
Add, rename, or remove databases by editing the JSON and
redeploying. Empty list is allowed — first launch will commonly
have none until you set the secret.

### Managed credentials (credential injection)

Entries with `user` + `password` are **managed**: the proxy
authenticates to the upstream itself (SCRAM-SHA-256, md5, or
cleartext — Neon uses SCRAM), so no app or human ever holds DB
credentials. A client connects with nothing but host, port, and
optionally a database name:

```
postgres://pgproxy.internal:5432/mydb
postgres://pgproxy.internal:5432          # default dbname from config
```

Rules in managed mode:

- The client's username is **ignored** (drivers auto-fill the OS
  user when the connection string has none; the proxy doesn't care).
  Authentication upstream always uses the configured `user`.
- The client's `database` is honored, except when it equals the
  client's username — that's the driver auto-fill pattern for "no
  database specified" — in which case the configured `dbname`
  applies. To use a different role, add another entry on another
  port (or a passthrough entry).
- The client is never asked for a password. If the upstream rejects
  the proxy's credentials, the client gets a normal Postgres FATAL
  error explaining it.
- The upstream's session state (`ParameterStatus`, `BackendKeyData`)
  is replayed to the client, after which the proxy reverts to a dumb
  byte-level splice, exactly like passthrough mode.

Entries without `user`/`password` are **passthrough**: exactly the
original pgproxy behavior, where the client's own credentials flow
through to the upstream. Use one as an escape hatch for admin access
with personal credentials.

Known limitation: the wire-protocol `CancelRequest` (psql Ctrl+C,
driver context-cancel) is not relayed, so an in-flight query can't
be aborted by the client that started it. Use `statement_timeout`
on the role, or `pg_cancel_backend()` from another session — the
injected `application_name` makes the offender easy to find in
`pg_stat_activity`.

### Dev reference page

A small HTML page at `/` on the debug port (default `:80`,
Tailscale-only) lists the configured databases with their Fly 6PN
and Tailscale URLs and target `host:port`. It also documents how to
configure `DESTINATION_PG_DBS` and how to use the HTTP CONNECT
proxy. No credentials are ever shown — pgproxy never sees them.

### Flags added by this fork

- `--destination-pg-dbs` — JSON array of `{name, listen, target}`
  entries, plus optional `{dbname, user, password}` for managed
  (credential-injecting) entries. Empty allowed.
- `--fly-listen-host` (default `[::]`) — host (no port) to bind Fly
  6PN listeners on. Empty disables Fly listeners.
- `--http-proxy-listen` (default `[::]:8080`) — kernel TCP listen
  address for the HTTPS CONNECT forward proxy. Empty disables.

Bind addresses are convenience defaults; the actual access control
is the source-IP classifier, so binding to `[::]` is safe.