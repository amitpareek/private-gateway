# Plain-TCP targets + unified port validation

*2026-07-30*

## Problem

Some upstreams are neither Postgres nor HTTP. The immediate case is Sportradar
MTS (`mtsgate-ci.betradar.com:5671`, AMQP over TLS): it is IP-allowlisted, and
the allowlisted addresses are this app's fixed Fly egress IPs. Apps therefore
need a way to reach it *through* the gateway.

Two mechanisms already exist and neither fits:

- The `CONNECT` proxy on 8080 tunnels arbitrary TCP, but the client must speak
  HTTP `CONNECT` first. The MTS .NET SDK has no proxy setting.
- The Postgres proxy speaks the Postgres wire protocol and enforces its own
  strict upstream TLS. Both are wrong for an opaque stream.

## Approach

A third proxy: a static, port-per-target byte pipe. Raw TCP carries no
destination metadata, so one listener forwards to exactly one upstream. That is
a real constraint, not a shortcoming — with a small, known set of upstreams it
is also the simplest thing that needs no client-side proxy support.

Rejected alternatives:

- **SNI-based routing on a single port.** Workable (the ClientHello carries
  `server_name` in plaintext), but only for TLS upstreams, and it buys nothing
  until two targets actually collide on a port.
- **SOCKS5.** Solves multiplexing but needs a proxy-aware client, which is the
  thing we don't have.
- **Extending the Postgres proxy.** It carries credential injection and
  `application_name` attribution. A dumb pipe must not inherit either.

### TLS stays end-to-end

The proxy never terminates TLS, sees no plaintext, and needs no certificate or
CA of its own. The client's ClientHello reaches the real upstream and the real
upstream's certificate comes back.

The consequence is client-side: a client dialing `<gateway>:9001` will, by
default, verify the returned certificate against *that* name and fail. The MTS
SDK exposes `SetSslServerName`, which sets RabbitMQ's `SslOption.ServerName` —
both the SNI and the verification target — independently of the dial address.
Verified against the live stage endpoint from the gateway:

```
Protocol version: TLSv1.3
Peer certificate: CN=haproxy.mts-nonprod.sportradar.com
Verification: OK
Verified peername: mtsgate-ci.betradar.com
```

Note the CN is a HAProxy hostname; `mtsgate-ci.betradar.com` is a SAN. Note also
that if `SslServerName` is left unset the SDK does not fail — it switches to
accepting `RemoteCertificateNameMismatch`, silently disabling name validation.

## Design

### `tcpproxy.go`

One new file. Accept → classify the peer → dial the target → copy bytes both
ways until either side ends.

- **Source gating** reuses `classifyPeer`, matching the Postgres listeners:
  Fly 6PN always, tailnet when `--tailscale-enabled`. Rejected peers are closed
  immediately and counted.
- **Keepalives** on both legs, no idle deadline. MTS feed and ticket
  connections are long-lived and idle between bets; an idle timeout would
  silently drop them.
- **Teardown** follows `httpproxy.go`: two copy goroutines, the first to finish
  tears down both. Consistent with the sibling and sufficient here — no upstream
  in scope relies on TCP half-close.
- **expvar** per target under `tcp_<name>`, mirroring the Postgres proxy's
  `pgproxy_<name>`.

### Config

`DESTINATION_TCP_TARGETS` → `--destination-tcp-targets`, a JSON array mirroring
`DESTINATION_PG_DBS` minus the credential fields:

```json
[{"name":"mts","listen":9001,"target":"mtsgate-ci.betradar.com:5671"}]
```

Empty is valid, as with the Postgres list.

### Unified port validation

One table, built and validated before any listener binds, covering every port
the process claims: Postgres entries, TCP entries, the `CONNECT` proxy, the
debug/dev page, and the DNS forwarder. Any collision is fatal, naming both
claimants:

```
port 9001 claimed by tcp target "mts" and pg db "admin"
```

This replaces a real gap: today's `seenPort` compares Postgres entries only
against each other, so a Postgres entry on 8080 binds first and the `CONNECT`
listener then dies with a bare `address already in use` that names nothing.

Reserved ranges, enforced as hard errors:

| kind | range |
|---|---|
| Postgres | 5400–6000 |
| plain TCP | 9000–9999 |

Live config uses 5432 and 5433, both inside the Postgres range, so enforcement
is compatible with what is deployed. The ranges also keep both kinds clear of
the fixed infrastructure ports (80, 53, 8080) and of Fly's own `hallpass` on 22.

Failure is `log.Fatalf` before any bind, so a bad config fails the container
start rather than half-binding and serving a partial gateway.

## Testing

No live upstream is involved:

- Table-driven validation cases: in-range, out-of-range each side, pg/tcp
  collision, pg/CONNECT collision, duplicate names, malformed targets, and the
  empty config.
- An in-process pipe test: local echo listener as the "upstream", a `tcpProxy`
  in front, assert bytes survive both directions and that the session counters
  move.

## Out of scope

SNI routing, SOCKS5, per-target access policy finer than `classifyPeer`, and
any change to the Postgres or `CONNECT` proxies beyond joining the shared port
table.
