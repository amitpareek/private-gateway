# private-gateway — project reference

## Overview

`private-gateway` is a private, 6PN-only gateway for Fly.io apps. Its largest component is a
Postgres wire-protocol proxy fronting upstream Postgres (e.g. Neon), which per database can
run as:

- **managed** — entry carries `user`+`password`; the proxy authenticates to the upstream
  itself and clients connect credential-less (client user ignored, only the db name honored).
- **passthrough** — no credentials; the client supplies real upstream credentials.

It also enforces strict upstream TLS, injects an `application_name` for attribution, serves
an HTTPS `CONNECT` forward proxy (so Fly apps egress via this app's fixed IP), and a small
dev/reference page. The Postgres proxy itself (`pgproxy.go`) is a fork kept close to upstream
`tailscale.com/cmd/pgproxy` — the project began as that fork and kept the filename as its
scope widened past Postgres, which is why the component and the project are named
differently.

## Architecture decision: real `tailscaled`, not `tsnet` ("Approach B")

The proxy used to embed Tailscale via **tsnet** (userspace). tsnet **cannot act as a real
subnet router**: its netstack accepts forwarded packets but RSTs any TCP flow that has no
local listener, so advertising a route gave ICMP/ping reachability to Fly 6PN apps but TCP
(HTTP, Postgres) was refused. That blocked the actual goal — reaching `*.internal` apps over
Tailscale.

**Approach B** drops tsnet and runs a real `tailscaled` (TUN device) in the container. The
Linux kernel (`ip_forward=1`) forwards all protocols, exactly like the reference project
[fly-apps/tailscale-router](https://github.com/fly-apps/tailscale-router). This makes the Go
binary fully Tailscale-free (clean Tailscale/Fly segregation) and fixes `.internal` for good.

**Status:** implemented on branch `approach-b`; `main` (commit `d0858c9`) is still the tsnet
design until merged. Runtime not yet deploy-verified on Fly (see below).

## Target architecture (two processes per machine)

- **`tailscaled`** (TUN) — the only Tailscale component. Joins the tailnet, advertises the
  org 6PN `/48` + exit node; the kernel forwards.
- **`private-gateway`** (Go) — a 6PN-only service: Postgres proxy + `CONNECT` proxy + dev page +
  `.internal` DNS forwarder.

Flow: tailnet client → `*.internal` → (Tailscale split DNS sends the query to this node) →
`private-gateway` DNS forwarder → Fly resolver (`fdaa::3`) → returns 6PN AAAA → kernel subnet route →
target's 6PN listener.

## Code segregation

**Fly / proxy layer — the `private-gateway` Go binary (no `tailscale.com` import):**

| File | Role |
|---|---|
| `pgproxy.go` | Pure Postgres wire proxy: strict upstream TLS + serve loop. Upstream-faithful; customizations are `// EXT` hooks. |
| `credentials-manager.go` | Credential management ("managed" mode): the proxy authenticates to the upstream itself so clients connect credential-less. Also the shared StartupMessage read/detect helpers. |
| `httpproxy.go` | HTTPS `CONNECT` forward proxy (outbound via the fixed Fly egress IP). |
| `tcpproxy.go` | Plain-TCP forwarder: one listen port per upstream, byte-for-byte, no parsing and no TLS termination. Kept separate from the Postgres proxy so credential injection and attribution can't leak into a dumb pipe. |
| `dns.go` | The `.internal` DNS forwarder (Go companion to `fly-router.sh`): relays to `DNS_RESOLVER`, the self → Tailscale-IP rewrite for the bare `<app>.internal` (`dnsIsSelf` is an exact match, so `<region>.<app>.internal` still selects a region), and the `<app>.<env>` alias scheme (`ALIAS_DOMAIN`). |
| `fly.go` | All Fly glue: multi-DB config, `runProxies` bootstrap, dev page, source gating (`classifyPeer`, auto-trusts Tailscale always + Fly 6PN when `onFly`), and `application_name` attribution (Fly PTR/TXT + Tailscale WhoIs over the local socket + StartupMessage rewrite). |

**fly-router / Tailscale layer — shell/Docker (no Go):**

| File | Role |
|---|---|
| `fly-router.sh` | Derive the org `/48`, `sysctl ip_forward`, start `tailscaled`, `tailscale up` (advertise routes + exit node). Modeled on `fly-apps/tailscale-router`. |
| Dockerfile | Builds the binary; installs `tailscale` + `iptables`/`ip6tables`; bundles the scripts. |
| `entrypoint.sh` | Orchestrator: run `fly-router.sh`, then `exec private-gateway`. |

Rule: **Tailscale = shell/Docker; Fly = Go.** They never mix in one file.

## Configuration

All config is env-driven. Setting `TS_AUTHKEY` enables Tailscale (omit it for a plain
Fly 6PN proxy); everything else has a
default chosen for how we run today. Set non-secrets in `fly.toml [env]`, secrets via
`fly secrets set`.

### Tailscale on/off (secret)

| Env | Default | Why |
|---|---|---|
| `TS_AUTHKEY` | — (unset = Tailscale off) | Presence is the on-switch for Tailscale: with it, `fly-router.sh` brings up `tailscaled` and the proxy trusts tailnet sources; without it, Tailscale is skipped and private-gateway is a plain Fly 6PN proxy. Use ephemeral+reusable so dead nodes self-clean. The entrypoint surfaces presence as `--tailscale-enabled` and drops the secret before exec'ing the proxy. |

### Common (good defaults; override only to change behavior)

| Env | Default | Why this default |
|---|---|---|
| `DESTINATION_PG_DBS` (secret) | empty | App must boot before any DB is configured; add later via secret. |
| `DESTINATION_TCP_TARGETS` (secret) | empty | Same reasoning as the DB list. Plain-TCP forwards for upstreams that are neither Postgres nor HTTP and that IP-allowlist our egress IP. One listen port per target — raw TCP has no hostname to route on. Listen ports must fall in 9000-9999 (Postgres uses 5400-6000); every port the process binds is checked for collisions before anything binds, and a clash is fatal. |
| `TS_HOSTNAME` | `$FLY_MACHINE_ID-$FLY_REGION-$FLY_APP_NAME` | Machine ID makes every ephemeral node uniquely named, avoiding MagicDNS `-1/-2` collisions across restarts/regions. |
| `TS_ADVERTISE_ROUTES` | auto-derive org `/48` from `fly-local-6pn` | Advertise exactly the reachable 6PN range, not the whole `fdaa::/16`. |
| `TS_ADVERTISE_EXIT_NODE` | `true` | We want every machine usable as a region-specific egress exit node. |
| `DNS_RESOLVER` | `[fdaa::3]:53` on Fly, else empty | Upstream resolver the forwarder relays `*.internal` to. Auto-defaults to Fly's `fdaa::3` when on Fly (no config); generic name so another provider can point it at theirs; empty disables. |
| `ALIAS_DOMAIN` | empty (off) | Pseudo-suffix (e.g. `prod`, `stage`) that maps `<app>.<ALIAS_DOMAIN>` to `<app>.<INTERNAL_DOMAIN>`, resolves it via `DNS_RESOLVER`, and answers under the alias name. Lets one tailnet client reach `core.prod` and `core.stage` at once (via Tailscale split DNS). Empty disables the feature. |
| `INTERNAL_DOMAIN` | `internal` on Fly, else empty | Real internal domain appended to the short name after stripping `ALIAS_DOMAIN`. `internal` on Fly (`core.prod`→`core.internal`); empty for bare service names on Docker platforms (`core.stage`→`core`, resolved by Docker DNS). |

### Advanced (defaults are fine; rarely touched)

| Env | Default | Why this default |
|---|---|---|
| `TS_ACCEPT_DNS` | `false` | Keep the node on Fly's resolver so it (and the forwarder) can reach `fdaa::3` / resolve `.internal`; Tailscale must not overwrite `resolv.conf`. |
| `TS_ACCEPT_ROUTES` | `false` | This node is a router, not a consumer; it needn't pull other nodes' subnet routes. |
| `TS_SNAT_SUBNET_ROUTES` | `true` | SNAT lets forwarded subnet traffic get replies; without it Fly 6PN can't route returns to Tailscale IPs. |
| `TS_STATE_DIR` | `/tmp/tailscale` | tmpfs = ephemeral state, so each restart re-auths cleanly (matches the ephemeral key). |
| `TS_CONTROL_URL` | — (Tailscale's) | Defaults to Tailscale's control plane; set only for self-hosted Headscale. |
| `TS_EXTRA_ARGS` | — | Escape hatch for `tailscale up` flags we didn't surface, so no rebuild is needed. |
| `UPSTREAM_CA_FILE` | `/etc/ssl/certs/ca-certificates.crt` | Standard CA path in the Alpine image; upstreams use public CAs. |
| `FLY_LISTEN_HOST` | `[::]` | Bind all interfaces so 6PN + routed traffic reach the listeners; source is gated by `classifyPeer`. |
| `HTTP_PROXY_LISTEN` | `[::]:8080` | Fixed-egress `CONNECT` proxy port; gated to 6PN sources (plus the tailnet if `HTTP_PROXY_ALLOW_TAILSCALE`). |
| `HTTP_PROXY_ALLOW_TAILSCALE` | `false` | The `CONNECT` proxy lends out this app's *fixed Fly egress IP*, so admitting the whole tailnet is a policy choice — not implied by running Tailscale. Off by default. Turn on to make `*.internal:8080` usable from the tailnet at all: the DNS self-rewrite answers those names with the node's Tailscale IP, which bypasses the subnet route and its SNAT, so such clients arrive as `peerTailscale` rather than `peerFly`. |
| `DEBUG_PORT` | `80` | Serves the dev page + `/debug/vars`; convenient over 6PN. |
| `TS_SOCKET` | `/var/run/tailscale/tailscaled.sock` | Local `tailscaled` API socket; private-gateway queries it (raw HTTP) to WhoIs Tailscale clients for `application_name`. Shared with `fly-router.sh`. |

Fly injects `FLY_APP_NAME`, `FLY_REGION`, `FLY_MACHINE_ID`, `FLY_PRIVATE_IP` automatically —
do not set these.

**No env var (auto-detected via `FLY_APP_NAME` = "on Fly"):**
- **Trusted sources** (`classifyPeer`): Tailscale ranges are *always* accepted (they're
  Tailscale-exclusive, so harmless when unused); Fly 6PN (`fdaa::/16`) is accepted *only on
  Fly*. So off-Fly the tailnet is the access path — nothing to configure. The `CONNECT`
  proxy is the one exception: it narrows to `peerFly` unless `HTTP_PROXY_ALLOW_TAILSCALE`
  is set, because it hands out the fixed Fly egress IP.
- **`DNS_RESOLVER`** defaults to Fly's `[fdaa::3]:53` on Fly, empty (forwarder off) elsewhere.
- **DNS self-rewrite** (answer own `*.internal` with the node's Tailscale IP) is on whenever
  `FLY_APP_NAME` is present and the forwarder is running. Falls back to plain forwarding until
  a Tailscale IP exists. See Decisions.

## Environment aliases (`<app>.<env>`)

`ALIAS_DOMAIN`/`INTERNAL_DOMAIN` let a tailnet client reach apps by an
environment-tagged name — `core.prod`, `bo.prod`, `core.stage` — even when a single dev
opens prod and stage at once. It builds on the existing DNS forwarder (`dns.go`):

- **Mechanism:** a query for `<app>.<ALIAS_DOMAIN>` is rewritten to `<app>.<INTERNAL_DOMAIN>`
  (`aliasTarget`), resolved via `DNS_RESOLVER` (`resolveAlias`, using a `net.Resolver` that
  dials the configured resolver), and answered **under the original alias name** via the
  same `0xC0 0x0C` compression-pointer builder (`dnsAnswerMulti`, one A/AAAA RR per address
  so multi-instance apps keep load-balancing). The check sits between `dnsSelfAnswer` and
  the plain forward path in `serveDNSUDP`/`handleDNSTCP`; a non-match returns nil and falls
  through to forwarding. Stores no records — each answer is computed live (TTL 30s).
- **Provider-generic:** on Fly `INTERNAL_DOMAIN` auto-defaults to `internal` (`core.prod` →
  `core.internal` → `[fdaa::3]:53`); it's **purely additive** — `core.internal` is
  unaffected. On Docker platforms (Dokploy/Openship) set `DNS_RESOLVER=127.0.0.11:53` and
  leave `INTERNAL_DOMAIN` empty so `core.stage` resolves the bare Docker service `core`
  (the gateway container must share the app's Docker network).
- **One tailnet, a gateway per environment.** A device's `tailscaled` is on one tailnet at
  a time, so both gateways + all devs join **one** tailnet; Tailscale **split DNS** routes
  `prod` → the Fly gateway and `stage` → the stage gateway (each to that gateway's Tailscale
  IP). Prod vs stage isolation is via ACLs/tags, not separate networks. DNS carries no port,
  so clients connect on the app's own port (`core.prod:5432`), exactly like `*.internal`.
- **Persistence:** split DNS points at the gateway's *Tailscale IP*, so give each gateway a
  persistent `TS_STATE_DIR` volume (not the tmpfs default) to keep that IP stable across
  restarts.

## Deployment (one-time Tailscale setup)

Only needed if you're enabling Tailscale (i.e. setting `TS_AUTHKEY`); skip it entirely
for a plain 6PN proxy.

- Create an ephemeral + reusable + tagged auth key → `fly secrets set TS_AUTHKEY=…`.
- Approve the advertised routes in the admin console, or grant an `autoApprovers` ACL to the
  node's tag (recommended, since ephemeral nodes re-register each restart).
- Set Tailscale **split DNS**: `internal` search domain → the node's Tailscale IP.
- The client must keep `accept-dns` on (default) for the split-DNS rule to apply.

**Runtime requirement to verify on Fly:** a TUN device (`/dev/net/tun`) and a writable
`ip_forward` sysctl. The reference app runs on Fly, so this is expected to work; confirm
early during implementation.

## Decisions / scope (current)

- **Per-user attribution via DNS self-rewrite ("Option I").** A tailnet user reaching
  `private-gateway.internal` over the *subnet route* would be attributed only at the router level
  (multi-machine forwarding SNATs the source to the router's 6PN address). To get a real
  per-user `application_name`, the forwarder answers private-gateway's *own* `*.internal` names with
  the node's **Tailscale IP** (auto-enabled on Fly via `FLY_APP_NAME`; `dnsSelfAnswer`). The tailnet
  client then connects **directly to private-gateway over Tailscale** — no subnet route, no SNAT — so
  its real source IP is preserved and `whoisTailscale` resolves the login/tags via the local
  `tailscaled` socket. Works on every port (Postgres, dev page, CONNECT), topology-independent.
  Fly 6PN apps are unaffected — they query Fly's resolver, not us, and still get the 6PN address.
  - **Tailscale identity is *appended*, not just filled in** (`finalAppName`). Clients like
    `psql` always send their own `application_name`, so to keep the human attributable we
    append the login: `psql` → `psql (amit@example.com)`. For non-Tailscale clients we only
    fill `application_name` when it's blank (preserving an app's own name).
  - Single-machine note: even via the 6PN/subnet path, a tailnet user hitting the router's
    *own* 6PN address is delivered locally (no SNAT) and is already identifiable — the
    self-rewrite makes this deterministic and adds the multi-machine + all-ports guarantees.
  - **Only the bare `<app>.internal` is rewritten** (`dnsIsSelf` is an exact match).
    Region- and machine-qualified names (`<region>.<app>.internal`,
    `<id>.vm.<app>.internal`, `vms.<app>.internal`) relay to `DNS_RESOLVER` and keep their
    normal Fly meaning. Rewriting them too collapsed every name onto whichever node
    answered the query, so `fra.<app>.internal` could hand back the *sin* node and picking
    a region by hostname was impossible — which matters because each machine has its own
    fixed egress IP. Trade-off: a tailnet client using a qualified name reaches us over the
    subnet route, so it may be SNATed and attributed at router level rather than per-user;
    the bare name remains the per-user path.
  - Considered alternatives: a port-specific `ip6tables` block (single-machine only, leaky
    across HA routers) and a Tailscale ACL (clean but requires tailnet policy edits). The DNS
    self-rewrite keeps everything in the app and needs no tailnet config.
- Reference implementation: [fly-apps/tailscale-router](https://github.com/fly-apps/tailscale-router).

## Status

- **Shipped on `main` and running on Fly** (app `internal-go-proxy`; remote
  `github.com/amitpareek/private-gateway`, renamed from `go_proxy`). Verified end-to-end:
  subnet routing, `.internal` over the tailnet, `application_name` attribution, optional
  Tailscale (gated on `TS_AUTHKEY`). Go has no `tailscale.com` import (WhoIs over the raw
  LocalAPI socket). `go build`/`vet`/`test` pass.
- `fly.toml` `app` defaults to `private-gateway`, but the **actual app name is set at deploy
  time** (`fly deploy -a <name>`), so the `app =` value is just a placeholder. Currently
  deployed as `internal-go-proxy`.
- **Open item:** `entrypoint.sh`/`fly-router.sh` aren't hardened against a failing
  `tailscale up` crash-looping the container (`set -e`). A past deploy hit a restart loop;
  if it recurs, run `tailscale up` backgrounded with retries and always `exec private-gateway`.
