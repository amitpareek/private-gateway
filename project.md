# pgproxy — project reference

## Overview

`pgproxy` is a Postgres wire-protocol proxy fronting upstream Postgres (e.g. Neon) for
Fly.io apps. Per database it can run as:

- **managed** — entry carries `user`+`password`; the proxy authenticates to the upstream
  itself and clients connect credential-less (client user ignored, only the db name honored).
- **passthrough** — no credentials; the client supplies real upstream credentials.

It also enforces strict upstream TLS, injects an `application_name` for attribution, serves
an HTTPS `CONNECT` forward proxy (so Fly apps egress via this app's fixed IP), and a small
dev/reference page. It's a fork kept close to upstream `tailscale.com/cmd/pgproxy`.

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
- **`pgproxy`** (Go) — a 6PN-only service: Postgres proxy + `CONNECT` proxy + dev page +
  `.internal` DNS forwarder.

Flow: tailnet client → `*.internal` → (Tailscale split DNS sends the query to this node) →
`pgproxy` DNS forwarder → Fly resolver (`fdaa::3`) → returns 6PN AAAA → kernel subnet route →
target's 6PN listener.

## Code segregation

**Fly / proxy layer — the `pgproxy` Go binary (no `tailscale.com` import):**

| File | Role |
|---|---|
| `pgproxy.go` | Pure Postgres wire proxy: strict upstream TLS + serve loop. Upstream-faithful; customizations are `// EXT` hooks. |
| `credentials-manager.go` | Credential management ("managed" mode): the proxy authenticates to the upstream itself so clients connect credential-less. Also the shared StartupMessage read/detect helpers. |
| `httpproxy.go` | HTTPS `CONNECT` forward proxy (outbound via the fixed Fly egress IP). |
| `fly.go` | All Fly glue: multi-DB config, `runProxies` bootstrap, dev page, source gating (`classifyPeer`, auto-trusts Tailscale always + Fly 6PN when `onFly`), `application_name` attribution (Fly PTR/TXT + Tailscale WhoIs over the local socket + StartupMessage rewrite), and the `.internal` DNS forwarder with the self → Tailscale-IP rewrite (Go companion to `fly-router.sh`). |

**fly-router / Tailscale layer — shell/Docker (no Go):**

| File | Role |
|---|---|
| `fly-router.sh` | Derive the org `/48`, `sysctl ip_forward`, start `tailscaled`, `tailscale up` (advertise routes + exit node). Modeled on `fly-apps/tailscale-router`. |
| Dockerfile | Builds the binary; installs `tailscale` + `iptables`/`ip6tables`; bundles the scripts. |
| `entrypoint.sh` | Orchestrator: run `fly-router.sh`, then `exec pgproxy`. |

Rule: **Tailscale = shell/Docker; Fly = Go.** They never mix in one file.

## Configuration

All config is env-driven. Setting `TS_AUTHKEY` enables Tailscale (omit it for a plain
Fly 6PN proxy); everything else has a
default chosen for how we run today. Set non-secrets in `fly.toml [env]`, secrets via
`fly secrets set`.

### Tailscale on/off (secret)

| Env | Default | Why |
|---|---|---|
| `TS_AUTHKEY` | — (unset = Tailscale off) | Presence is the on-switch for Tailscale: with it, `fly-router.sh` brings up `tailscaled` and the proxy trusts tailnet sources; without it, Tailscale is skipped and pgproxy is a plain Fly 6PN proxy. Use ephemeral+reusable so dead nodes self-clean. The entrypoint surfaces presence as `--tailscale-enabled` and drops the secret before exec'ing the proxy. |

### Common (good defaults; override only to change behavior)

| Env | Default | Why this default |
|---|---|---|
| `DESTINATION_PG_DBS` (secret) | empty | App must boot before any DB is configured; add later via secret. |
| `TS_HOSTNAME` | `$FLY_MACHINE_ID-$FLY_REGION-$FLY_APP_NAME` | Machine ID makes every ephemeral node uniquely named, avoiding MagicDNS `-1/-2` collisions across restarts/regions. |
| `TS_ADVERTISE_ROUTES` | auto-derive org `/48` from `fly-local-6pn` | Advertise exactly the reachable 6PN range, not the whole `fdaa::/16`. |
| `TS_ADVERTISE_EXIT_NODE` | `true` | We want every machine usable as a region-specific egress exit node. |
| `DNS_RESOLVER` | `[fdaa::3]:53` on Fly, else empty | Upstream resolver the forwarder relays `*.internal` to. Auto-defaults to Fly's `fdaa::3` when on Fly (no config); generic name so another provider can point it at theirs; empty disables. |

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
| `HTTP_PROXY_LISTEN` | `[::]:8080` | Fixed-egress `CONNECT` proxy port; gated to 6PN sources. |
| `DEBUG_PORT` | `80` | Serves the dev page + `/debug/vars`; convenient over 6PN. |
| `TS_SOCKET` | `/var/run/tailscale/tailscaled.sock` | Local `tailscaled` API socket; pgproxy queries it (raw HTTP) to WhoIs Tailscale clients for `application_name`. Shared with `fly-router.sh`. |

Fly injects `FLY_APP_NAME`, `FLY_REGION`, `FLY_MACHINE_ID`, `FLY_PRIVATE_IP` automatically —
do not set these.

**No env var (auto-detected via `FLY_APP_NAME` = "on Fly"):**
- **Trusted sources** (`classifyPeer`): Tailscale ranges are *always* accepted (they're
  Tailscale-exclusive, so harmless when unused); Fly 6PN (`fdaa::/16`) is accepted *only on
  Fly*. So off-Fly the tailnet is the access path — nothing to configure.
- **`DNS_RESOLVER`** defaults to Fly's `[fdaa::3]:53` on Fly, empty (forwarder off) elsewhere.
- **DNS self-rewrite** (answer own `*.internal` with the node's Tailscale IP) is on whenever
  `FLY_APP_NAME` is present and the forwarder is running. Falls back to plain forwarding until
  a Tailscale IP exists. See Decisions.

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
  `pgproxy.internal` over the *subnet route* would be attributed only at the router level
  (multi-machine forwarding SNATs the source to the router's 6PN address). To get a real
  per-user `application_name`, the forwarder answers pgproxy's *own* `*.internal` names with
  the node's **Tailscale IP** (auto-enabled on Fly via `FLY_APP_NAME`; `dnsSelfAnswer`). The tailnet
  client then connects **directly to pgproxy over Tailscale** — no subnet route, no SNAT — so
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
  - Considered alternatives: a port-specific `ip6tables` block (single-machine only, leaky
    across HA routers) and a Tailscale ACL (clean but requires tailnet policy edits). The DNS
    self-rewrite keeps everything in the app and needs no tailnet config.
- Reference implementation: [fly-apps/tailscale-router](https://github.com/fly-apps/tailscale-router).

## Status

- `main` @ `d0858c9` — tsnet-based (pre-migration).
- Branch `approach-b` — Approach B implemented: Go has no `tailscale.com` import
  (WhoIs uses the raw LocalAPI socket); `fly.go` holds the `.internal` DNS forwarder with
  auto self-rewrite (own `*.internal` → Tailscale IP) + Tailscale WhoIs attribution; `fly-router.sh` + orchestrator
  `entrypoint.sh` + Dockerfile install tailscale. `go build`/`vet`/`test` pass; shell
  syntax checked.
- Next — deploy-verify on Fly (TUN + `ip_forward`; and that the `tailscaled` LocalAPI WhoIs
  works over the socket), then merge to `main`.
