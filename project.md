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
| `managed.go` | Credential management ("managed" mode): the proxy authenticates to the upstream itself so clients connect credential-less. |
| `httpproxy.go` | HTTPS `CONNECT` forward proxy (outbound via the fixed Fly egress IP). |
| `extensions.go` | Fly glue: multi-DB config parsing, dev page, source gating (`classifyPeer`), `application_name` attribution (Fly PTR/TXT). |
| `fly-router.go` | `.internal` DNS forwarder → Fly resolver (`fdaa::3`). Go half of the fly-router feature. |

**fly-router / Tailscale layer — shell/Docker (no Go):**

| File | Role |
|---|---|
| `fly-router.sh` | Derive the org `/48`, `sysctl ip_forward`, start `tailscaled`, `tailscale up` (advertise routes + exit node). Modeled on `fly-apps/tailscale-router`. |
| Dockerfile | Builds the binary; installs `tailscale` + `iptables`/`ip6tables`; bundles the scripts. |
| `entrypoint.sh` | Orchestrator: run `fly-router.sh`, then `exec pgproxy`. |

Rule: **Tailscale = shell/Docker; Fly = Go.** They never mix in one file.

## Configuration

All config is env-driven. A bare deploy needs only `TS_AUTHKEY`; everything else has a
default chosen for how we run today. Set non-secrets in `fly.toml [env]`, secrets via
`fly secrets set`.

### Required (secret)

| Env | Default | Why |
|---|---|---|
| `TS_AUTHKEY` | — (required) | The node can't join the tailnet without it; use ephemeral+reusable so dead nodes self-clean. |

### Common (good defaults; override only to change behavior)

| Env | Default | Why this default |
|---|---|---|
| `DESTINATION_PG_DBS` (secret) | empty | App must boot before any DB is configured; add later via secret. |
| `TS_HOSTNAME` | `$FLY_MACHINE_ID-$FLY_REGION-$FLY_APP_NAME` | Machine ID makes every ephemeral node uniquely named, avoiding MagicDNS `-1/-2` collisions across restarts/regions. |
| `TS_ADVERTISE_ROUTES` | auto-derive org `/48` from `fly-local-6pn` | Advertise exactly the reachable 6PN range, not the whole `fdaa::/16`. |
| `TS_ADVERTISE_EXIT_NODE` | `true` | We want every machine usable as a region-specific egress exit node. |
| `FLY_DNS_RESOLVER` | `[fdaa::3]:53` | `fdaa::3` is Fly's internal resolver; forwarding `.internal` there is what makes Fly names resolve over the tailnet. |

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

Fly injects `FLY_APP_NAME`, `FLY_REGION`, `FLY_MACHINE_ID`, `FLY_PRIVATE_IP` automatically —
do not set these.

## Deployment (one-time Tailscale setup)

- Create an ephemeral + reusable + tagged auth key → `fly secrets set TS_AUTHKEY=…`.
- Approve the advertised routes in the admin console, or grant an `autoApprovers` ACL to the
  node's tag (recommended, since ephemeral nodes re-register each restart).
- Set Tailscale **split DNS**: `internal` search domain → the node's Tailscale IP.
- The client must keep `accept-dns` on (default) for the split-DNS rule to apply.

**Runtime requirement to verify on Fly:** a TUN device (`/dev/net/tun`) and a writable
`ip_forward` sysctl. The reference app runs on Fly, so this is expected to work; confirm
early during implementation.

## Decisions / scope (current)

- **Per-user attribution over `.internal` is deferred.** Subnet routing SNATs the source to
  the router's 6PN address, so a tailnet user reaching `pgproxy.internal` is attributed at
  the router level, not per user. Fly 6PN apps still get `<region>.<app>` via PTR/TXT. If
  per-user attribution becomes a hard requirement later, options are: persistent node
  identity + connect by Tailscale name, or per-user Postgres credentials/tokens.
- Reference implementation: [fly-apps/tailscale-router](https://github.com/fly-apps/tailscale-router).

## Status

- `main` @ `d0858c9` — tsnet-based (pre-migration).
- Branch `approach-b` — Approach B implemented: Go is 6PN-only (no `tailscale.com`),
  `fly-router.go` (DNS forwarder) added, `fly-router.sh` + orchestrator `entrypoint.sh` +
  Dockerfile install tailscale. `go build`/`vet`/`test` pass; shell syntax checked.
- Next — deploy-verify on Fly (TUN + `ip_forward`), then merge to `main`.
