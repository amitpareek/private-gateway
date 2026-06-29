# CLAUDE.md

Guidance for working in this repo. For the full design + config reference, see [project.md](project.md).

## What this is

`pgproxy` is a Postgres wire-protocol proxy that fronts upstream Postgres (e.g. Neon)
for Fly apps. It enforces strict upstream TLS regardless of the client's TLS, can inject
upstream credentials ("managed" mode) so clients connect credential-less, attributes
connections via `application_name`, and also runs an HTTPS `CONNECT` forward proxy (fixed
Fly egress IP) plus a small dev/reference page. It's a fork kept close to upstream
`tailscale.com/cmd/pgproxy`.

## Build / test / run

- Build: `go build ./...`
- Vet:   `go vet ./...`
- Test:  `go test ./...`  (in-process fake Postgres; no network needed)
- Go 1.24.

## The one hard rule: Tailscale and Fly code stay segregated

- **Fly / proxy (Go) — no `tailscale.com` import:**
  - `pgproxy.go`              — the **pure Postgres wire proxy** (strict upstream TLS, serve loop). Upstream-faithful; keep diff-minimal, hooks marked `// EXT`.
  - `credentials-manager.go` — **credential management** ("managed" mode): the proxy logs in to the upstream itself so clients connect credential-less; also the shared StartupMessage read/detect helpers.
  - `httpproxy.go`           — the **HTTPS `CONNECT` forward proxy** (outbound via the fixed Fly egress IP).
  - `fly.go`                 — **all Fly glue**: multi-DB config (incl. per-entry `allow` lists that gate which Tailscale users may use a port), `runProxies` bootstrap, dev page, source gating (`classifyPeer` — Fly 6PN when `onFly`, Tailscale ranges when `--tailscale-enabled`), `application_name` attribution (Fly PTR/TXT **and** Tailscale WhoIs via the local socket; identity *appended* to a client-set name), and the `.internal` DNS forwarder including the self→Tailscale-IP rewrite (Go companion to `fly-router.sh`).
- **Tailscale / fly-router (shell/Docker, NOT Go):**
  - `fly-router.sh` + Dockerfile install lines — all `tailscaled` / `tailscale up` logic
    (the Fly subnet-router setup; modeled on `fly-apps/tailscale-router`).
  - `entrypoint.sh` — thin orchestration only (run `fly-router.sh`, then `exec pgproxy`).

Rule: **`tsnet`/`tailscale.com` stay out of Go; the binary is not a tailnet node.**
The one allowed touchpoint: `fly.go` may query the local `tailscaled` API socket
via **raw HTTP** (no `tailscale.com` import) for best-effort WhoIs. All Tailscale
*configuration* still lives in shell/Docker. Do not re-introduce `tsnet`.

## Architecture status

**Shipped and running on Fly** (app `internal-go-proxy`; remote
`github.com/amitpareek/private-gateway`). The current design — "Approach B" — is a real
`tailscaled` (TUN) subnet router + exit node alongside the 6PN-only Go proxy, all merged to
`main`. Tailscale is **optional**: it comes up only when `TS_AUTHKEY` is set; otherwise
pgproxy is a plain Fly 6PN proxy. Auto-detection (no toggles): `onFly` = `FLY_APP_NAME`
present; Tailscale-on = `TS_AUTHKEY` present (surfaced to the binary as `--tailscale-enabled`,
with the secret unset before exec). `project.md` is the source of truth for design + config.

Known open item: `entrypoint.sh`/`fly-router.sh` aren't hardened against a failing
`tailscale up` crash-looping the container (`set -e`); harden if a restart loop recurs.

## Conventions

- Keep `pgproxy.go` close to upstream; put customizations in the `EXT` files.
- Match surrounding style; tests live alongside as `*_test.go`.
- Config is env-driven (see project.md). Tailscale vars are prefixed `TS_`.
- Commit only when asked. Branch off `main` first if asked to commit.
