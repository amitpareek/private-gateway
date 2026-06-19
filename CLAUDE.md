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
  - `pgproxy.go`   — upstream-faithful core (proxy, TLS, serve loop). Keep diff-minimal; hooks marked `// EXT`.
  - `extensions.go`— Fly 6PN bits: dev page, `classifyPeer`, `application_name` (Fly PTR/TXT).
  - `httpproxy.go` — HTTPS `CONNECT` forward proxy.
  - `managed.go`   — managed credential injection.
  - `flydns.go`    — `.internal` DNS forwarder → Fly resolver (`fdaa::3`).
- **Tailscale / fly-router (shell/Docker, NOT Go):**
  - `fly-router.sh` + Dockerfile install lines — all `tailscaled` / `tailscale up` logic
    (the Fly subnet-router setup; modeled on `fly-apps/tailscale-router`).
  - `entrypoint.sh` — thin orchestration only (run `fly-router.sh`, then `exec pgproxy`).

Rule: **Tailscale logic lives in shell/Docker; the Go binary has no Tailscale dependency.**
Do not re-introduce `tsnet` into the Go code.

## Architecture status

**"Approach B" is implemented on branch `approach-b`** (this branch): a real `tailscaled`
subnet router + exit node alongside a 6PN-only Go proxy, with the file layout above. `main`
still holds the older **tsnet-embedded** design (commit `d0858c9`) until this is merged.
Runtime (TUN / `ip_forward`) is **not yet deploy-verified** on Fly. `project.md` is the
source of truth for the design and config.

## Conventions

- Keep `pgproxy.go` close to upstream; put customizations in the `EXT` files.
- Match surrounding style; tests live alongside as `*_test.go`.
- Config is env-driven (see project.md). Tailscale vars are prefixed `TS_`.
- Commit only when asked. Branch off `main` first if asked to commit.
