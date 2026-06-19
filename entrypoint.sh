#!/bin/sh
# Orchestrator: bring up the fly-router (Tailscale) layer, then hand off
# to the Fly/proxy layer. Thin glue only — router logic lives in
# fly-router.sh, proxy logic in the pgproxy binary. All config is
# env-driven; see project.md for the full table and defaults.
#
# Components (all from this one image):
#   pgproxy        the Go proxy binary, built from:
#     pgproxy.go              pure Postgres wire proxy (strict upstream TLS)
#     credentials-manager.go  managed mode: proxy logs in upstream so clients
#                             connect credential-less
#     httpproxy.go            HTTPS CONNECT forward proxy (fixed Fly egress IP)
#     fly.go                  all Fly glue: multi-DB config, dev page, source
#                             gating, application_name, .internal DNS forwarder
#   fly-router.sh  Tailscale layer: tailscaled subnet router + exit node
#   entrypoint.sh  this orchestrator
set -e

# Tailscale is enabled iff TS_AUTHKEY is set. Capture that as a bool to
# pass the proxy, so the binary keeps no knowledge of the secret.
TS_ENABLED=false
[ -n "${TS_AUTHKEY:-}" ] && TS_ENABLED=true

# fly-router layer (Tailscale subnet router + exit node). Backgrounded
# tailscaled survives the exec below by reparenting to pgproxy (PID 1).
# No-op when TS_AUTHKEY is unset.
/fly-router.sh

# Drop the auth key before handing off — the proxy never needs it.
unset TS_AUTHKEY

# Fly / proxy layer. Map env -> flags (the binary has no Tailscale flags
# beyond the derived --tailscale-enabled bool).
exec /pgproxy \
  --debug-port="${DEBUG_PORT:-80}" \
  --upstream-ca-file="${UPSTREAM_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}" \
  --fly-listen-host="${FLY_LISTEN_HOST:-[::]}" \
  --http-proxy-listen="${HTTP_PROXY_LISTEN:-[::]:8080}" \
  --dns-resolver="${DNS_RESOLVER:-}" \
  --tailscaled-socket="${TS_SOCKET:-/var/run/tailscale/tailscaled.sock}" \
  --tailscale-enabled="$TS_ENABLED" \
  --destination-pg-dbs="${DESTINATION_PG_DBS:-}"
