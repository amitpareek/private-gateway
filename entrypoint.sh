#!/bin/sh
# Orchestrator: bring up the fly-router (Tailscale) layer, then hand off
# to the Fly/proxy layer. Thin glue only — router logic lives in
# fly-router.sh, proxy logic in the pgproxy binary. All config is
# env-driven; see project.md for the full table and defaults.
#
# Components (all from this one image):
#   pgproxy        the Go proxy binary, built from:
#     pgproxy.go     pure Postgres wire proxy (strict upstream TLS)
#     managed.go     managed mode: proxy logs in upstream so clients connect
#                    credential-less
#     httpproxy.go   HTTPS CONNECT forward proxy (fixed Fly egress IP)
#     extensions.go  Fly bits: multi-DB config, dev page, source gating,
#                    application_name attribution
#     fly-router.go  .internal DNS forwarder -> Fly resolver
#   fly-router.sh  Tailscale layer: tailscaled subnet router + exit node
#   entrypoint.sh  this orchestrator
set -e

# fly-router layer (Tailscale subnet router + exit node). Backgrounded
# tailscaled survives the exec below by reparenting to pgproxy (PID 1).
/fly-router.sh

# Fly / proxy layer. Map env -> flags (the binary has no Tailscale flags).
exec /pgproxy \
  --debug-port="${DEBUG_PORT:-80}" \
  --upstream-ca-file="${UPSTREAM_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}" \
  --fly-listen-host="${FLY_LISTEN_HOST:-[::]}" \
  --http-proxy-listen="${HTTP_PROXY_LISTEN:-[::]:8080}" \
  --fly-dns-resolver="${FLY_DNS_RESOLVER-[fdaa::3]:53}" \
  --destination-pg-dbs="${DESTINATION_PG_DBS:-}"
