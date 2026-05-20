#!/bin/sh
# Map Fly env vars / secrets to pgproxy flags.
#
# Required (set with `fly secrets set ...`):
#   DESTINATION_PG_URL  Upstream Postgres host:port, e.g.
#                       ep-x-y.us-east-1.aws.neon.tech:5432
#   TS_AUTHKEY          Tailscale auth key. Use an ephemeral+reusable
#                       key so each restart auto-cleans the old node.
#
# Optional:
#   TS_HOSTNAME         Tailscale hostname. Default: $FLY_APP_NAME.
#   UPSTREAM_CA_FILE    CA bundle for upstream TLS verification.
#                       Default: /etc/ssl/certs/ca-certificates.crt
#                       (system roots; validates Neon's public cert).
#   STATE_DIR           Tailscale state dir. Default: /tmp/tsnet
#                       (in-memory via tmpfs; node re-auths on
#                       every restart, hence the ephemeral key).
set -e

: "${DESTINATION_PG_URL:?DESTINATION_PG_URL must be set (e.g. via 'fly secrets set DESTINATION_PG_URL=...')}"
: "${TS_AUTHKEY:?TS_AUTHKEY must be set (use an ephemeral+reusable key)}"

TS_HOSTNAME="${TS_HOSTNAME:-${FLY_APP_NAME:-pgproxy}}"
UPSTREAM_CA_FILE="${UPSTREAM_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"
STATE_DIR="${STATE_DIR:-/tmp/tsnet}"

mkdir -p "$STATE_DIR"

exec /pgproxy \
  --hostname="$TS_HOSTNAME" \
  --upstream-addr="$DESTINATION_PG_URL" \
  --upstream-ca-file="$UPSTREAM_CA_FILE" \
  --state-dir="$STATE_DIR"
