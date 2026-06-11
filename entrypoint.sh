#!/bin/sh
# Map Fly env vars / secrets to pgproxy flags.
#
# Required:
#   TS_AUTHKEY            Tailscale auth key. Use an ephemeral+reusable
#                         key so each restart auto-cleans the old node.
#
# Optional:
#   DESTINATION_PG_DBS    JSON array of Postgres databases. Example:
#                           [
#                             {"name":"rw","listen":5432,
#                              "target":"ep-xxx.aws.neon.tech:5432",
#                              "dbname":"main","user":"app_user",
#                              "password":"..."},
#                             {"name":"admin","listen":5439,
#                              "target":"ep-xxx.aws.neon.tech:5432"}
#                           ]
#                         With user+password the entry is "managed":
#                         the proxy logs in upstream itself and clients
#                         connect credential-less. Without them it is a
#                         passthrough (client needs real credentials).
#                         May be empty on first launch; configure later
#                         via `fly secrets set DESTINATION_PG_DBS='...'`.
#   TS_HOSTNAME           Tailscale hostname. Default: $FLY_APP_NAME.
#   UPSTREAM_CA_FILE      CA bundle. Default: /etc/ssl/certs/ca-certificates.crt
#   STATE_DIR             tsnet state dir. Default: /tmp/tsnet
set -e

: "${TS_AUTHKEY:?TS_AUTHKEY must be set (use an ephemeral+reusable key)}"

TS_HOSTNAME="${TS_HOSTNAME:-${FLY_APP_NAME:-pgproxy}}"
UPSTREAM_CA_FILE="${UPSTREAM_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"
STATE_DIR="${STATE_DIR:-/tmp/tsnet}"

mkdir -p "$STATE_DIR"

exec /pgproxy \
  --hostname="$TS_HOSTNAME" \
  --upstream-ca-file="$UPSTREAM_CA_FILE" \
  --state-dir="$STATE_DIR" \
  --destination-pg-dbs="${DESTINATION_PG_DBS:-}"
