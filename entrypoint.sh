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
#   TS_HOSTNAME           Tailscale hostname. Default: $FLY_REGION.$FLY_APP_NAME
#                         (e.g. "sin.pgproxy"); falls back to $FLY_APP_NAME or
#                         "pgproxy" when FLY_REGION is unset.
#   TS_ADVERTISE_ROUTES   Comma-separated CIDRs to advertise as a subnet
#                         router. Default: fdaa::/16 (the Fly 6PN range), so
#                         tailnet peers can reach this org's Fly apps through
#                         the proxy. Set empty to advertise none.
#   TS_ADVERTISE_EXIT_NODE  "true"/"false" — advertise this node as a Tailscale
#                         exit node (egress via this app's fixed Fly IP).
#                         Default: true.
#   FLY_DNS_RESOLVER      Fly internal DNS resolver to forward queries to.
#                         Default: [fdaa::3]:53. When set, the proxy serves
#                         DNS on its Tailscale IPs (:53) so tailnet clients
#                         with split DNS can resolve *.internal. Set empty to
#                         disable. Pair with Tailscale split DNS: add this
#                         node's Tailscale IP as a nameserver restricted to
#                         the "internal" search domain.
#   UPSTREAM_CA_FILE      CA bundle. Default: /etc/ssl/certs/ca-certificates.crt
#   STATE_DIR             tsnet state dir. Default: /tmp/tsnet
#
# Advertised subnet routes and exit nodes only carry traffic once
# approved in the tailnet (admin console, or an autoApprovers ACL for
# the node's tags).
set -e

: "${TS_AUTHKEY:?TS_AUTHKEY must be set (use an ephemeral+reusable key)}"

# Name the node "<region>.<app>" (e.g. sin.pgproxy) from Fly's env vars.
DEFAULT_HOSTNAME="${FLY_REGION:+${FLY_REGION}.}${FLY_APP_NAME:-pgproxy}"
TS_HOSTNAME="${TS_HOSTNAME:-$DEFAULT_HOSTNAME}"
TS_ADVERTISE_ROUTES="${TS_ADVERTISE_ROUTES-fdaa::/16}"
TS_ADVERTISE_EXIT_NODE="${TS_ADVERTISE_EXIT_NODE:-true}"
FLY_DNS_RESOLVER="${FLY_DNS_RESOLVER-[fdaa::3]:53}"
UPSTREAM_CA_FILE="${UPSTREAM_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"
STATE_DIR="${STATE_DIR:-/tmp/tsnet}"

mkdir -p "$STATE_DIR"

exec /pgproxy \
  --hostname="$TS_HOSTNAME" \
  --advertise-routes="$TS_ADVERTISE_ROUTES" \
  --advertise-exit-node="$TS_ADVERTISE_EXIT_NODE" \
  --fly-dns-resolver="$FLY_DNS_RESOLVER" \
  --upstream-ca-file="$UPSTREAM_CA_FILE" \
  --state-dir="$STATE_DIR" \
  --destination-pg-dbs="${DESTINATION_PG_DBS:-}"
