#!/bin/sh
# fly-router.sh — make this Fly machine a Tailscale subnet router + exit
# node for the Fly 6PN network. This is the entire "Tailscale layer";
# the pgproxy Go binary contains no Tailscale code.
#
# Modeled on the reference project:
#   https://github.com/fly-apps/tailscale-router
#
# ─── WHAT THIS DOES, AND WHY ────────────────────────────────────────────
# Goal: let people on a Tailscale tailnet reach Fly apps addressed as
# <app>.internal (including pgproxy), and use this machine as an exit node.
#
# Fly's private network ("6PN", the IPv6 range fdaa::/16) is not part of
# the tailnet, so a tailnet client can't reach it directly. This script
# turns THIS machine into a bridge:
#   1. a real tailscaled joins the tailnet and ADVERTISES the org's 6PN
#      subnet (and the exit-node routes), and
#   2. the Linux kernel FORWARDS packets between the Tailscale interface
#      and Fly 6PN (ip_forward).
# A tailnet client then resolves <app>.internal (via Tailscale split DNS →
# the pgproxy DNS forwarder, see fly.go) and routes the connection
# through this machine to the 6PN target.
#
# Why a REAL tailscaled (TUN), not userspace/tsnet:
#   tsnet (userspace) can advertise a route but cannot actually forward
#   arbitrary subnet TCP — its netstack RSTs flows that have no local
#   listener, so ping worked but TCP to *.internal did not. A real TUN
#   device + kernel ip_forward forwards every protocol, which is the
#   whole point of this design.
#
# This is the Tailscale layer. Its sibling, the Fly/proxy layer, is the
# `pgproxy` Go binary:
#   pgproxy.go              pure Postgres wire proxy (strict upstream TLS)
#   credentials-manager.go  managed mode: proxy logs in upstream, clients
#                           connect credential-less
#   httpproxy.go            HTTPS CONNECT forward proxy (fixed Fly egress IP)
#   fly.go                  all Fly glue: config, dev page, source gating,
#                           application_name, AND the .internal DNS forwarder
#                           (the Go companion to this script)
# entrypoint.sh runs this script, then exec's pgproxy. See project.md.
#
# Config is env-driven (TS_* vars). Defaults below are what we run today;
# the rationale for each lives in project.md.
set -e

# Tailscale is optional: with no TS_AUTHKEY we skip it entirely and pgproxy
# runs as a plain (Fly 6PN) proxy. Use an ephemeral+reusable+tagged key.
if [ -z "${TS_AUTHKEY:-}" ]; then
  echo "fly-router: TS_AUTHKEY not set — Tailscale disabled, running proxy only"
  exit 0
fi

# ─── Defaults (see project.md for the "why" of each) ────────────────────
TS_STATE_DIR="${TS_STATE_DIR:-/tmp/tailscale}"      # tmpfs → ephemeral; re-auths each restart
TS_ADVERTISE_EXIT_NODE="${TS_ADVERTISE_EXIT_NODE:-true}"
TS_ACCEPT_DNS="${TS_ACCEPT_DNS:-false}"             # keep the node on Fly's resolver (needs fdaa::3)
TS_ACCEPT_ROUTES="${TS_ACCEPT_ROUTES:-false}"       # a router needn't consume others' routes
TS_SNAT_SUBNET_ROUTES="${TS_SNAT_SUBNET_ROUTES:-true}"
TS_SOCKET="${TS_SOCKET:-/var/run/tailscale/tailscaled.sock}"

# Hostname = machineid-region-appname. The machine id keeps every
# ephemeral node uniquely named across restarts/regions (no MagicDNS
# -1/-2 suffix collisions).
DEFAULT_HOSTNAME="${FLY_MACHINE_ID:-pgproxy}-${FLY_REGION:-local}-${FLY_APP_NAME:-pgproxy}"
TS_HOSTNAME="${TS_HOSTNAME:-$DEFAULT_HOSTNAME}"

# Routes to advertise. If TS_ADVERTISE_ROUTES is unset, derive the org's
# exact 6PN /48: Fly assigns each org a /48 inside fdaa::/16, and the
# machine's own 6PN address is the "fly-local-6pn" entry in /etc/hosts.
# Advertising the precise /48 (rather than the whole fdaa::/16) is what
# the reference does. Set TS_ADVERTISE_ROUTES= to advertise nothing, or
# to an explicit CIDR to override.
if [ -z "${TS_ADVERTISE_ROUTES+x}" ]; then
  sixpn="$(grep -m1 fly-local-6pn /etc/hosts 2>/dev/null | awk '{print $1}')"
  if [ -n "$sixpn" ]; then
    prefix="$(echo "$sixpn" | cut -d: -f1-3)"   # first 3 hextets = the /48
    TS_ADVERTISE_ROUTES="${prefix}::/48"
  else
    TS_ADVERTISE_ROUTES=""
  fi
fi

# ─── Kernel forwarding ──────────────────────────────────────────────────
# A subnet router / exit node forwards packets between interfaces; the
# kernel only does that when forwarding is enabled. Without this, routes
# are advertised but no traffic actually flows.
sysctl -w net.ipv4.ip_forward=1 || echo "warn: could not set ipv4 ip_forward"
sysctl -w net.ipv6.conf.all.forwarding=1 || echo "warn: could not set ipv6 forwarding"

# ─── TUN device ─────────────────────────────────────────────────────────
# tailscaled needs a real TUN device for kernel-level routing (userspace
# networking would NOT forward). Fly usually provides /dev/net/tun; create
# the node if the platform didn't.
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200 || echo "warn: could not create /dev/net/tun"
fi

mkdir -p "$TS_STATE_DIR" "$(dirname "$TS_SOCKET")"

# ─── Start the daemon ───────────────────────────────────────────────────
# Backgrounded: it keeps running after entrypoint.sh exec's pgproxy (it
# reparents to PID 1). NOTE: there is no supervisor — if tailscaled dies,
# routing stops but pgproxy keeps serving 6PN.
tailscaled \
  --state="$TS_STATE_DIR/tailscaled.state" \
  --socket="$TS_SOCKET" \
  --tun=tailscale0 &

# `tailscale up` talks to the daemon over its socket; wait for it to exist.
i=0
while [ ! -S "$TS_SOCKET" ] && [ "$i" -lt 50 ]; do i=$((i + 1)); sleep 0.1; done

# ─── Join + advertise ───────────────────────────────────────────────────
# --snat-subnet-routes: SNAT forwarded subnet traffic to this node's 6PN
#   address so replies have a return path (Fly 6PN can't route back to a
#   Tailscale IP). --accept-dns=false: don't let Tailscale overwrite the
#   node's resolv.conf, so it keeps reaching Fly's resolver / fdaa::3.
set -- --authkey="$TS_AUTHKEY" \
       --hostname="$TS_HOSTNAME" \
       --accept-dns="$TS_ACCEPT_DNS" \
       --accept-routes="$TS_ACCEPT_ROUTES" \
       --snat-subnet-routes="$TS_SNAT_SUBNET_ROUTES"
[ -n "$TS_ADVERTISE_ROUTES" ] && set -- "$@" --advertise-routes="$TS_ADVERTISE_ROUTES"
[ "$TS_ADVERTISE_EXIT_NODE" = "true" ] && set -- "$@" --advertise-exit-node
[ -n "${TS_CONTROL_URL:-}" ] && set -- "$@" --login-server="$TS_CONTROL_URL"

echo "fly-router: hostname=$TS_HOSTNAME routes=${TS_ADVERTISE_ROUTES:-none} exit-node=$TS_ADVERTISE_EXIT_NODE"
# Advertised routes/exit node must be approved in the tailnet before they
# carry traffic (admin console, or an autoApprovers ACL on the node's tag).
# shellcheck disable=SC2086  # TS_EXTRA_ARGS is an intentional word-split escape hatch
tailscale --socket="$TS_SOCKET" up "$@" ${TS_EXTRA_ARGS:-}
