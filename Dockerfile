# pgproxy image. Two layers run side by side at runtime:
#   - Fly/proxy (the `pgproxy` Go binary): pgproxy.go (pure Postgres wire
#     proxy), managed.go (credential-injection mode), httpproxy.go (HTTPS
#     CONNECT proxy), extensions.go (Fly config/dev page/source gating/
#     application_name), fly-router.go (.internal DNS forwarder).
#   - fly-router (Tailscale): fly-router.sh runs tailscaled as a subnet
#     router + exit node (modeled on fly-apps/tailscale-router).
# entrypoint.sh wires them together. See project.md.
#
# go.mod requires go >= 1.24. The pgproxy binary has NO Tailscale
# dependency; Tailscale runs only as the separate runtime daemon.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/pgproxy .

FROM alpine:3.20
# ca-certificates: verify upstream (Neon etc.) TLS.
# tailscale: real tailscaled daemon (subnet router + exit node).
# iptables/ip6tables: tailscaled programs SNAT + forwarding rules.
RUN apk add --no-cache ca-certificates tailscale iptables ip6tables

COPY --from=build /out/pgproxy /pgproxy
COPY entrypoint.sh /entrypoint.sh
COPY fly-router.sh /fly-router.sh
RUN chmod +x /entrypoint.sh /fly-router.sh

# 5432 = Postgres (Fly 6PN; reachable from the tailnet via the subnet router)
# 8080 = HTTPS CONNECT forward proxy (Fly 6PN only)
#   80 = debug/metrics + dev page (Fly 6PN)
#   53 = .internal DNS forwarder (served to the tailnet)
# Postgres/HTTP listeners bind [::] and are gated by the source-IP classifier.
EXPOSE 5432 8080 80 53

ENTRYPOINT ["/entrypoint.sh"]
