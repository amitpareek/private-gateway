# private-gateway image. Two layers run side by side at runtime:
#   - Fly/proxy (the `private-gateway` Go binary): pgproxy.go (pure Postgres wire
#     proxy), credentials-manager.go (managed/credential-injection mode),
#     httpproxy.go (HTTPS CONNECT proxy), fly.go (all Fly glue: config,
#     dev page, source gating, application_name, .internal DNS forwarder).
#   - fly-router (Tailscale): fly-router.sh runs tailscaled as a subnet
#     router + exit node (modeled on fly-apps/tailscale-router).
# entrypoint.sh wires them together. See project.md.
#
# go.mod requires go >= 1.24. The private-gateway binary has NO Tailscale
# dependency; Tailscale runs only as the separate runtime daemon.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/private-gateway .

FROM alpine:3.20
# ca-certificates: verify upstream (Neon etc.) TLS.
# tailscale: real tailscaled daemon (subnet router + exit node).
# iptables/ip6tables: tailscaled programs SNAT + forwarding rules.
RUN apk add --no-cache ca-certificates tailscale iptables ip6tables

COPY --from=build /out/private-gateway /private-gateway
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
