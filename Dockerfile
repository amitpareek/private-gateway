FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/pgproxy .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/pgproxy /pgproxy
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 5432 = Postgres (Fly 6PN + Tailscale)
# 8080 = HTTPS CONNECT forward proxy (Fly 6PN only)
# Both are bound on [::] and gated by source-IP classifier.
EXPOSE 5432 8080

ENTRYPOINT ["/entrypoint.sh"]
