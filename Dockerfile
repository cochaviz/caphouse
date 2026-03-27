# syntax=docker/dockerfile:1

# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/caphouse     ./cmd/caphouse && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/caphouse-api  ./cmd/caphouse-api

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21

COPY --from=builder /out/caphouse     /usr/local/bin/caphouse
COPY --from=builder /out/caphouse-api /usr/local/bin/caphouse-api

# GeoIP / ASN sources — set these to enable IP geolocation enrichment.
# Each value is a URL to a DB-IP CSV file (plain or .gz).
# Flags --geoip-source / --geoip-source-v6 / --asn-source / --asn-source-v6
# can be used instead.
ENV CAPHOUSE_GEOIP_SOURCE=""
ENV CAPHOUSE_GEOIP_SOURCE_V6=""
ENV CAPHOUSE_ASN_SOURCE=""
ENV CAPHOUSE_ASN_SOURCE_V6=""

CMD ["caphouse-api"]
