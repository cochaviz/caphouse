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

CMD ["caphouse-api"]
