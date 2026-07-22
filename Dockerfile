# syntax=docker/dockerfile:1

# ---- Builder ----
FROM golang:1.24-bookworm AS builder

WORKDIR /build

# Cache deps first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Optional build arg for version injection (provided by CI via GitVersion)
ARG VERSION=dev

# Build with version injection (DuckDB ships CGO via prebuilt libs, so not fully static)
RUN CGO_ENABLED=1 go build \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /relay ./cmd/relay

# ---- Runtime ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary
COPY --from=builder /relay /app/relay

# Copy default config
COPY config.yaml /app/config.yaml

# Data directory for DuckDB
RUN mkdir -p /app/db

EXPOSE 8080

ENTRYPOINT ["/app/relay"]