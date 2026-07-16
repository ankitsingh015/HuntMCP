# =============================================================================
# Stage 1: Build Go binary
# =============================================================================
FROM golang:1.23-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/huntmcp-server ./cmd/server

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /usr/local/bin/huntmcp-server /usr/local/bin/huntmcp-server

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["huntmcp-server"]
