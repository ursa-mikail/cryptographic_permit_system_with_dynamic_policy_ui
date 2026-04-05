FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY cmd/      ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o /permit-authority \
    ./cmd/server/

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /permit-authority /permit-authority

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/permit-authority"]
