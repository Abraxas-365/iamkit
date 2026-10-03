# ---- Frontend build stage ----
FROM node:22-alpine AS frontend

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ .
RUN npm run build -- --outDir /frontend/dist

# ---- Go build stage ----
FROM golang:1.26-alpine AS build

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Embed the pre-built frontend into the Go binary.
COPY --from=frontend /frontend/dist ./internal/console/dist/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /iamkit ./cmd/iamkit

# ---- Runtime stage ----
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S iamkit && adduser -S iamkit -G iamkit

COPY --from=build /iamkit /usr/local/bin/iamkit

USER iamkit
EXPOSE 8080

# 127.0.0.1, not localhost: the server listens on IPv4 and busybox wget
# does not fall back from ::1 where the container has IPv6 loopback.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "-qO-", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["iamkit"]
