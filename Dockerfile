# ---- Build stage ----
FROM golang:1.26-alpine AS build

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /iamkit ./cmd/iamkit

# ---- Runtime stage ----
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S iamkit && adduser -S iamkit -G iamkit

COPY --from=build /iamkit /usr/local/bin/iamkit

USER iamkit
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "-qO-", "http://localhost:8080/health"]

ENTRYPOINT ["iamkit"]
