FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build \
    -ldflags="-s -w" \
    -o /proceda-agent \
    ./cmd/proceda-agent


FROM alpine:3.22

RUN addgroup -S proceda \
    && adduser -S proceda -G proceda \
    && mkdir -p /var/lib/proceda /run/proceda \
    && chown -R proceda:proceda \
        /var/lib/proceda \
        /run/proceda

COPY --from=builder \
    /proceda-agent \
    /usr/local/bin/proceda-agent

USER proceda

ENTRYPOINT ["proceda-agent"]