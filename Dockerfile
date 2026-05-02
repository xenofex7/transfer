# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.21

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

ARG VERSION=dev

RUN apk add --no-cache git ca-certificates mailcap

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
    -tags netgo \
    -ldflags "-X github.com/dutchcoders/transfer.sh/cmd.Version=${VERSION} -s -w -extldflags '-static'" \
    -o /out/transfersh \
    ./

FROM alpine:${ALPINE_VERSION} AS final

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE

LABEL org.opencontainers.image.title="transfer.sh" \
      org.opencontainers.image.description="Easy file sharing from the command line" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates mailcap tzdata wget && \
    addgroup -S -g 65532 transfersh && \
    adduser -S -D -H -u 65532 -G transfersh transfersh && \
    mkdir -p /data && chown transfersh:transfersh /data

COPY --from=build /out/transfersh /usr/local/bin/transfersh

USER transfersh:transfersh

ENV LISTENER=":8080" \
    BASEDIR="/data" \
    TEMP_PATH="/tmp" \
    PURGE_DAYS="360" \
    PURGE_INTERVAL="24"

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/health.html || exit 1

ENTRYPOINT ["/usr/local/bin/transfersh"]
