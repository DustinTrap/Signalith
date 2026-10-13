FROM golang:1.27.1@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/signalith ./cmd/signalith
RUN mkdir -p /out/data/detections /out/data/lookups /out/data/dashboards /out/data/archive && chmod 700 /out/data/archive

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/signalith /usr/local/bin/signalith
# Writable folders for custom detections, lookups, dashboards and archived
# days, owned by the nonroot user.
COPY --from=build --chown=65532:65532 /out/data /var/lib/signalith
# SIGNALITH_STATE_DIR holds what Signalith makes for itself: its master key
# (keys/), its HTTPS certificate (tls/), and this server's identity
# (node.id) and its lock (cluster/).
ENV SIGNALITH_STATE_DIR=/var/lib/signalith \
    SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections \
    SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups \
    SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards \
    SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive
# Web UI and API (HTTPS), syslog, and syslog over TLS (see
# deploy/docker/signalith.yaml).
EXPOSE 8080 5514/udp 5514/tcp 6514/tcp
ENTRYPOINT ["/usr/local/bin/signalith"]
CMD ["serve", "-c", "/etc/signalith/signalith.yaml"]
