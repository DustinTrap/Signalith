FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/signalith ./cmd/signalith
RUN mkdir -p /out/data/detections /out/data/lookups /out/data/dashboards

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/signalith /usr/local/bin/signalith
# Writable folders for custom detections, lookups and dashboards, owned by the nonroot user.
COPY --from=build --chown=65532:65532 /out/data /var/lib/signalith
ENV SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections \
    SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups \
    SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/signalith"]
CMD ["serve", "-c", "/etc/signalith/signalith.yaml"]
