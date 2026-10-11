FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/signalith ./cmd/signalith

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/signalith /usr/local/bin/signalith
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/signalith"]
CMD ["serve", "-c", "/etc/signalith/signalith.yaml"]
