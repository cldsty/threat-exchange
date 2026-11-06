# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
ARG GO_VERSION=1.27.3
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Download modules first so that this layer is cached until go.mod changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify

COPY . .

ARG VERSION=dev
# Static, reproducible binary: no cgo, no local paths, no debug info.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/threat-exchange ./cmd/threat-exchange

# ---- runtime stage ----------------------------------------------------------
# Distroless: no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
LABEL org.opencontainers.image.title="threat-exchange" \
      org.opencontainers.image.description="Threat information exchange service" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/threat-exchange /usr/local/bin/threat-exchange

# 65532 is the "nonroot" user of distroless images.
USER 65532:65532

EXPOSE 8443 8081

HEALTHCHECK --interval=10s --timeout=4s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/threat-exchange", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/threat-exchange"]
CMD ["serve"]
