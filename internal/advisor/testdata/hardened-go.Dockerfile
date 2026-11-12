# syntax=docker/dockerfile:1.7
# hardened-go — minimal, non-root base for statically linked Go services.
#
# Runtime layer is gcr.io/distroless/static: no shell, no package manager, no
# libc — only the CA bundle, tzdata and /etc/passwd. Pinned by digest so the
# supply chain is reproducible; the :nonroot variant defaults to uid 65532.
ARG GO_VERSION=1.27

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
# Build fully static, stripped and with a reproducible build path.
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY examples/go/go.mod ./
RUN go mod download
COPY examples/go/main.go ./
RUN go build -ldflags="-s -w" -o /out/app .

FROM gcr.io/distroless/static-debian13@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
LABEL org.opencontainers.image.title="hardened-go" \
      org.opencontainers.image.description="Minimal distroless base for static Go services" \
      org.opencontainers.image.source="https://github.com/moveeeax/docker-hardened-base" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian13:nonroot"
COPY --from=build /out/app /app
# uid:gid 65532 (nonroot) — enforced numerically so read-only rootfs and
# runAsNonRoot admission policies can verify it without resolving /etc/passwd.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app"]
