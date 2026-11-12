FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o /out/app .

FROM debian:latest
LABEL org.opencontainers.image.source="https://example.com/app"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/app /app
USER root
EXPOSE 80 8080/tcp 443/tcp
ENTRYPOINT ["/app"]
