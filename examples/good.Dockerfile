# The same build, written so the cache survives and the image stays small.
FROM golang:1.22.5-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /usr/local/bin/api
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/api"]
