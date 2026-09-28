FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/app ./cmd/app

FROM golang:1.22
COPY --from=build /out/app /usr/local/bin/app
CMD ["app"]
