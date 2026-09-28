FROM golang:1.22
WORKDIR /src
COPY . .
RUN go mod download
RUN go build -o /bin/app ./cmd/app
EXPOSE 8080
CMD ["/bin/app"]
