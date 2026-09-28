# Every mistake this tool looks for, in one file.
FROM golang:1.22

RUN apt-get update
RUN apt-get install -y git ca-certificates

WORKDIR /src
COPY . .
RUN go mod download
RUN go build -o /bin/api ./cmd/api

ADD ./config /etc/api
EXPOSE 8080
CMD ["/bin/api"]
