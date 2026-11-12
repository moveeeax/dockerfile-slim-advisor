# The final stage stays on the builder on purpose: the service shells out to go.
# slim-advisor ignore=DSA002,DSA006 reason="runs go generate at start"
FROM golang:1.22.5
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# slim-advisor ignore=DSA009
ADD config.json /etc/app/
# slim-advisor ignore=dsa009 reason=lowercase-ids-work
ADD extra.json /etc/app/
ADD other.json /etc/app/
CMD ["go", "run", "."]
