FROM golang:1.18-alpine3.15 AS builder

RUN apk add --no-cache git mercurial subversion

WORKDIR /go/src/app

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY . .
RUN go build ./cmd/...

FROM alpine:3.15.0
CMD ["prom-authzed-proxy"]
ENTRYPOINT ["prom-authzed-proxy"]
COPY --from=builder /go/src/app/prom-authzed-proxy /usr/local/bin
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf
