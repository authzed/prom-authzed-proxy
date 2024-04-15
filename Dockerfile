FROM golang:1.22-alpine3.19 AS builder

RUN apk add --no-cache git mercurial subversion

WORKDIR /go/src/app

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY . .
RUN go build ./cmd/...

FROM cgr.dev/chainguard/static:latest
CMD ["prom-authzed-proxy"]
ENTRYPOINT ["prom-authzed-proxy"]
COPY --from=builder /go/src/app/prom-authzed-proxy /usr/local/bin

