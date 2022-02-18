FROM golang:1.17.7-alpine3.15 AS build

WORKDIR /go/src/prom-authzed-proxy

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./ /go/src/prom-authzed-proxy
RUN go build .

FROM alpine:3.15
COPY --from=build /go/src/prom-authzed-proxy/prom-authzed-proxy /usr/local/bin/
CMD ["prom-authzed-proxy"]
ENTRYPOINT ["prom-authzed-proxy"]
