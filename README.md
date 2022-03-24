# prom-authzed-proxy

[![Container Image](https://img.shields.io/github/v/release/authzed/prom-authzed-proxy?color=%232496ED&label=container&logo=docker "Container Image")](https://quay.io/repository/authzed/prom-authzed-proxy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![Build Status](https://github.com/authzed/prom-authzed-proxy/workflows/Build%20&%20Test/badge.svg)](https://github.com/authzed/prom-authzed-proxy/actions)
[![Mailing List](https://img.shields.io/badge/email-google%20groups-4285F4)](https://groups.google.com/g/authzed-oss)
[![Discord Server](https://img.shields.io/discord/844600078504951838?color=7289da&logo=discord "Discord Server")](https://discord.gg/jTysUaxXzM)
[![Twitter](https://img.shields.io/twitter/follow/authzed?color=%23179CF0&logo=twitter&style=flat-square)](https://twitter.com/authzed)

prom-authzed-proxy is a proxy for [Prometheus] that authorizes the request's [Bearer Token] with [Authzed] or [SpiceDB] and enforces a label in a PromQL query.

[SpiceDB] is a database system for managing security-critical permissions checking.

SpiceDB acts as a centralized service that stores authorization data.
Once stored, data can be performantly queried to answer questions such as "Does this user have access to this resource?" and "What are all the resources this user has access to?".

[Authzed] operates the globally available, serverless database platform for SpiceDB.

See [CONTRIBUTING.md] for instructions on how to contribute and perform common tasks like building the project and running tests.

[Prometheus]: https://prometheus.io
[prom-label-proxy]: https://github.com/prometheus-community/prom-label-proxy
[Bearer Token]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
[Authzed]: https://authzed.com
[SpiceDB]: https://github.com/authzed/spicedb
[CONTRIBUTING.md]: CONTRIBUTING.md

## Basic Usage

### Installation

If you're using a modern version of [Go], run the following command to install:

```sh
go install github.com/authzed/prom-authzed-proxy/cmd/prom-authzed-proxy
```

If you want a container of the proxy and have [docker] installed:

```sh
docker pull authzed/prom-authzed-proxy:latest
```

[Go]: https://golang.org/dl/
[docker]: https://www.docker.com/products/docker-desktop

### Running against localhost

The following command will run the proxy that checks the permissions against [authzed.com] and a Prometheus running on localhost:

```sh
prom-authzed-proxy \
    --proxy-upstream-prometheus-addr http://localhost:9090 \
    --proxy-spicedb-token tc_client_token_1234deadbeef  \
    --proxy-check-resource-type metric \
    --proxy-check-resource-id-query-param install \
    --proxy-check-permission view
    --proxy-check-subject-type token \
```

Each request is checked to have a value as a [Bearer Token] that has the `view` permission for the resource specified in the PromQL label `install` with their respective types.

If the permission check fails, the proxy will return an HTTP 403.

[authzed.com]: https://authzed.com
[Bearer Token]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1

## Related Projects

- [Prometheus] - industry standard time series database
- [SpiceDB] - industry standard permissions database
- [prom-label-proxy] - proxy that enforces labels in PromQL
- [kube-rbac-proxy] - proxy that authorizes requests with Kubernetes cluster RBAC, sometimes used with prom-label-proxy

[kube-rbac-proxy]: https://github.com/brancz/kube-rbac-proxy
[SpiceDB]: https://github.com/authzed/spicedb
