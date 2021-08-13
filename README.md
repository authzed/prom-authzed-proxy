# prom-authzed-proxy

[![Container Repository on Quay.io](https://quay.io/repository/authzed/prom-authzed-proxy/status "Docker Repository on Quay.io")](https://quay.io/repository/authzed/prom-authzed-proxy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![Build Status](https://github.com/authzed/prom-authzed-proxy/workflows/build/badge.svg)](https://github.com/authzed/prom-authzed-proxy/actions)
[![Mailing List](https://img.shields.io/badge/email-google%20groups-4285F4)](https://groups.google.com/g/authzed-oss)
[![Discord Server](https://img.shields.io/discord/844600078504951838?color=7289da&logo=discord "Discord Server")](https://discord.gg/jTysUaxXzM)
[![Twitter](https://img.shields.io/twitter/follow/authzed?color=%23179CF0&logo=twitter&style=flat-square)](https://twitter.com/authzed)

prom-authzed-proxy is a proxy for [Prometheus] that authorizes the request's [Bearer Token] with [Authzed] and enforces a label in a PromQL query.

[Authzed] is a database and service that stores, computes, and validates your application's permissions.

Developers create a schema that models their permissions requirements and use a client library, such as this one, to apply the schema to the database, insert data into the database, and query the data to efficiently check permissions in their applications.

See [CONTRIBUTING.md] for instructions on how to contribute and perform common tasks like building the project and running tests.

[Prometheus]: https://prometheus.io
[prom-label-proxy]: https://github.com/prometheus-community/prom-label-proxy
[Bearer Token]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
[Authzed]: https://authzed.com
[CONTRIBUTING.md]: CONTRIBUTING.md

## Basic Usage

### Installation

If you're using a modern version of [Go], run the following command to install:

```sh
go install github.com/authzed/prom-authzed-proxy
```

[Go]: https://golang.org/dl/

### Running against localhost

The following command will run the proxy that checks the permissions against [authzed.com] and a Prometheus running on localhost:

```sh
prom-authzed-proxy \
    --upstream-prom-addr http://localhost:9090 \
    --object-id-parameter install \
    --authzed-token tc_client_token_1234deadbeef  \
    --authzed-subject-definition-path psystem/token \
    --authzed-subject-relation ...
    --authzed-object-definition-path psystem/prometheus \
    --authzed-permission viewer \
```

Each request is checked to have a value as a [Bearer Token] that is a `viewer` of the value in the PromQL label `install` with their respective Authzed Object Types.

If the permission check fails, the proxy will return an HTTP 403.

[authzed.com]: https://authzed.com
[Bearer Token]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
