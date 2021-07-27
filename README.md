# prom-authzed-proxy

`prom-authzed-proxy` is a proxy for [Prometheus](https://prometheus.io/) that filters access based on the result of an Authzed Check request.

This application makes use of [prom-label-proxy](https://github.com/prometheus-community/prom-label-proxy) to ensure that all Prometheus queries that have been Check-ed also have the correct label.

## Running

Running the following:

```sh
./prom-authzed-proxy --upstream-prom-addr http://localhost:9090 --object-id-parameter install --authzed-token tc_client_token_1234deadbeef  --authzed-object-definition-path mypermissionssystem/prometheus --authzed-permission viewer --authzed-subject-definition-path mypermissionssystem/token --authzed-subject-relation ...
```

This will ensure that an extra query parameter with the name of `install` is given in all URLs and that a `Bearer` token is specified in the `Authorization` header.
The Check request will be performed on the object `mypermissionssystem/prometheus:{install}#viewer@mypermissionssystem/token:{token}#...`. with the `install` and `token` values replaced with the given query parameter value and Bearer token, respectively.

If the Check fails, will return a 403.
