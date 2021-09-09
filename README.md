# Prometheus Exporter for Linux Netfilter Tables

[![tommie](https://circleci.com/gh/tommie/prometheus-nftables-exporter.svg?style=svg)](https://circleci.com/gh/tommie/prometheus-nftables-exporter)

This is an exporter for Netfilter configuration and statistics.

## Metrics

* `nftables_chain_metadata{family, table, chain, hook, policy, priority}`
  Metadata about each chain. Value is always 1. (Gauge)
* `nftables_set_metadata{family, table, set, ismap, keytype, datatype}`
  Metadata about each set. Value is always 1. (Gauge)
* `nftables_table_metadata{family, table, flags}`
  Metadata about each table. Value is always 1. (Gauge)
* `nftables_chain_rule_count{family. table, chain}}`
  Total rule count in chain. (Gauge)
* `nftables_rule_byte_count{family, table, chain, comment}`
  Number of bytes matching the rule. (Cumulative)
* `nftables_rule_packet_count{family, table, chain, comment}`
  Number of packets matching the rule. (Cumulative)
* `nftables_counter_byte_count{family, table, counter}`
  Number of bytes triggering the counter. (Ccumulative)
* `nftables_counter_packet_count{family, table, counter}`
  Number of packets triggering the counter. (Cumulative)
* `nftables_set_size{family, table, set}`
  Number of elements in the set. (Gauge)

All counters and sets are included by default. Rules need to have
non-empty comments to show up.

## Running In Docker

To build a Docker image:

```shell
$ docker build -t prometheus-nftables-exporter .
```

And then

```shell
$ docker run --network host --cap-drop all --cap-add NET_ADMIN --cap-add NET_RAW --rm -it prometheus-nftables-exporter
Listening for HTTP connections on "127.0.0.1:9732"...
```

## Running Directly

To build it plain:

```shell
$ go test ./...
$ go install ./cmd/promnftd
$ setcap -q cap_net_admin,cap_net_raw+ep ./promnftd
```

The `setcap` command is needed to be able to run the command as any
user.

```shell
$ ./promnftd -http-addr localhost:9732
Listening for HTTP connections on "127.0.0.1:9732"...
```

## Configuration

Only command line flags are relevant for configuration. You will want
to set `-http-addr`, but other defaults are already useful.

Controlling what's exported:

* `-counter-names string`
  Regular expression of names of counters to include (fully anchored). (default ".*")
* `-rule-comments string`
  Regular expression of comments of rules to include (fully anchored). (default ".*")
* `-set-names string`
  Regular expression of names of sets to include (fully anchored).

Controlling how the exporter runs:

* `-http-addr string`
  TCP-address to listen for HTTP connections on. (default "localhost:0")
* `-standalone-log`
  Log to stderr, with time prefix. Useful if not running in Docker or Systemd.

## HTTP Endpoint

Since there's no standard for Prometheus exporter TCP ports, you'll
have to decide. It's normally something 9100--9400.

## Implementation Notes and Caveats

* The `ismap` and `keytype` labels for sets will be wrong until
  [google/nftables#129](https://github.com/google/nftables/pull/129)
  is merged.
* Implemented in Go.
* Uses the `google/nftables` library.
* Designed to run as non-root in a Docker container with network mode
  `host`, or with Systemd.
* Netfilter makes it difficult to render a string from a rule
  expression, so we require a comment instead.

## Prior Work

There are multiple of these already:

* [dadevel](https://github.com/dadevel/prometheus-nftables-exporter),
  seems very useful. Also exports sets, maps and meters. No tests.
* [Inattrass](https://github.com/lnattrass/prometheus-nftables-collector),
  designed to run as a Systemd timer. Doesn't export rules. No tests.
* [digineo](https://github.com/digineo/nftables_exporter), only
  exports rule counters with comments. No filtering of rules. No tests.
* [Sheridan](https://github.com/Sheridan/nftables_exporter), exports
  rules, but tries to parse rules into Prometheus labels. This feels
  wrong. No tests. One pull request, open since 2019.
* [Intrinsec](https://github.com/Intrinsec/nftables_exporter), linked
  from [Prometheus Exporters](https://prometheus.io/docs/instrumenting/exporters/).
  Only exports rule count from what I can tell. I don't see how that's
  useful. Some tests.

## License

Licensed under the [MIT license](./LICENSE).
