SSL agent for Poke
=================

This tool will wait for hostnames to check their SSL certificates thanks to [ssllabs](https://www.ssllabs.com)
with the given Warp10 endpoint and token, it will produce time series with the results of the tests.

## Produced metrics

For each host, 2 series will be produced:

```
# SSL Grade
// http.ssl.grade{host=1.ssl-checker.poke.io,domain=poke.io,zone=EU} 'A'
# SSL expiration date
// http.ssl.valid.until{host=1.ssl-checker.poke.io,domain=poke.io,zone=EU} 1522074886000000
```

## Configuration

ssl-go-agent will look for configuration files in this order:

- /etc/poke-ssl-agent/
- $HOME/.poke-ssl-agent
- . (current folder)

You can override every configuration entry with environement variables.
Ex:

```sh
export POKE_SSL-AGENT_HOST=1.ssl-checker.poke.io
```

Needed configuration:

```yaml
host: 1.ssl-checker.poke.io
zone: gra
kafka:
  brokers:
    - kafka.poke.io:9092
  user: kafkaUser
  password: kafkaPassword
  topics:
    - check-ssl
```

# Build

Local version:

```sh
make init
make dep
make build
```

Distribution version:

```sh
make dist
```
