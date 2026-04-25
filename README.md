# toydns

A tiny recursive DNS server in Rust, following [dnsguide](https://github.com/EmilHernvall/dnsguide).

It listens on UDP `0.0.0.0:2053`, parses incoming DNS queries, and resolves
each one iteratively starting from a root nameserver
(`a.root-servers.net` / `198.41.0.4`) — following NS referrals and glue
records, recursively resolving NS hostnames when no glue is provided.

## Run

```sh
cargo run
```

Then, from another terminal:

```sh
dig @127.0.0.1 -p 2053 www.google.com
```

## Test

```sh
cargo test
```

## Capture packets (optional)

Capture a query:

```sh
nc -u -l 1053 > query_packet.txt &
dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com
```

Get the matching response:

```sh
nc -u -w1 8.8.8.8 53 < query_packet.txt > response_packet.txt
```
