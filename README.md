# toydns

A tiny DNS server in Rust, following [dnsguide](https://github.com/EmilHernvall/dnsguide).

It listens on UDP `0.0.0.0:2053`, parses incoming DNS queries, forwards them to
Google's public resolver (`8.8.8.8:53`), and returns the parsed response to the
client.

## Run

```sh
cargo run
```

Then, from another terminal:

```sh
dig @127.0.0.1 -p 2053 google.com
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
