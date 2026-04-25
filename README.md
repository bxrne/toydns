# toydns

A tiny DNS resolver in Rust, following [dnsguide](https://github.com/EmilHernvall/dnsguide).

## Capture packets

Capture a query:

```sh
nc -u -l 1053 > query_packet.txt &
dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com
```

Get the matching response:

```sh
nc -u -w1 8.8.8.8 53 < query_packet.txt > response_packet.txt
```

## Run

```sh
cargo run
```
