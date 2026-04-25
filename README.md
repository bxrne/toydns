# toydns

A tiny DNS resolver in Rust, following [dnsguide](https://github.com/EmilHernvall/dnsguide).

## Run

Sends a live DNS A query for `google.com` to Google's public resolver (`8.8.8.8:53`) and prints the parsed response:

```sh
cargo run
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
