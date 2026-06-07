# dns-resolver

A DNS resolver in Go, built by working through
[EmilHernvall/dnsguide](https://github.com/EmilHernvall/dnsguide) chapters 1–5.

## Status

In progress. See [tags](https://github.com/dhruvsolanki0811/dns-resolver/tags) for chapter milestones.

## Build

    go build -o dns-resolver .

## Usage

    # Chapter 1 — parse a captured DNS response packet from disk
    ./dns-resolver parse testdata/response_packet.bin

    # Chapter 2 — query an upstream resolver
    ./dns-resolver lookup google.com @8.8.8.8

    # Chapter 4 — serve as a forwarding resolver on UDP :2053
    ./dns-resolver serve --upstream 8.8.8.8:53
    dig @127.0.0.1 -p 2053 google.com

    # Chapter 5 — serve as a recursive resolver (no upstream)
    ./dns-resolver serve --mode recursive
    dig @127.0.0.1 -p 2053 google.com

## License

MIT — see [LICENSE](LICENSE).
