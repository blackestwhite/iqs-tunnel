# IQS-Tunnel

IQS-Tunnel is an improved Go rewrite of QS-Tunnel. It keeps the same asymmetric transport idea:

- uplink travels inside DNS query names
- downlink returns over spoofed UDP packets

The difference is that IQS-Tunnel adds a reliability layer around that transport instead of sending blindly.

## Research Notice

This project is a research prototype for studying DNS-based uplink transport, spoofed UDP downlink behavior, and reliability techniques around asymmetric tunnels. It is not presented as a production-ready censorship circumvention product.

## Warning

IP spoofing can be disruptive, may violate provider policies, and can be illegal or unauthorized on many networks. Use IQS-Tunnel only in environments you own or are explicitly authorized to test, and only for controlled research, lab work, or defensive experimentation.

## What Changed

- DNS responses now carry a signed ACK report, so the client knows which uplink packets really reached the server.
- Every tunnel packet includes `session_id`, `seq`, `ack`, and `ack_bits`.
- The client acknowledges spoofed downlink packets in later DNS uplink packets, so the server can retransmit only what is still missing.
- DNS retries are cache-busted with per-send fragment nonces.
- The client keeps basic performance scores for resolvers and prefers healthier ones.
- Optional single-parity shard protection is available on the spoofed downlink path.

## Layout

- `cmd/iqs-client`: local client binary
- `cmd/iqs-server`: authoritative DNS + spoof server binary
- `internal/protocol`: wire format, ACK logic, fragmentation, parity
- `internal/dnsmsg`: minimal DNS TXT query/response codec
- `internal/rawip`: raw IPv4 UDP sender used for spoofed downlink

## Important Notes

- The server must be authoritative for the configured domains.
- The server needs permission to open a raw IPv4 socket in order to send spoofed UDP.
- The client still needs to transmit uplink traffic. Spoofing is only for the return path.
- This layer is still a UDP forwarder. A reliable encrypted UDP protocol such as Hysteria, WireGuard, or a QUIC-based transport should sit above it.
- The release binaries are intended for research and controlled testing. You are responsible for legal, policy, and operational compliance when using them.

## Releases

The repository includes a GitHub Actions workflow that cross-builds release archives for:

- Linux
- macOS
- FreeBSD

When a tag like `v0.1.0` is pushed, the workflow attaches archives and a `SHA256SUMS.txt` file to the GitHub release page.

## Run

```bash
go run ./cmd/iqs-server -config configs/server.example.json
go run ./cmd/iqs-client -config configs/client.example.json
```

You can also print the embedded build version:

```bash
go run ./cmd/iqs-server -version
go run ./cmd/iqs-client -version
```

## Protocol Summary

1. The local app sends UDP to the client bind address.
2. The client wraps the datagram in a signed tunnel packet and splits it into DNS-safe fragments.
3. Recursive resolvers forward the query to the authoritative server.
4. The authoritative server reassembles the packet, forwards the UDP payload upstream, and returns a TXT ACK report in the DNS response.
5. Upstream responses are wrapped in signed downlink packets, fragmented if needed, and sent back as spoofed UDP.
6. The client reassembles them, forwards the payload locally, and piggybacks downlink ACK state on later DNS uplink packets.
