# tsuru

High-throughput, `#![forbid(unsafe_code)]` parser for KRX MDF (Korean exchange market data) PCAP captures. Streams classic PCAP files (or `stdin`), extracts KOSPI200 `B6034` quote messages on UDP ports `15515` and `15516`, and prints a 5-level order book per line.

## Build and run

Requires a Rust toolchain (edition 2024).

```bash
cargo build --release
./target/release/tsuru <pcap-file> [-r] [--utc-offset-secs 32400]

# Or stream from stdin / compressed captures:
zcat capture.pcap.gz | ./target/release/tsuru - -r
```

- `-r, --reorder`: Reorder quotes by 10ms quote accept time (`HHMMSSuu`) using a 3-second sliding window while preserving FIFO arrival order on ties.
- `--utc-offset-secs`: UTC offset applied to packet capture timestamps (defaults to `+32400` / KST UTC+9).

## Output format

```text
HH:MM:SS.uuuuuu HH:MM:SS:uu ISIN <5 bids> <5 asks>
```

- Column 1: Packet capture timestamp (default KST, microsecond precision).
- Column 2: Exchange quote accept time (`HH:MM:SS:uu`, 10ms resolution).
- Column 3: 12-byte issue code (ISIN).
- Bids are printed 5th level down to 1st level (`qty@price`); asks 1st level up to 5th level (`qty@price`).

## Design decisions

- **Streaming reader over `mmap`**: Reads into a single reusable 2 MiB buffer with zero `unsafe` code (`#![forbid(unsafe_code)]`). Supports regular files, pipes, and `stdin`, avoids `SIGBUS`/concurrent-truncation hazards, and keeps RSS constant (~5 MiB in streaming mode) regardless of capture size.
- **Strict header validation**: Validates the 24-byte PCAP global header (little/big-endian, microsecond/nanosecond timestamps, rejecting PCAPNG with a clear error), link-layer framing (`Ethernet` with 802.1Q/QinQ VLAN unwrapping, `RawIp`, `LinuxSll`), IPv4 version/IHL/protocol (`UDP = 17`), fragmentation flags/offset, and IP/UDP lengths. Only non-fragmented UDP datagrams are parsed; fragmented IP packets are explicitly skipped.
- **Zero-parse ASCII order formatting**: B6034 prices (5 ASCII digits) and quantities (7 ASCII digits) are emitted as decimal integers without leading zeros. Rather than parsing 20 fields per packet into binary integers and dividing back to ASCII, `tsuru` trims leading `'0'` bytes directly from the packet slice — eliminating 20 division loops per packet and avoiding integer truncation on 5-digit prices (`0..=99999`). Whole-second `HH:MM:SS.` prefixes are cached across packets, and microseconds are formatted via a 200-byte 2-digit lookup table.
- **Centisecond timing wheel for `-r` reordering**: Because `accept_time` has 10ms resolution (`HHMMSSuu`), a 3-second reorder window contains at most ~300 distinct keys. Instead of an $O(\log N)$ unstable `BinaryHeap`, `-r` uses a 1024-slot ring buffer with a 128-byte occupancy bitmap:
  - $O(1)$ insertion and `trailing_zeros` bucket advancement.
  - Strictly FIFO-stable within every 10ms bucket.
  - Formats lines directly into reused per-bucket `Vec<u8>` buffers so flushing is a single bulk write per bucket.
  - Spills non-wall-clock or out-of-window timestamps (e.g. `99999999` or midnight wraps) to a `BTreeMap` fallback merged in strict lexicographical order.
  - Allocated only when `-r` is passed.
- **Minimal dependencies & single-stage output buffering**: Only `clap` and `anyhow` are required. Lines write directly into a single 1 MiB output buffer (no intermediate per-line `Vec` → `BufWriter` copy, and no custom allocator overhead on a hot path that doesn't allocate). Profiling symbols live in `[profile.profiling]` (`cargo build --profile profiling`) so release builds remain stripped and small.

## Performance (v1 vs v2)

Measured on a synthetic 201.4 MiB capture (800,000 packets, 640,134 B6034 quotes, 20% non-quote traffic, up to 1.2s out-of-order jitter, output to `/dev/null`, warm cache, median of 7 runs):

| Metric | v1 (`mmap` + `BinaryHeap` + `mimalloc`) | v2 (streaming + timing wheel) | Change |
| --- | ---: | ---: | ---: |
| Streaming (`no -r`) | 185.1 ms (1.06 GiB/s) | 142.2 ms (1.38 GiB/s) | **1.30× faster** |
| Streaming peak RSS | 213.5 MB | 4.9 MB | **43× less RAM** |
| Reorder (`-r`) | 389.1 ms (0.51 GiB/s) | 196.8 ms (1.00 GiB/s) | **1.98× faster** |
| Reorder peak RSS | 225.0 MB | 39.4 MB | **5.7× less RAM** |
| Reorder 10ms FIFO tie violations | 636,445 / 640,134 | **0** | Fixed |
| Release binary size | 825 KB | 538 KB | **-35%** |

## Testing

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```
