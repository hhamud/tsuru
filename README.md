# tsuru

Zero-allocation parser for KRX MDF (Korean exchange market data) pcap files. Reads a UDP-multicast pcap capture, extracts B6034 KOSPI200 quote messages, and prints a 5-level order book per line.

## Build and run

Requires a Rust toolchain.

```bash
cargo build --release
./target/release/tsuru <pcap-file> [-r]
```

Use `-r` to reorder messages by quote accept time. This uses a small bounded min-heap so out-of-order packets are emitted in accept-time order.

## Output format

```
HH:MM:SS.uuuuuu HH:MM:SS:uu ISIN <5 bids> <5 asks>
```

Bids are printed 5th level to 1st level; asks 1st level to 5th level.

## Design decisions

mmap: The pcap is memory-mapped with `memmap2::Mmap` and `advise(Sequential)`. The parser is sequential and read-only, so mmap avoids read syscalls and lets the OS page the file in on demand. 

Single-threaded: Each packet depends only on its own bytes, so there is no shared mutable state to protect. More importantly, the throughput bottleneck is not parsing but writing formatted text to stdout. Adding parser threads would not speed up the single stdout writer; it would only add synchronization (locks, queues, or ordered output) and contention overhead. Multithreading only makes sense once the output stage is removed or parallelized.

Heap-bound: The only dynamic allocation is the 1 MiB reorder heap and the 1 MiB output buffer. The parser is otherwise zero-allocation: every quote is a stack-allocated fixed-size struct (`[u8; 12]`, `[Order; 5]`, etc.), integer formatting writes directly into a reused buffer, and the output line is reused for every packet. When reordering is enabled, packets older than 3 seconds are flushed to keep the heap bounded.

Allocator: `mimalloc` is used as the global allocator for low-latency small heap allocations.

Optimization: CPU profiling with `perf` and `cargo flamegraph` was used to guide the design. The profiles showed that parsing itself is cheap and the dominant cost is formatting and writing output, which is why the implementation stays single-threaded and focuses on minimizing allocations and buffering output.

Only non-fragmented UDP is handled; IP fragmentation and UDP reassembly are not ignored in this implementation.

Only UDP destination ports 15515 and 15516 are parsed.

