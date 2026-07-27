use anyhow::Result;
use clap::Parser;
use helpers::{parse_decimals, push_n, push_u32};
use memmap2::Mmap;
use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
};

pub mod helpers;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const HEADER: &[u8; 5] = b"B6034";
const FEED_PORTS: [u16; 2] = [15515, 15516];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the pcap file
    #[arg(index = 1)]
    path: PathBuf,

    /// Reorder messages by quote accept time
    #[arg(short = 'r')]
    reorder: bool,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Default)]
pub struct Order {
    quantity: u32,
    price: u16,
}

#[derive(Debug, Eq, PartialEq)]
struct QuotePacket {
    pcap_time_sec: u32,
    pcap_time_usec: u32,
    accept_time: [u8; 8], // Stack-allocated 8-byte ASCII array (HHMMSSuu)
    issue_code: [u8; 12], // Stack-allocated 12-byte ASCII array (ISIN)
    bids: [Order; 5],
    asks: [Order; 5],
}

// Order QuotePacket by `accept_time` for min-heap reordering
impl Ord for QuotePacket {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering so the earliest accept_time pops first in Min-Heap
        other.accept_time.cmp(&self.accept_time)
    }
}

impl PartialOrd for QuotePacket {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[inline]
fn parse_pcap_timestamp(header: &[u8]) -> (u32, u32) {
    let ts_sec = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let ts_usec = u32::from_le_bytes(header[4..8].try_into().unwrap());
    (ts_sec, ts_usec)
}

#[inline]
fn parse_quote_payload(pcap_sec: u32, pcap_usec: u32, payload: &[u8]) -> Option<QuotePacket> {
    if payload.len() < 215 || !payload.starts_with(HEADER) {
        return None;
    }

    // Zero-allocation stack array copies
    let issue_code: [u8; 12] = payload[5..17].try_into().ok()?;
    let accept_time: [u8; 8] = payload[206..214].try_into().ok()?;

    let mut bids = [Order::default(); 5];
    for (i, bid) in bids.iter_mut().enumerate() {
        let b_off = 29 + i * 12;
        let price = parse_decimals(&payload[b_off..b_off + 5]);
        let quantity = parse_decimals(&payload[b_off + 5..b_off + 12]);
        *bid = Order { quantity, price }
    }

    let mut asks = [Order::default(); 5];
    for (i, ask) in asks.iter_mut().enumerate() {
        let a_off = 96 + i * 12;
        let price = parse_decimals(&payload[a_off..a_off + 5]);
        let qty = parse_decimals(&payload[a_off + 5..a_off + 12]);
        *ask = Order {
            quantity: qty,
            price,
        }
    }

    Some(QuotePacket {
        pcap_time_sec: pcap_sec,
        pcap_time_usec: pcap_usec,
        accept_time,
        issue_code,
        bids,
        asks,
    })
}

#[inline]
fn print_packet<W: Write>(buf: &mut Vec<u8>, pkt: &QuotePacket, out: &mut W) -> Result<()> {
    buf.clear();

    let total_secs = (pkt.pcap_time_sec + 32_400) % 86400;
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    // accept time
    push_n::<2>(buf, hours);
    buf.push(b':');
    push_n::<2>(buf, mins);
    buf.push(b':');
    push_n::<2>(buf, secs);
    buf.push(b'.');
    push_n::<6>(buf, pkt.pcap_time_usec);

    buf.push(b' ');
    for (i, chunk) in pkt.accept_time.chunks(2).enumerate() {
        if i > 0 {
            buf.push(b':');
        }
        buf.extend_from_slice(chunk);
    }
    buf.push(b' ');
    buf.extend_from_slice(&pkt.issue_code);

    // Bids: 5th level down to 1st level
    for i in (0..5).rev() {
        buf.push(b' ');
        push_u32(buf, pkt.bids[i].quantity);
        buf.push(b'@');
        push_u32(buf, pkt.bids[i].price as u32);
    }

    // Asks: 1st level up to 5th level
    for i in 0..5 {
        buf.push(b' ');
        push_u32(buf, pkt.asks[i].quantity);
        buf.push(b'@');
        push_u32(buf, pkt.asks[i].price as u32);
    }

    buf.push(b'\n');
    out.write_all(buf)?;

    Ok(())
}

pub fn process_payload<W: Write>(
    bytes: &[u8],
    reorder: bool,
    line: &mut Vec<u8>,
    out: &mut W,
) -> Result<()> {
    let mut offset = 24; // Skip 24-byte PCAP global header
    let mut heap: BinaryHeap<QuotePacket> = BinaryHeap::with_capacity(1024 * 1024);
    let mut max_pcap_sec = 0u32;

    while offset + 16 <= bytes.len() {
        let pcap_hdr = &bytes[offset..offset + 16];
        let (pcap_sec, pcap_usec) = parse_pcap_timestamp(pcap_hdr);
        let incl_len =
            u32::from_le_bytes([pcap_hdr[8], pcap_hdr[9], pcap_hdr[10], pcap_hdr[11]]) as usize;

        let pkt_start = offset + 16;
        let pkt_end = pkt_start + incl_len;

        if pkt_end > bytes.len() {
            break;
        }

        let pkt_bytes = &bytes[pkt_start..pkt_end];

        if pkt_bytes.len() >= 34 {
            let eth_type = u16::from_be_bytes([pkt_bytes[12], pkt_bytes[13]]);
            let ip_start = if eth_type == 0x8100 { 18 } else { 14 };

            if pkt_bytes.len() >= ip_start + 20 {
                let ihl = (pkt_bytes[ip_start] & 0x0F) as usize * 4;
                let udp_start = ip_start + ihl;

                // Assumption: each MDF message fits in a single non-fragmented UDP datagram.
                // IP fragmentation and UDP reassembly are not handled.
                if pkt_bytes.len() < udp_start + 8 {
                    offset = pkt_end;
                    continue;
                }

                let dst_port = u16::from_be_bytes([pkt_bytes[udp_start + 2], pkt_bytes[udp_start + 3]]);
                if !FEED_PORTS.contains(&dst_port) {
                    offset = pkt_end;
                    continue;
                }

                let payload_start = udp_start + 8; // Skip 8-byte UDP header

                if pkt_bytes.len() >= payload_start {
                    let udp_payload = &pkt_bytes[payload_start..];

                    if let Some(quote) = parse_quote_payload(pcap_sec, pcap_usec, udp_payload) {
                        if reorder {
                            max_pcap_sec = max_pcap_sec.max(pcap_sec);
                            heap.push(quote);

                            // Flush packets older than 3 seconds to keep memory bounded
                            while let Some(top) = heap.peek() {
                                if max_pcap_sec > top.pcap_time_sec + 3 {
                                    print_packet(line, &heap.pop().unwrap(), out)?;
                                } else {
                                    break;
                                }
                            }
                        } else {
                            print_packet(line, &quote, out)?;
                        }
                    }
                }
            }
        }

        offset = pkt_end;
    }

    // Flush any remaining buffered packets from the heap
    if reorder {
        while let Some(quote) = heap.pop() {
            print_packet(line, &quote, out)?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let file = File::open(&args.path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    mmap.advise(memmap2::Advice::Sequential)?;

    if mmap.len() < 24 {
        return Ok(());
    }

    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(1024 * 1024, stdout.lock());
    let mut line_buf = Vec::with_capacity(512);
    process_payload(&mmap, args.reorder, &mut line_buf, &mut out)?;

    out.flush()?;
    Ok(())
}

