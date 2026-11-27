#![forbid(unsafe_code)]

pub mod format;
pub mod krx;
pub mod pcap;
pub mod reorder;

use crate::format::{KST_UTC_OFFSET_SECS, MAX_LINE_LEN, QuoteFormatter};
use crate::krx::{QuoteRef, is_feed_port};
use crate::pcap::{PcapReader, extract_udp_payload};
use crate::reorder::{DEFAULT_REORDER_WINDOW_USEC, ReorderBuffer};
use anyhow::Result;
use std::io::{self, Read, Write};

const OUT_BUF_CAP: usize = 1024 * 1024; // 1 MiB output buffer
const OUT_FLUSH_THRESHOLD: usize = OUT_BUF_CAP - MAX_LINE_LEN;

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub reorder: bool,
    pub reorder_window_usec: u64,
    pub utc_offset_secs: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reorder: false,
            reorder_window_usec: DEFAULT_REORDER_WINDOW_USEC,
            utc_offset_secs: KST_UTC_OFFSET_SECS,
        }
    }
}

/// Single-stage output buffer that formats lines directly into a 1 MiB `Vec<u8>`
/// without an intermediate per-line buffer copy.
struct OutputBuffer<W> {
    buf: Vec<u8>,
    inner: W,
}

impl<W: Write> OutputBuffer<W> {
    fn new(inner: W) -> Self {
        Self {
            buf: Vec::with_capacity(OUT_BUF_CAP),
            inner,
        }
    }

    #[inline]
    fn maybe_flush(&mut self) -> io::Result<()> {
        if self.buf.len() >= OUT_FLUSH_THRESHOLD {
            self.flush_buf()?;
        }
        Ok(())
    }

    #[cold]
    fn flush_buf(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.inner.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }
}

impl<W: Write> Write for OutputBuffer<W> {
    #[inline]
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.buf.capacity() - self.buf.len() {
            self.flush_buf()?;
            if data.len() >= self.buf.capacity() {
                self.inner.write_all(data)?;
                return Ok(data.len());
            }
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf()?;
        self.inner.flush()
    }
}

/// Streams a PCAP from `reader`, extracts KRX B6034 KOSPI200 quotes, and writes
/// formatted 5-level order books to `writer`.
pub fn process_pcap<R: Read, W: Write>(reader: R, writer: W, config: Config) -> Result<()> {
    let mut pcap = PcapReader::new(reader)?;
    let link_type = pcap.header().link_type;
    let mut formatter = QuoteFormatter::new(config.utc_offset_secs);
    let mut out = OutputBuffer::new(writer);

    if config.reorder {
        let mut reorder = ReorderBuffer::new(config.reorder_window_usec);
        while let Some(pkt) = pcap.next_packet()? {
            let Some((dst_port, udp_payload)) = extract_udp_payload(link_type, pkt.data) else {
                continue;
            };
            if !is_feed_port(dst_port) {
                continue;
            }
            if let Some(quote) = QuoteRef::parse(pkt.ts_sec, pkt.ts_usec, udp_payload) {
                reorder.push_and_flush(&quote, &mut formatter, &mut out)?;
            }
        }
        reorder.finish(&mut out)?;
    } else {
        while let Some(pkt) = pcap.next_packet()? {
            let Some((dst_port, udp_payload)) = extract_udp_payload(link_type, pkt.data) else {
                continue;
            };
            if !is_feed_port(dst_port) {
                continue;
            }
            if let Some(quote) = QuoteRef::parse(pkt.ts_sec, pkt.ts_usec, udp_payload) {
                formatter.format_into(&quote, &mut out.buf);
                out.maybe_flush()?;
            }
        }
    }

    out.flush()?;
    Ok(())
}
