use crate::format::QuoteFormatter;
use crate::krx::{QuoteRef, parse_accept_time_cs};
use std::collections::BTreeMap;
use std::io::{self, Write};

pub const DEFAULT_REORDER_WINDOW_USEC: u64 = 3_000_000; // 3 seconds

// 1024 centisecond slots = 10.24s window, covering the 3s reorder guarantee with headroom.
const WHEEL_SIZE: usize = 1024;
const WHEEL_MASK: usize = WHEEL_SIZE - 1;
const BITMAP_WORDS: usize = WHEEL_SIZE / 64;

#[derive(Default)]
struct WheelBucket {
    buf: Vec<u8>,
    accept_time: [u8; 8],
    min_pcap_usec: u64,
    occupied: bool,
}

struct FallbackBucket {
    buf: Vec<u8>,
    min_pcap_usec: u64,
}

/// Centisecond timing wheel for reordering quotes by 10ms `accept_time` (`HHMMSSuu`).
///
/// Key properties:
/// - O(1) push and O(1) occupancy lookup via a 1024-slot ring buffer + 128-byte bitmap.
/// - Strictly FIFO-stable within each 10ms bucket (quotes sharing an `accept_time`
///   preserve capture arrival order).
/// - Pre-formats lines into reused per-bucket byte buffers so flushing is a single
///   bulk write per bucket with zero heap allocations after warm-up.
/// - Seamlessly spills non-wall-clock or out-of-window timestamps (e.g. `99999999` or
///   midnight jumps) into a `BTreeMap` fallback and merges in exact key order.
pub struct ReorderBuffer {
    window_usec: u64,
    max_pcap_usec: u64,
    slots: Vec<WheelBucket>,
    bitmap: [u64; BITMAP_WORDS],
    occupied_count: usize,
    min_cs: u32,
    max_cs: u32,
    fallback: BTreeMap<[u8; 8], FallbackBucket>,
}

impl ReorderBuffer {
    pub fn new(window_usec: u64) -> Self {
        let mut slots = Vec::with_capacity(WHEEL_SIZE);
        slots.resize_with(WHEEL_SIZE, WheelBucket::default);
        Self {
            window_usec,
            max_pcap_usec: 0,
            slots,
            bitmap: [0u64; BITMAP_WORDS],
            occupied_count: 0,
            min_cs: 0,
            max_cs: 0,
            fallback: BTreeMap::new(),
        }
    }

    /// Flushes any buckets expired by the incoming packet's timestamp, then inserts the quote.
    #[inline]
    pub fn push_and_flush<W: Write>(
        &mut self,
        quote: &QuoteRef<'_>,
        formatter: &mut QuoteFormatter,
        out: &mut W,
    ) -> io::Result<()> {
        let pcap_usec = quote.pcap_ts_usec();
        if pcap_usec > self.max_pcap_usec {
            self.max_pcap_usec = pcap_usec;
            self.flush_ready(out)?;
        }

        if let Some(cs) = parse_accept_time_cs(quote.accept_time) {
            if !self.fallback.is_empty() && self.fallback.contains_key(quote.accept_time) {
                self.insert_fallback(pcap_usec, quote, formatter);
            } else if self.fits_in_wheel(cs) {
                self.insert_wheel(cs, pcap_usec, quote, formatter);
            } else {
                self.insert_fallback(pcap_usec, quote, formatter);
            }
        } else {
            self.insert_fallback(pcap_usec, quote, formatter);
        }

        Ok(())
    }

    /// Flushes all remaining buffered quotes in strictly ascending `accept_time` order.
    pub fn finish<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        while self.occupied_count > 0 || !self.fallback.is_empty() {
            match self.next_source() {
                Some(NextSource::Wheel) => self.pop_wheel_min(out)?,
                Some(NextSource::Fallback) => self.pop_fallback_min(out)?,
                None => break,
            }
        }
        Ok(())
    }

    #[inline]
    fn fits_in_wheel(&self, cs: u32) -> bool {
        if self.occupied_count == 0 {
            return true;
        }
        let new_min = self.min_cs.min(cs);
        let new_max = self.max_cs.max(cs);
        (new_max - new_min) < WHEEL_SIZE as u32
    }

    #[inline]
    fn insert_wheel(
        &mut self,
        cs: u32,
        pcap_usec: u64,
        quote: &QuoteRef<'_>,
        formatter: &mut QuoteFormatter,
    ) {
        if self.occupied_count == 0 {
            self.min_cs = cs;
            self.max_cs = cs;
        } else {
            if cs < self.min_cs {
                self.min_cs = cs;
            }
            if cs > self.max_cs {
                self.max_cs = cs;
            }
        }

        let idx = (cs as usize) & WHEEL_MASK;
        let slot = &mut self.slots[idx];
        if !slot.occupied {
            slot.occupied = true;
            slot.accept_time = *quote.accept_time;
            slot.min_pcap_usec = pcap_usec;
            self.bitmap[idx >> 6] |= 1u64 << (idx & 63);
            self.occupied_count += 1;
        } else if pcap_usec < slot.min_pcap_usec {
            slot.min_pcap_usec = pcap_usec;
        }

        formatter.format_into(quote, &mut slot.buf);
    }

    #[cold]
    fn insert_fallback(
        &mut self,
        pcap_usec: u64,
        quote: &QuoteRef<'_>,
        formatter: &mut QuoteFormatter,
    ) {
        let entry = self
            .fallback
            .entry(*quote.accept_time)
            .or_insert_with(|| FallbackBucket {
                buf: Vec::with_capacity(256),
                min_pcap_usec: pcap_usec,
            });
        if pcap_usec < entry.min_pcap_usec {
            entry.min_pcap_usec = pcap_usec;
        }
        formatter.format_into(quote, &mut entry.buf);
    }

    #[inline]
    fn flush_ready<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        if self.fallback.is_empty() {
            // Hot path: wheel only
            while self.occupied_count > 0 {
                let idx = (self.min_cs as usize) & WHEEL_MASK;
                let min_pcap = self.slots[idx].min_pcap_usec;
                if self.max_pcap_usec.saturating_sub(min_pcap) < self.window_usec {
                    break;
                }
                self.pop_wheel_min(out)?;
            }
            return Ok(());
        }

        // General path: merge wheel and fallback in strict accept_time order
        while let Some(src) = self.next_source() {
            let min_pcap = match src {
                NextSource::Wheel => self.slots[(self.min_cs as usize) & WHEEL_MASK].min_pcap_usec,
                NextSource::Fallback => self.fallback.first_key_value().unwrap().1.min_pcap_usec,
            };
            if self.max_pcap_usec.saturating_sub(min_pcap) < self.window_usec {
                break;
            }
            match src {
                NextSource::Wheel => self.pop_wheel_min(out)?,
                NextSource::Fallback => self.pop_fallback_min(out)?,
            }
        }
        Ok(())
    }

    #[inline]
    fn next_source(&self) -> Option<NextSource> {
        let wheel_key = if self.occupied_count > 0 {
            Some(&self.slots[(self.min_cs as usize) & WHEEL_MASK].accept_time)
        } else {
            None
        };
        let fallback_key = self.fallback.first_key_value().map(|(k, _)| k);

        match (wheel_key, fallback_key) {
            (Some(w), Some(f)) => {
                if w < f {
                    Some(NextSource::Wheel)
                } else {
                    Some(NextSource::Fallback)
                }
            }
            (Some(_), None) => Some(NextSource::Wheel),
            (None, Some(_)) => Some(NextSource::Fallback),
            (None, None) => None,
        }
    }

    #[inline]
    fn pop_wheel_min<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        let idx = (self.min_cs as usize) & WHEEL_MASK;
        let slot = &mut self.slots[idx];
        out.write_all(&slot.buf)?;
        slot.buf.clear();
        slot.occupied = false;
        self.bitmap[idx >> 6] &= !(1u64 << (idx & 63));
        self.occupied_count -= 1;

        if self.occupied_count > 0 {
            self.advance_min_cs();
        }
        Ok(())
    }

    #[cold]
    fn pop_fallback_min<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        if let Some((_, bucket)) = self.fallback.pop_first() {
            out.write_all(&bucket.buf)?;
        }
        Ok(())
    }

    /// Finds the next occupied centisecond strictly greater than `self.min_cs` using
    /// the 128-byte occupancy bitmap (`trailing_zeros` skips up to 64 empty slots per op).
    #[inline]
    fn advance_min_cs(&mut self) {
        let start = self.min_cs + 1;
        let span = (self.max_cs - start + 1) as usize;
        let start_idx = (start as usize) & WHEEL_MASK;

        let mut offset = 0usize;
        while offset < span {
            let idx = (start_idx + offset) & WHEEL_MASK;
            let word_idx = idx >> 6;
            let bit_idx = idx & 63;

            let masked = self.bitmap[word_idx] >> bit_idx;
            if masked != 0 {
                let delta = masked.trailing_zeros() as usize;
                let total_delta = offset + delta;
                if total_delta < span {
                    self.min_cs = start + total_delta as u32;
                    return;
                }
            }
            // Advance to the start of the next 64-bit word
            offset += 64 - bit_idx;
        }
    }
}

#[derive(Clone, Copy)]
enum NextSource {
    Wheel,
    Fallback,
}
