use crate::krx::{QuoteRef, trim_leading_zeros};

pub const KST_UTC_OFFSET_SECS: i64 = 32_400; // UTC+9
pub const MAX_LINE_LEN: usize = 192; // Actual max is 181 bytes

#[rustfmt::skip]
const DIGITS2: &[u8; 200] = b"\
00010203040506070809\
10111213141516171819\
20212223242526272829\
30313233343536373839\
40414243444546474849\
50515253545556575859\
60616263646566676869\
70717273747576777879\
80818283848586878889\
90919293949596979899";

/// Caches the formatted `HH:MM:SS.` prefix for the most recently seen whole second.
///
/// In market data captures, thousands of consecutive packets share the same second,
/// avoiding redundant modulo/division work on >99.9% of packets.
#[derive(Debug, Clone)]
pub struct QuoteFormatter {
    utc_offset_secs: i64,
    cached_sec: u32,
    cached_valid: bool,
    line: [u8; MAX_LINE_LEN],
}

impl Default for QuoteFormatter {
    fn default() -> Self {
        Self::new(KST_UTC_OFFSET_SECS)
    }
}

impl QuoteFormatter {
    pub fn new(utc_offset_secs: i64) -> Self {
        let mut line = [0u8; MAX_LINE_LEN];
        // Pre-fill constant prefix punctuation once for the lifetime of the formatter:
        // `HH:MM:SS.uuuuuu HH:MM:SS:uu <12-byte ISIN>`
        line[2] = b':';
        line[5] = b':';
        line[8] = b'.';
        line[15] = b' ';
        line[18] = b':';
        line[21] = b':';
        line[24] = b':';
        line[27] = b' ';

        Self {
            utc_offset_secs,
            cached_sec: 0,
            cached_valid: false,
            line,
        }
    }

    #[cold]
    fn update_hms(&mut self, pcap_sec: u32) {
        let total_secs = (i64::from(pcap_sec) + self.utc_offset_secs).rem_euclid(86_400) as usize;
        let hours = total_secs / 3600;
        let rem = total_secs % 3600;
        let mins = rem / 60;
        let secs = rem % 60;

        self.line[0] = DIGITS2[hours * 2];
        self.line[1] = DIGITS2[hours * 2 + 1];
        self.line[3] = DIGITS2[mins * 2];
        self.line[4] = DIGITS2[mins * 2 + 1];
        self.line[6] = DIGITS2[secs * 2];
        self.line[7] = DIGITS2[secs * 2 + 1];

        self.cached_sec = pcap_sec;
        self.cached_valid = true;
    }

    /// Formats a quote line directly into `dst` with a single `extend_from_slice`.
    ///
    /// Format: `HH:MM:SS.uuuuuu HH:MM:SS:uu ISIN <bids 5..=1> <asks 1..=5>\n`
    #[inline]
    pub fn format_into(&mut self, quote: &QuoteRef<'_>, dst: &mut Vec<u8>) {
        // 0..9: HH:MM:SS. (cached per whole second)
        if !self.cached_valid || self.cached_sec != quote.pcap_sec {
            self.update_hms(quote.pcap_sec);
        }

        let line = &mut self.line;

        // 9..15: uuuuuu (clamped to 999_999 for safety on malformed packets)
        let us = (quote.pcap_usec as usize).min(999_999);
        let hi = us / 10_000;
        let rem = us % 10_000;
        let mid = rem / 100;
        let lo = rem % 100;
        line[9] = DIGITS2[hi * 2];
        line[10] = DIGITS2[hi * 2 + 1];
        line[11] = DIGITS2[mid * 2];
        line[12] = DIGITS2[mid * 2 + 1];
        line[13] = DIGITS2[lo * 2];
        line[14] = DIGITS2[lo * 2 + 1];

        // 16..27: HH:MM:SS:uu (colons already pre-filled)
        let at = quote.accept_time;
        line[16] = at[0];
        line[17] = at[1];
        line[19] = at[2];
        line[20] = at[3];
        line[22] = at[4];
        line[23] = at[5];
        line[25] = at[6];
        line[26] = at[7];

        // 28..40: ISIN
        line[28..40].copy_from_slice(quote.issue_code);

        let mut pos = 40;

        // Bids: 5th level down to 1st level
        for i in (0..5).rev() {
            let (price_raw, qty_raw) = quote.bid_raw(i);
            pos = write_order(line, pos, qty_raw, price_raw);
        }

        // Asks: 1st level up to 5th level
        for i in 0..5 {
            let (price_raw, qty_raw) = quote.ask_raw(i);
            pos = write_order(line, pos, qty_raw, price_raw);
        }

        line[pos] = b'\n';
        pos += 1;

        dst.extend_from_slice(&line[..pos]);
    }
}

#[inline]
fn write_order(
    line: &mut [u8; MAX_LINE_LEN],
    mut pos: usize,
    qty_raw: &[u8],
    price_raw: &[u8],
) -> usize {
    let qty = trim_leading_zeros(qty_raw);
    let price = trim_leading_zeros(price_raw);

    line[pos] = b' ';
    pos += 1;
    line[pos..pos + qty.len()].copy_from_slice(qty);
    pos += qty.len();
    line[pos] = b'@';
    pos += 1;
    line[pos..pos + price.len()].copy_from_slice(price);
    pos += price.len();
    pos
}
