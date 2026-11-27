pub const HEADER: &[u8; 5] = b"B6034";
pub const FEED_PORTS: [u16; 2] = [15515, 15516];
pub const MSG_LEN: usize = 215;

pub const ISIN_OFFSET: usize = 5;
pub const ISIN_LEN: usize = 12;
pub const BIDS_OFFSET: usize = 29;
pub const ASKS_OFFSET: usize = 96;
pub const LEVEL_STRIDE: usize = 12;
pub const PRICE_LEN: usize = 5;
pub const QTY_LEN: usize = 7;
pub const LEVELS: usize = 5;
pub const ACCEPT_TIME_OFFSET: usize = 206;
pub const ACCEPT_TIME_LEN: usize = 8;

/// Zero-copy view into a KRX B6034 KOSPI200 quote payload.
///
/// Borrows directly from the packet buffer so no intermediate integer parsing
/// or per-packet struct copying is needed on the hot path.
#[derive(Debug, Clone, Copy)]
pub struct QuoteRef<'a> {
    pub pcap_sec: u32,
    pub pcap_usec: u32,
    pub issue_code: &'a [u8; ISIN_LEN],
    pub accept_time: &'a [u8; ACCEPT_TIME_LEN],
    pub bids_raw: &'a [u8; LEVELS * LEVEL_STRIDE],
    pub asks_raw: &'a [u8; LEVELS * LEVEL_STRIDE],
}

impl<'a> QuoteRef<'a> {
    /// Parses a B6034 quote payload without allocating or converting decimals to integers.
    #[inline]
    pub fn parse(pcap_sec: u32, pcap_usec: u32, payload: &'a [u8]) -> Option<Self> {
        if payload.len() < MSG_LEN || &payload[0..5] != HEADER {
            return None;
        }

        let issue_code: &[u8; ISIN_LEN] = payload[ISIN_OFFSET..ISIN_OFFSET + ISIN_LEN]
            .try_into()
            .ok()?;
        let bids_raw: &[u8; LEVELS * LEVEL_STRIDE] = payload
            [BIDS_OFFSET..BIDS_OFFSET + LEVELS * LEVEL_STRIDE]
            .try_into()
            .ok()?;
        let asks_raw: &[u8; LEVELS * LEVEL_STRIDE] = payload
            [ASKS_OFFSET..ASKS_OFFSET + LEVELS * LEVEL_STRIDE]
            .try_into()
            .ok()?;
        let accept_time: &[u8; ACCEPT_TIME_LEN] = payload
            [ACCEPT_TIME_OFFSET..ACCEPT_TIME_OFFSET + ACCEPT_TIME_LEN]
            .try_into()
            .ok()?;

        Some(Self {
            pcap_sec,
            pcap_usec,
            issue_code,
            accept_time,
            bids_raw,
            asks_raw,
        })
    }

    #[inline]
    pub fn pcap_ts_usec(&self) -> u64 {
        u64::from(self.pcap_sec) * 1_000_000 + u64::from(self.pcap_usec)
    }

    /// Returns `(price_ascii, quantity_ascii)` for bid level `level` (`0..5`, 0 = best bid).
    #[inline]
    pub fn bid_raw(&self, level: usize) -> (&'a [u8], &'a [u8]) {
        let off = level * LEVEL_STRIDE;
        (
            &self.bids_raw[off..off + PRICE_LEN],
            &self.bids_raw[off + PRICE_LEN..off + LEVEL_STRIDE],
        )
    }

    /// Returns `(price_ascii, quantity_ascii)` for ask level `level` (`0..5`, 0 = best ask).
    #[inline]
    pub fn ask_raw(&self, level: usize) -> (&'a [u8], &'a [u8]) {
        let off = level * LEVEL_STRIDE;
        (
            &self.asks_raw[off..off + PRICE_LEN],
            &self.asks_raw[off + PRICE_LEN..off + LEVEL_STRIDE],
        )
    }
}

#[inline]
pub fn is_feed_port(port: u16) -> bool {
    port == FEED_PORTS[0] || port == FEED_PORTS[1]
}

/// Parses an 8-byte ASCII `HHMMSSuu` accept timestamp into centiseconds since midnight.
///
/// Returns `None` if any byte is not an ASCII digit or if the fields are out of
/// wall-clock range (e.g. sentinel `99999999`).
#[inline]
pub fn parse_accept_time_cs(raw: &[u8; 8]) -> Option<u32> {
    let d = |b: u8| -> Option<u32> {
        let v = b.wrapping_sub(b'0');
        if v <= 9 { Some(u32::from(v)) } else { None }
    };

    let hh = d(raw[0])? * 10 + d(raw[1])?;
    let mm = d(raw[2])? * 10 + d(raw[3])?;
    let ss = d(raw[4])? * 10 + d(raw[5])?;
    let uu = d(raw[6])? * 10 + d(raw[7])?;

    if hh >= 24 || mm >= 60 || ss >= 60 {
        return None;
    }

    Some(((hh * 3600 + mm * 60 + ss) * 100) + uu)
}

/// Strips leading `'0'` bytes from a non-empty ASCII decimal slice, keeping at least
/// one digit (so `"00000"` yields `"0"`).
#[inline]
pub fn trim_leading_zeros(digits: &[u8]) -> &[u8] {
    let last = digits.len() - 1;
    let mut i = 0;
    while i < last && digits[i] == b'0' {
        i += 1;
    }
    &digits[i..]
}
