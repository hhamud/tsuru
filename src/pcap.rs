use anyhow::{Result, bail};
use std::io::{ErrorKind, Read};

const PCAP_GLOBAL_HDR_LEN: usize = 24;
const PCAP_PKT_HDR_LEN: usize = 16;
const DEFAULT_BUF_CAP: usize = 2 * 1024 * 1024;
const MAX_PACKET_LEN: usize = 64 * 1024 * 1024;

const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_VLAN: u16 = 0x8100;
const ETH_TYPE_QINQ: u16 = 0x88A8;
const IP_PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPrecision {
    Microsecond,
    Nanosecond,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    RawIp,
    LinuxSll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapHeader {
    pub endianness: Endianness,
    pub precision: TimestampPrecision,
    pub snaplen: u32,
    pub link_type: LinkType,
}

impl PcapHeader {
    pub fn parse(bytes: &[u8; PCAP_GLOBAL_HDR_LEN]) -> Result<Self> {
        let (endianness, precision) = match &bytes[0..4] {
            [0xd4, 0xc3, 0xb2, 0xa1] => (Endianness::Little, TimestampPrecision::Microsecond),
            [0xa1, 0xb2, 0xc3, 0xd4] => (Endianness::Big, TimestampPrecision::Microsecond),
            [0x4d, 0x3c, 0xb2, 0xa1] => (Endianness::Little, TimestampPrecision::Nanosecond),
            [0xa1, 0xb2, 0x3c, 0x4d] => (Endianness::Big, TimestampPrecision::Nanosecond),
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                bail!("PCAPNG format is not supported; convert to classic PCAP first")
            }
            magic => bail!("invalid PCAP magic bytes: {:02x?}", magic),
        };

        let read_u32 = |slice: &[u8]| -> u32 {
            let arr: [u8; 4] = slice.try_into().unwrap();
            match endianness {
                Endianness::Little => u32::from_le_bytes(arr),
                Endianness::Big => u32::from_be_bytes(arr),
            }
        };

        let snaplen = read_u32(&bytes[16..20]);
        let link_raw = read_u32(&bytes[20..24]);
        let link_type = match link_raw {
            1 => LinkType::Ethernet,
            101 => LinkType::RawIp,
            113 => LinkType::LinuxSll,
            other => bail!("unsupported PCAP link-layer type: {other}"),
        };

        Ok(Self {
            endianness,
            precision,
            snaplen,
            link_type,
        })
    }

    #[inline]
    fn read_u32(&self, bytes: [u8; 4]) -> u32 {
        match self.endianness {
            Endianness::Little => u32::from_le_bytes(bytes),
            Endianness::Big => u32::from_be_bytes(bytes),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RawPacket<'a> {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub data: &'a [u8],
}

/// Streaming PCAP reader backed by a single reusable buffer.
///
/// Works on regular files, pipes, and stdin with zero `unsafe` code and constant
/// memory footprint regardless of capture size.
pub struct PcapReader<R> {
    reader: R,
    header: PcapHeader,
    buf: Vec<u8>,
    pos: usize,
    filled: usize,
    eof: bool,
}

impl<R: Read> PcapReader<R> {
    pub fn new(reader: R) -> Result<Self> {
        Self::with_capacity(reader, DEFAULT_BUF_CAP)
    }

    pub fn with_capacity(mut reader: R, capacity: usize) -> Result<Self> {
        let mut hdr_bytes = [0u8; PCAP_GLOBAL_HDR_LEN];
        read_exact_or_err(&mut reader, &mut hdr_bytes)?;
        let header = PcapHeader::parse(&hdr_bytes)?;
        let cap = capacity.max(64 * 1024);

        Ok(Self {
            reader,
            header,
            buf: vec![0u8; cap],
            pos: 0,
            filled: 0,
            eof: false,
        })
    }

    #[inline]
    pub fn header(&self) -> PcapHeader {
        self.header
    }

    /// Reads the next packet, returning a zero-copy slice into the internal buffer.
    #[inline]
    pub fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>> {
        if self.filled - self.pos < PCAP_PKT_HDR_LEN && !self.ensure_bytes(PCAP_PKT_HDR_LEN)? {
            return Ok(None);
        }

        let hdr = &self.buf[self.pos..self.pos + PCAP_PKT_HDR_LEN];
        let ts_sec = self.header.read_u32([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let ts_sub = self.header.read_u32([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let incl_len = self.header.read_u32([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;

        if incl_len > MAX_PACKET_LEN {
            bail!("corrupt PCAP packet length: {incl_len} bytes");
        }

        let record_len = PCAP_PKT_HDR_LEN + incl_len;
        if self.filled - self.pos < record_len && !self.ensure_bytes(record_len)? {
            // Truncated trailing packet at EOF
            return Ok(None);
        }

        let ts_usec = match self.header.precision {
            TimestampPrecision::Microsecond => ts_sub,
            TimestampPrecision::Nanosecond => ts_sub / 1_000,
        };

        let pkt_start = self.pos + PCAP_PKT_HDR_LEN;
        let pkt_end = pkt_start + incl_len;
        self.pos = pkt_end;

        Ok(Some(RawPacket {
            ts_sec,
            ts_usec,
            data: &self.buf[pkt_start..pkt_end],
        }))
    }

    #[cold]
    fn ensure_bytes(&mut self, needed: usize) -> Result<bool> {
        if self.eof {
            return Ok(self.filled - self.pos >= needed);
        }

        let remaining = self.filled - self.pos;
        if self.pos > 0 {
            if remaining > 0 {
                self.buf.copy_within(self.pos..self.filled, 0);
            }
            self.pos = 0;
            self.filled = remaining;
        }

        if needed > self.buf.len() {
            self.buf.resize(needed.next_power_of_two(), 0);
        }

        while self.filled < needed {
            match self.reader.read(&mut self.buf[self.filled..]) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(n) => self.filled += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(true)
    }
}

fn read_exact_or_err<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut read_total = 0;
    while read_total < buf.len() {
        match reader.read(&mut buf[read_total..]) {
            Ok(0) => bail!("unexpected EOF while reading PCAP global header"),
            Ok(n) => read_total += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Extracts `(dst_port, udp_payload)` from a non-fragmented IPv4/UDP frame.
///
/// Validates link-layer EtherType (with optional 802.1Q/QinQ VLAN tags), IPv4
/// version, header length, protocol (`UDP = 17`), fragmentation flags/offset,
/// IP total length, and UDP payload length.
#[inline]
pub fn extract_udp_payload(link_type: LinkType, frame: &[u8]) -> Option<(u16, &[u8])> {
    let ip_start = match link_type {
        LinkType::Ethernet => {
            if frame.len() < 14 {
                return None;
            }
            let mut offset = 12;
            let mut eth_type = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
            offset += 2;

            // Unwrap up to 2 VLAN tags (802.1Q / 802.1ad QinQ)
            for _ in 0..2 {
                if eth_type == ETH_TYPE_VLAN || eth_type == ETH_TYPE_QINQ {
                    if frame.len() < offset + 4 {
                        return None;
                    }
                    eth_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                    offset += 4;
                } else {
                    break;
                }
            }

            if eth_type != ETH_TYPE_IPV4 {
                return None;
            }
            offset
        }
        LinkType::LinuxSll => {
            if frame.len() < 16 {
                return None;
            }
            let eth_type = u16::from_be_bytes([frame[14], frame[15]]);
            if eth_type != ETH_TYPE_IPV4 {
                return None;
            }
            16
        }
        LinkType::RawIp => 0,
    };

    if frame.len() < ip_start + 20 {
        return None;
    }

    let ip = &frame[ip_start..];
    if (ip[0] >> 4) != 4 {
        return None;
    }

    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    if ihl < 20 {
        return None;
    }

    // Protocol must be UDP (17)
    if ip[9] != IP_PROTO_UDP {
        return None;
    }

    // Reject fragmented IPv4 packets (MF flag 0x2000 or non-zero fragment offset 0x1FFF)
    let frag_field = u16::from_be_bytes([ip[6], ip[7]]);
    if (frag_field & 0x3FFF) != 0 {
        return None;
    }

    let ip_total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ip_total_len < ihl + 8 || ip_total_len > ip.len() {
        return None;
    }

    let udp = &ip[ihl..ip_total_len];
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }

    Some((dst_port, &udp[8..udp_len]))
}
