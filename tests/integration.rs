use std::io::Cursor;
use tsuru::{Config, process_pcap};

fn make_b6034(
    isin: &[u8; 12],
    bids: [(u32, u32); 5],
    asks: [(u32, u32); 5],
    accept_time: &[u8; 8],
) -> Vec<u8> {
    let mut buf = vec![b'0'; 215];
    buf[0..5].copy_from_slice(b"B6034");
    buf[5..17].copy_from_slice(isin);

    for (i, (price, qty)) in bids.iter().enumerate() {
        let off = 29 + i * 12;
        buf[off..off + 5].copy_from_slice(format!("{price:05}").as_bytes());
        buf[off + 5..off + 12].copy_from_slice(format!("{qty:07}").as_bytes());
    }
    for (i, (price, qty)) in asks.iter().enumerate() {
        let off = 96 + i * 12;
        buf[off..off + 5].copy_from_slice(format!("{price:05}").as_bytes());
        buf[off + 5..off + 12].copy_from_slice(format!("{qty:07}").as_bytes());
    }

    buf[206..214].copy_from_slice(accept_time);
    buf[214] = 0xFF;
    buf
}

fn make_ipv4_udp(
    dst_port: u16,
    payload: &[u8],
    proto: u8,
    frag_field: u16,
    ip_options_len: usize,
    udp_len_override: Option<u16>,
) -> Vec<u8> {
    assert_eq!(ip_options_len % 4, 0);
    let ihl_bytes = 20 + ip_options_len;
    let udp_len = udp_len_override.unwrap_or((8 + payload.len()) as u16);
    let ip_total_len = (ihl_bytes + 8 + payload.len()) as u16;

    let mut pkt = Vec::with_capacity(ip_total_len as usize);
    pkt.push(0x40 | ((ihl_bytes / 4) as u8));
    pkt.push(0);
    pkt.extend_from_slice(&ip_total_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&frag_field.to_be_bytes());
    pkt.push(64);
    pkt.push(proto);
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&[192, 168, 1, 1]);
    pkt.extend_from_slice(&[224, 0, 1, 1]);
    pkt.resize(ihl_bytes, 0);

    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

fn wrap_eth(eth_type: u16, vlan_tags: &[(u16, u16)], l3: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + vlan_tags.len() * 4 + l3.len());
    frame.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x01, 0x01]);
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    for &(tpid, tci) in vlan_tags {
        frame.extend_from_slice(&tpid.to_be_bytes());
        frame.extend_from_slice(&tci.to_be_bytes());
    }
    frame.extend_from_slice(&eth_type.to_be_bytes());
    frame.extend_from_slice(l3);
    frame
}

fn build_pcap(
    magic: [u8; 4],
    big_endian: bool,
    link_type: u32,
    packets: &[(u32, u32, Vec<u8>)],
) -> Vec<u8> {
    let put_u16 = |out: &mut Vec<u8>, v: u16| {
        if big_endian {
            out.extend_from_slice(&v.to_be_bytes());
        } else {
            out.extend_from_slice(&v.to_le_bytes());
        }
    };
    let put_u32 = |out: &mut Vec<u8>, v: u32| {
        if big_endian {
            out.extend_from_slice(&v.to_be_bytes());
        } else {
            out.extend_from_slice(&v.to_le_bytes());
        }
    };

    let mut out = Vec::new();
    out.extend_from_slice(&magic);
    put_u16(&mut out, 2);
    put_u16(&mut out, 4);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 65535);
    put_u32(&mut out, link_type);

    for (sec, subsec, data) in packets {
        put_u32(&mut out, *sec);
        put_u32(&mut out, *subsec);
        put_u32(&mut out, data.len() as u32);
        put_u32(&mut out, data.len() as u32);
        out.extend_from_slice(data);
    }
    out
}

fn run_pcap(pcap: &[u8], config: Config) -> String {
    let mut out = Vec::new();
    process_pcap(Cursor::new(pcap), &mut out, config).expect("process_pcap failed");
    String::from_utf8(out).expect("output is valid UTF-8")
}

#[test]
fn parses_valid_b6034_and_strips_leading_zeros() {
    let payload = make_b6034(
        b"KR4101SC0009",
        [(0, 0), (100, 1), (200, 22), (300, 333), (400, 4444)],
        [(500, 5), (600, 60), (700, 700), (800, 8000), (900, 9999999)],
        b"09010203",
    );
    let frame = wrap_eth(
        0x0800,
        &[],
        &make_ipv4_udp(15515, &payload, 17, 0x4000, 0, None),
    );
    // 0 UTC = 09:00:00 KST
    let pcap = build_pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 1, &[(0, 42, frame)]);

    let output = run_pcap(&pcap, Config::default());
    assert_eq!(
        output,
        "09:00:00.000042 09:01:02:03 KR4101SC0009 \
         4444@400 333@300 22@200 1@100 0@0 \
         5@500 60@600 700@700 8000@800 9999999@900\n"
    );
}

#[test]
fn handles_five_digit_prices_above_u16_max() {
    let payload = make_b6034(
        b"KR4101SC0009",
        [
            (65536, 10),
            (70000, 20),
            (80000, 30),
            (90000, 40),
            (99999, 50),
        ],
        [(65536, 1), (65537, 2), (75000, 3), (88888, 4), (99999, 5)],
        b"09000001",
    );
    let frame = wrap_eth(0x0800, &[], &make_ipv4_udp(15516, &payload, 17, 0, 0, None));
    let pcap = build_pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 1, &[(10, 500, frame)]);

    let output = run_pcap(&pcap, Config::default());
    assert!(output.contains("50@99999 40@90000 30@80000 20@70000 10@65536"));
    assert!(output.contains("1@65536 2@65537 3@75000 4@88888 5@99999"));
}

#[test]
fn supports_vlan_qinq_and_ip_options() {
    let p1 = make_b6034(b"ISIN_VLAN_01", [(1, 1); 5], [(2, 2); 5], b"09000001");
    let p2 = make_b6034(b"ISIN_QINQ_02", [(3, 3); 5], [(4, 4); 5], b"09000002");

    let f1 = wrap_eth(
        0x0800,
        &[(0x8100, 100)],
        &make_ipv4_udp(15515, &p1, 17, 0, 0, None),
    );
    let f2 = wrap_eth(
        0x0800,
        &[(0x88A8, 10), (0x8100, 20)],
        &make_ipv4_udp(15516, &p2, 17, 0, 8, None),
    );

    let pcap = build_pcap(
        [0xd4, 0xc3, 0xb2, 0xa1],
        false,
        1,
        &[(1, 0, f1), (2, 0, f2)],
    );
    let output = run_pcap(&pcap, Config::default());
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("ISIN_VLAN_01"));
    assert!(lines[1].contains("ISIN_QINQ_02"));
}

#[test]
fn filters_non_udp_fragmented_wrong_ethertype_and_malformed_lengths() {
    let payload = make_b6034(b"KR4101SC0009", [(100, 1); 5], [(101, 1); 5], b"09000000");

    // 1. TCP (proto = 6) masquerading on dst port 15515
    let tcp_fake = wrap_eth(0x0800, &[], &make_ipv4_udp(15515, &payload, 6, 0, 0, None));
    // 2. Fragmented IPv4 (MF bit set = 0x2000)
    let frag_mf = wrap_eth(
        0x0800,
        &[],
        &make_ipv4_udp(15515, &payload, 17, 0x2000, 0, None),
    );
    // 3. Fragmented IPv4 (non-zero fragment offset = 1)
    let frag_off = wrap_eth(
        0x0800,
        &[],
        &make_ipv4_udp(15515, &payload, 17, 0x0001, 0, None),
    );
    // 4. Non-IPv4 EtherType (IPv6 = 0x86DD)
    let wrong_eth = wrap_eth(0x86DD, &[], &make_ipv4_udp(15515, &payload, 17, 0, 0, None));
    // 5. Wrong destination port
    let wrong_port = wrap_eth(0x0800, &[], &make_ipv4_udp(15517, &payload, 17, 0, 0, None));
    // 6. Truncated UDP length field (smaller than B6034)
    let short_udp = wrap_eth(
        0x0800,
        &[],
        &make_ipv4_udp(15515, &payload, 17, 0, 0, Some(100)),
    );
    // 7. Valid packet with trailing Ethernet FCS/padding bytes
    let mut valid_padded = wrap_eth(
        0x0800,
        &[],
        &make_ipv4_udp(15515, &payload, 17, 0x4000, 0, None),
    );
    valid_padded.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let pcap = build_pcap(
        [0xd4, 0xc3, 0xb2, 0xa1],
        false,
        1,
        &[
            (1, 0, tcp_fake),
            (2, 0, frag_mf),
            (3, 0, frag_off),
            (4, 0, wrong_eth),
            (5, 0, wrong_port),
            (6, 0, short_udp),
            (7, 0, valid_padded),
        ],
    );

    let output = run_pcap(&pcap, Config::default());
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("09:00:07.000000 "));
}

#[test]
fn supports_big_endian_nanosecond_and_raw_sll_link_types() {
    let payload = make_b6034(b"KR4101SC0009", [(100, 1); 5], [(101, 1); 5], b"09000000");
    let ip_udp = make_ipv4_udp(15515, &payload, 17, 0, 0, None);

    // Big-endian microsecond Ethernet
    let eth_frame = wrap_eth(0x0800, &[], &ip_udp);
    let be_pcap = build_pcap(
        [0xa1, 0xb2, 0xc3, 0xd4],
        true,
        1,
        &[(5, 123_456, eth_frame.clone())],
    );
    assert!(run_pcap(&be_pcap, Config::default()).starts_with("09:00:05.123456 "));

    // Little-endian nanosecond PCAP (987_654_321 ns -> 987_654 us)
    let ns_pcap = build_pcap(
        [0x4d, 0x3c, 0xb2, 0xa1],
        false,
        1,
        &[(5, 987_654_321, eth_frame)],
    );
    assert!(run_pcap(&ns_pcap, Config::default()).starts_with("09:00:05.987654 "));

    // Raw IP (link type 101)
    let raw_pcap = build_pcap(
        [0xd4, 0xc3, 0xb2, 0xa1],
        false,
        101,
        &[(5, 1, ip_udp.clone())],
    );
    assert!(run_pcap(&raw_pcap, Config::default()).starts_with("09:00:05.000001 "));

    // Linux SLL (link type 113)
    let mut sll = vec![0u8; 16];
    sll[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
    sll.extend_from_slice(&ip_udp);
    let sll_pcap = build_pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 113, &[(5, 2, sll)]);
    assert!(run_pcap(&sll_pcap, Config::default()).starts_with("09:00:05.000002 "));
}

#[test]
fn rejects_pcapng_bad_magic_and_truncated_global_header() {
    let mut out = Vec::new();
    // PCAPNG magic
    let mut pcapng = vec![0u8; 24];
    pcapng[0..4].copy_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a]);
    let err = process_pcap(Cursor::new(&pcapng), &mut out, Config::default()).unwrap_err();
    assert!(err.to_string().contains("PCAPNG"));

    // Garbage magic
    let garbage = [0xFFu8; 24];
    assert!(process_pcap(Cursor::new(&garbage), &mut out, Config::default()).is_err());

    // Truncated header
    let short = [0u8; 10];
    assert!(process_pcap(Cursor::new(&short), &mut out, Config::default()).is_err());
}

#[test]
fn handles_truncated_trailing_packet_gracefully() {
    let p1 = make_b6034(b"ISIN_GOOD_01", [(1, 1); 5], [(2, 2); 5], b"09000001");
    let f1 = wrap_eth(0x0800, &[], &make_ipv4_udp(15515, &p1, 17, 0, 0, None));
    let mut pcap = build_pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 1, &[(1, 0, f1)]);
    // Append a second packet header claiming 300 bytes, followed by only 10 bytes
    pcap.extend_from_slice(&2u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&300u32.to_le_bytes());
    pcap.extend_from_slice(&300u32.to_le_bytes());
    pcap.extend_from_slice(&[0u8; 10]);

    let output = run_pcap(&pcap, Config::default());
    assert_eq!(output.lines().count(), 1);
    assert!(output.contains("ISIN_GOOD_01"));
}

#[test]
fn reorder_sorts_by_accept_time_and_preserves_fifo_on_ties() {
    let mk = |sec: u32, usec: u32, isin: &[u8; 12], accept: &[u8; 8]| {
        let p = make_b6034(isin, [(100, 1); 5], [(101, 1); 5], accept);
        let f = wrap_eth(0x0800, &[], &make_ipv4_udp(15515, &p, 17, 0, 0, None));
        (sec, usec, f)
    };

    let packets = vec![
        mk(1, 100, b"TIE_FIRST_01", b"09000100"),
        mk(1, 200, b"TIE_SECND_02", b"09000100"),
        mk(1, 300, b"EARLY_LATE03", b"09000050"), // arrived later, earlier accept_time
        mk(1, 400, b"TIE_THIRD_03", b"09000100"),
        mk(2, 0, b"EARLIEST__04", b"09000010"), // arrived even later, earliest accept_time
        mk(5, 500, b"AFTER_3SEC05", b"09000500"), // triggers flush of >3s old buckets
        mk(6, 0, b"LATE_IN_W_06", b"09000490"),
    ];

    let pcap = build_pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 1, &packets);
    let output = run_pcap(
        &pcap,
        Config {
            reorder: true,
            ..Config::default()
        },
    );

    let isins: Vec<&str> = output
        .lines()
        .map(|l| l.split_whitespace().nth(2).unwrap())
        .collect();
    assert_eq!(
        isins,
        vec![
            "EARLIEST__04",
            "EARLY_LATE03",
            "TIE_FIRST_01",
            "TIE_SECND_02",
            "TIE_THIRD_03",
            "LATE_IN_W_06",
            "AFTER_3SEC05",
        ]
    );
}

#[test]
fn reorder_handles_long_quiet_gap_and_sentinel_accept_time() {
    let mk = |sec: u32, isin: &[u8; 12], accept: &[u8; 8]| {
        let p = make_b6034(isin, [(100, 1); 5], [(101, 1); 5], accept);
        let f = wrap_eth(0x0800, &[], &make_ipv4_udp(15515, &p, 17, 0, 0, None));
        (sec, 0, f)
    };

    let packets = vec![
        mk(1, b"BEFORE_GAP01", b"09000100"),
        mk(2, b"STALE_SENT02", b"99999999"), // flushes once t=600s arrives (>3s old)
        mk(600, b"INWIN_SENT03", b"99999999"), // stays in fallback and sorts after 09:10:00:00
        mk(600, b"AFTER_GAP_04", b"09100000"), // 10-minute jump resets wheel cleanly
        mk(601, b"AFTER_GAP_05", b"09095950"), // out-of-order after gap
    ];

    let pcap = build_pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 1, &packets);
    let output = run_pcap(
        &pcap,
        Config {
            reorder: true,
            ..Config::default()
        },
    );

    let isins: Vec<&str> = output
        .lines()
        .map(|l| l.split_whitespace().nth(2).unwrap())
        .collect();
    assert_eq!(
        isins,
        vec![
            "BEFORE_GAP01",
            "STALE_SENT02",
            "AFTER_GAP_05",
            "AFTER_GAP_04",
            "INWIN_SENT03",
        ]
    );
}

#[test]
fn supports_custom_utc_offsets_including_negative() {
    let payload = make_b6034(b"KR4101SC0009", [(1, 1); 5], [(2, 2); 5], b"09000000");
    let frame = wrap_eth(0x0800, &[], &make_ipv4_udp(15515, &payload, 17, 0, 0, None));
    let pcap = build_pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 1, &[(3600, 0, frame)]);

    // UTC (offset 0) -> 01:00:00
    let utc = run_pcap(
        &pcap,
        Config {
            utc_offset_secs: 0,
            ..Config::default()
        },
    );
    assert!(utc.starts_with("01:00:00.000000 "));

    // UTC-5 (-18000s) -> 20:00:00 (previous day wrap)
    let est = run_pcap(
        &pcap,
        Config {
            utc_offset_secs: -18_000,
            ..Config::default()
        },
    );
    assert!(est.starts_with("20:00:00.000000 "));
}
