#![cfg(not(any()))]
use super::*;

fn build_query(domain: &str, qtype: u16, qclass: u16, id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    // Header: ID, flags=RD set (0x0100), QD=1
    write_u16(&mut q, id);
    write_u16(&mut q, 0x0100);
    write_u16(&mut q, 1);
    write_u16(&mut q, 0);
    write_u16(&mut q, 0);
    write_u16(&mut q, 0);
    // QNAME
    for label in domain.split('.') {
        let b = label.as_bytes();
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0);
    // QTYPE + QCLASS
    write_u16(&mut q, qtype);
    write_u16(&mut q, qclass);
    q
}

#[test]
fn parse_simple_qname() {
    let req = build_query("www.example", 1, 1, 0xBEEF);
    let hdr = parse_header(&req).unwrap();
    assert_eq!(hdr.id, 0xBEEF);
    let (name, off, qtype, qclass) = parse_question(&req).unwrap();
    assert_eq!(name, "www.example");
    assert!(off <= req.len());
    assert_eq!(qtype, 1);
    assert_eq!(qclass, 1);
}

#[test]
fn build_a_response() {
    let req = build_query("a.b", 1, 1, 0x0001);
    let hdr = parse_header(&req).unwrap();
    let (_name, qend, _t, _c) = parse_question(&req).unwrap();
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    let cfg = ServerCfg {
        zone_labels: None,
        mailbox_zone_labels: None,
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 300,
        pretty_stdout: false,
        accept_ascii_only: false,
    };
    let resp = build_response(&req, hdr, qend, ip, true, false, &cfg);
    assert!(resp.len() > req.len());
    // Header checks
    assert_eq!(read_u16(&resp[0..2]), 0x0001);
    let flags = read_u16(&resp[2..4]);
    assert_eq!(flags & 0x8000, 0x8000); // QR set
    assert_eq!(read_u16(&resp[4..6]), 1); // QDCOUNT
    assert_eq!(read_u16(&resp[6..8]), 1); // ANCOUNT
    // RDATA should end with ip octets
    assert_eq!(&resp[resp.len() - 4..], &ip.octets());
}

#[test]
fn non_a_in_zone_attaches_soa_with_neg_ttl() {
    let zone = "x.foo.bar";
    let qname = "foo.x.example"; // question name doesn't matter as long as in_zone=true
    let req = build_query(qname, 16, 1, 0x002a); // QTYPE=TXT(16)
    let hdr = parse_header(&req).unwrap();
    let (_name, qend, _t, _c) = parse_question(&req).unwrap();
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    let zone_labels = validate_zone_and_labels(zone).unwrap();
    let cfg = ServerCfg {
        zone_labels: Some(zone_labels.clone()),
        mailbox_zone_labels: None,
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 123,
        pretty_stdout: false,
        accept_ascii_only: false,
    };
    let resp = build_response(&req, hdr, qend, ip, false, true, &cfg);
    // Header basics
    assert_eq!(read_u16(&resp[4..6]), 1); // QD=1
    assert_eq!(read_u16(&resp[6..8]), 0); // AN=0
    assert_eq!(read_u16(&resp[8..10]), 1); // NS=1
    // Find TTL of SOA in authority RR
    let qlen = qend - DNS_HEADER_LEN;
    let mut off = DNS_HEADER_LEN + qlen;
    // NAME = zone apex
    for lab in &zone_labels {
        off += 1 + lab.len();
    }
    off += 1; // root
    // TYPE(2) + CLASS(2)
    assert_eq!(read_u16(&resp[off..off + 2]), 6); // SOA
    assert_eq!(read_u16(&resp[off + 2..off + 4]), 1); // IN
    let ttl = u32::from_be_bytes([resp[off + 4], resp[off + 5], resp[off + 6], resp[off + 7]]);
    assert_eq!(ttl, 123);
    // RCODE=0
    let flags = read_u16(&resp[2..4]);
    assert_eq!(flags & 0x000F, 0);
}

#[test]
fn non_a_outside_zone_returns_notimp() {
    let req = build_query("foo.other", 16, 1, 0x0002);
    let hdr = parse_header(&req).unwrap();
    let (_name, qend, _t, _c) = parse_question(&req).unwrap();
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    let cfg = ServerCfg {
        zone_labels: None,
        mailbox_zone_labels: None,
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 300,
        pretty_stdout: false,
        accept_ascii_only: false,
    };
    let resp = build_response(&req, hdr, qend, ip, false, false, &cfg);
    let flags = read_u16(&resp[2..4]);
    assert_eq!(flags & 0x000F, 4); // NotImp
    assert_eq!(read_u16(&resp[8..10]), 0); // NS=0
}

#[test]
fn aaaa_outside_zone_returns_notimp() {
    // AAAA query outside any configured zone should return NOTIMP like other non-A types
    let req = build_query("node.other", 28, 1, 0x00AB); // QTYPE=AAAA(28)
    let hdr = parse_header(&req).unwrap();
    let (_name, qend, _t, _c) = parse_question(&req).unwrap();
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    let cfg = ServerCfg {
        zone_labels: None,
        mailbox_zone_labels: None,
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 300,
        pretty_stdout: false,
        accept_ascii_only: false,
    };
    let resp = build_response(&req, hdr, qend, ip, false, false, &cfg);
    let flags = read_u16(&resp[2..4]);
    assert_eq!(flags & 0x000F, 4); // NotImp
    assert_eq!(read_u16(&resp[6..8]), 0); // AN=0
    assert_eq!(read_u16(&resp[8..10]), 0); // NS=0
}

#[test]
fn aaaa_in_zone_attaches_soa_with_neg_ttl() {
    let zone = "x.foo.bar";
    let qname = "node.x.example";
    let req = build_query(qname, 28, 1, 0x00AA); // AAAA
    let hdr = parse_header(&req).unwrap();
    let (_name, qend, _t, _c) = parse_question(&req).unwrap();
    let ip = Ipv4Addr::new(192, 0, 2, 55);
    let zone_labels = validate_zone_and_labels(zone).unwrap();
    let cfg = ServerCfg {
        zone_labels: Some(zone_labels.clone()),
        mailbox_zone_labels: None,
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 77,
        pretty_stdout: false,
        accept_ascii_only: false,
    };
    let resp = build_response(&req, hdr, qend, ip, false, true, &cfg);
    assert_eq!(read_u16(&resp[6..8]), 0); // AN=0
    assert_eq!(read_u16(&resp[8..10]), 1); // NS=1
    // Jump to SOA TTL
    let qlen = qend - DNS_HEADER_LEN;
    let mut off = DNS_HEADER_LEN + qlen;
    for lab in &zone_labels {
        off += 1 + lab.len();
    }
    off += 1; // root
    assert_eq!(read_u16(&resp[off..off + 2]), 6);
    assert_eq!(read_u16(&resp[off + 2..off + 4]), 1);
    let ttl = u32::from_be_bytes([resp[off + 4], resp[off + 5], resp[off + 6], resp[off + 7]]);
    assert_eq!(ttl, 77);
    let flags = read_u16(&resp[2..4]);
    assert_eq!(flags & 0x000F, 0); // RCODE=NOERROR
}

fn build_query_with_flags(domain: &str, qtype: u16, qclass: u16, id: u16, flags: u16) -> Vec<u8> {
    let mut q = Vec::new();
    write_u16(&mut q, id);
    write_u16(&mut q, flags);
    write_u16(&mut q, 1);
    write_u16(&mut q, 0);
    write_u16(&mut q, 0);
    write_u16(&mut q, 0);
    for label in domain.split('.') {
        let b = label.as_bytes();
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0);
    write_u16(&mut q, qtype);
    write_u16(&mut q, qclass);
    q
}

#[test]
fn rd_flag_is_copied_to_response() {
    let req0 = build_query_with_flags("a.b", 1, 1, 1, 0x0000); // RD=0
    let req1 = build_query_with_flags("a.b", 1, 1, 1, 0x0100); // RD=1
    let hdr0 = parse_header(&req0).unwrap();
    let hdr1 = parse_header(&req1).unwrap();
    let (_n0, q0, _t0, _c0) = parse_question(&req0).unwrap();
    let (_n1, q1, _t1, _c1) = parse_question(&req1).unwrap();
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let cfg = ServerCfg {
        zone_labels: None,
        mailbox_zone_labels: None,
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 300,
        pretty_stdout: false,
        accept_ascii_only: false,
    };
    let r0 = build_response(&req0, hdr0, q0, ip, true, false, &cfg);
    let r1 = build_response(&req1, hdr1, q1, ip, true, false, &cfg);
    assert_eq!(read_u16(&r0[2..4]) & 0x0100, 0x0000);
    assert_eq!(read_u16(&r1[2..4]) & 0x0100, 0x0100);
}

#[test]
fn dnsm_parsing_errors_are_logged() {
    let zone = "x.foo.bar";
    let tmp = std::env::temp_dir().join(format!("dnsm_test_{}", fastrand::u64(..)));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut log = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tmp.join("log.txt"))
            .unwrap(),
    );
    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let cfg = ServerCfg {
        zone_labels: Some(validate_zone_and_labels(zone).unwrap()),
        mailbox_zone_labels: None,
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 300,
        pretty_stdout: false,
        accept_ascii_only: false,
    };
    // parse_error due to invalid character '@' in label
    let peer = "127.0.0.1:5555".parse().unwrap();
    try_handle_dnsm(
        "inv@lid.x.foo.bar",
        &cfg,
        &mut sessions,
        1,
        &mut log,
        peer,
        None,
    );
    // short_bytes due to too-short decoded bytes ("a" decodes to < 8 bytes)
    try_handle_dnsm(
        "a.x.foo.bar",
        &cfg,
        &mut sessions,
        2,
        &mut log,
        peer,
        None,
    );
    drop(log); // ensure file is closed
    let text = std::fs::read_to_string(tmp.join("log.txt")).unwrap();
    assert!(text.contains("\"event\":\"parse_error\""));
    assert!(text.contains("\"event\":\"decode_error\""));
    assert!(text.contains("\"reason\":\"short_bytes\""));
    let _ = std::fs::remove_dir_all(&tmp);
}

// --- helpers for mailbox tests ---
fn b32_encode(data: &[u8]) -> String {
    const ALPH: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = Vec::with_capacity((data.len() * 8).div_ceil(5));
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | (b as u64);
        acc_bits += 8;
        while acc_bits >= 5 {
            let shift = acc_bits - 5;
            let idx = ((acc >> shift) & 0x1F) as usize;
            out.push(ALPH[idx]);
            acc &= (1u64 << shift) - 1;
            acc_bits -= 5;
        }
    }
    if acc_bits > 0 {
        let idx = ((acc << (5 - acc_bits)) & 0x1F) as usize;
        out.push(ALPH[idx]);
    }
    String::from_utf8(out).unwrap()
}

fn build_header_u64(remaining: u16, session45: u64, version: u8, is_first: bool) -> u64 {
    let bytes = ChunkHeader::new(remaining, session45, version, is_first).to_bytes();
    u64::from_be_bytes(bytes)
}

fn cfg_base(zone: &str) -> ServerCfg {
    ServerCfg {
        zone_labels: Some(validate_zone_and_labels(zone).unwrap()),
        mailbox_zone_labels: None,
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 300,
        pretty_stdout: false,
        accept_ascii_only: false,
    }
}

fn init_tmp_db(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).expect("open tmp db");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            mailbox TEXT,
            data BLOB NOT NULL,
            received_at INTEGER NOT NULL,
            message_id BLOB
        );
        CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages(mailbox);
        CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
        CREATE UNIQUE INDEX IF NOT EXISTS uniq_messages_mailbox_msgid
            ON messages(mailbox, message_id)
            WHERE message_id IS NOT NULL;",
    )
    .expect("init schema");
    conn
}

#[test]
fn mailbox_single_chunk_no_session_persists_to_db() {
    let zone = "x.foo.bar";
    let tmp = std::env::temp_dir().join(format!("dnsm_test_db_{}", fastrand::u64(..)));
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("msgs.sqlite");
    let db = init_tmp_db(&db_path);
    let mut log = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tmp.join("log.txt"))
            .unwrap(),
    );
    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let cfg = cfg_base(zone);

    let remaining: u16 = 0;
    let session: u64 = 0; // ignored when no-session flag is set
    let version: u8 = 0;
    let is_first = true;
    let header = build_header_u64(remaining, session, version, is_first).to_be_bytes();
    let opts: u8 = OPT_MAILBOX | OPT_NO_SESSION; // mailbox present + no-session
    let mailbox: u64 = 0x42;
    let data = b"mbxdata";
    // LZMA-compress the input to match client behavior
    let comp = {
        use lzma_rust2::{LzmaOptions, LzmaWriter};
        use std::io::Write;
        let mut w = LzmaWriter::new_use_header(
            Vec::new(),
            &LzmaOptions::default(),
            Some(data.len() as u64),
        )
        .unwrap();
        w.write_all(&data[..]).unwrap();
        w.finish().unwrap()
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(&header);
    payload.push(opts);
    payload.extend_from_slice(&mailbox.to_be_bytes());
    payload.extend_from_slice(&comp);

    let enc = b32_encode(&payload);
    let domain = format!("{}.{}", enc, zone);
    let now = 1_234u128;
    let peer = "127.0.0.1:53000".parse().unwrap();

    try_handle_dnsm(&domain, &cfg, &mut sessions, now, &mut log, peer, Some(&db));

    // Expect DB row for derived session
    let sid = session_from_payload(data) as i64;
    let mut stmt = db
        .prepare("SELECT data FROM messages WHERE session_id=?1 AND mailbox=?2")
        .unwrap();
    let mut rows = stmt
        .query_map(params![sid, format!("{:016x}", mailbox)], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })
        .unwrap();
    let got = rows.next().expect("row").unwrap();
    assert_eq!(&got, data);

    // Check log contains sid_derived:1
    let log_text = std::fs::read_to_string(tmp.join("log.txt")).unwrap();
    assert!(log_text.contains("\"event\":\"chunk\""));
    assert!(log_text.contains("\"sid_derived\":1"));

    // cleanup
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn mailbox_single_chunk_duplicate_is_ignored_by_unique_index() {
    let zone = "x.foo.bar";
    let tmp = std::env::temp_dir().join(format!("dnsm_test_db_dup_{}", fastrand::u64(..)));
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("msgs.sqlite");
    let db = init_tmp_db(&db_path);
    let mut log = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tmp.join("log.txt"))
            .unwrap(),
    );
    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let cfg = cfg_base(zone);

    // Build a single-chunk, no-session payload with mailbox
    let remaining: u16 = 0;
    let session: u64 = 0; // ignored when no-session flag is set
    let version: u8 = 0;
    let is_first = true;
    let header = build_header_u64(remaining, session, version, is_first).to_be_bytes();
    let opts: u8 = OPT_MAILBOX | OPT_NO_SESSION; // mailbox present + no-session
    let mailbox: u64 = 0x42;
    let data = b"dupdata";
    let comp = {
        use lzma_rust2::{LzmaOptions, LzmaWriter};
        use std::io::Write;
        let mut w = LzmaWriter::new_use_header(
            Vec::new(),
            &LzmaOptions::default(),
            Some(data.len() as u64),
        )
        .unwrap();
        w.write_all(&data[..]).unwrap();
        w.finish().unwrap()
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(&header);
    payload.push(opts);
    payload.extend_from_slice(&mailbox.to_be_bytes());
    payload.extend_from_slice(&comp);

    let enc = b32_encode(&payload);
    let domain = format!("{}.{}", enc, zone);
    let peer = "127.0.0.1:53001".parse().unwrap();

    // First time: inserts
    try_handle_dnsm(&domain, &cfg, &mut sessions, 100, &mut log, peer, Some(&db));
    // Second time with same domain: should be ignored by UNIQUE index (OR IGNORE)
    try_handle_dnsm(&domain, &cfg, &mut sessions, 101, &mut log, peer, Some(&db));

    let mut stmt = db
        .prepare("SELECT COUNT(1) FROM messages WHERE mailbox=?1 AND data=?2")
        .unwrap();
    let cnt: i64 = stmt
        .query_row(params![format!("{:016x}", mailbox), &data[..]], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(cnt, 1);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
// Compression is mandatory across clients; multi-chunk path stays the same.
fn mailbox_multi_chunk_persists_assembled_to_db() {
    let zone = "x.foo.bar";
    let tmp = std::env::temp_dir().join(format!("dnsm_test_db_{}", fastrand::u64(..)));
    std::fs::create_dir_all(&tmp).unwrap();
    let db = init_tmp_db(&tmp.join("msgs.sqlite"));
    let mut log = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tmp.join("log.txt"))
            .unwrap(),
    );
    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let cfg = cfg_base(zone);

    let version: u8 = 0;
    let sid: u64 = 0x1A2B3;
    let mailbox: u64 = 100;

    // LZMA-compress full message, then split compressed bytes across 2 chunks
    let data0 = b"hello ";
    let data1 = b"world";
    let mut original = Vec::new();
    original.extend_from_slice(data0);
    original.extend_from_slice(data1);
    let compressed = {
        use lzma_rust2::{LzmaOptions, LzmaWriter};
        use std::io::Write;
        let mut w = LzmaWriter::new_use_header(
            Vec::new(),
            &LzmaOptions::default(),
            Some(original.len() as u64),
        )
        .unwrap();
        w.write_all(&original[..]).unwrap();
        w.finish().unwrap()
    };
    let split = usize::max(1, compressed.len() / 2);
    let first_part = &compressed[..split];
    let second_part = &compressed[split..];

    // chunk 0 (first): remaining=1, opts with mailbox
    let header0 = build_header_u64(1, sid, version, true).to_be_bytes();
    let mut payload0 = Vec::new();
    payload0.extend_from_slice(&header0);
    payload0.push(OPT_MAILBOX); // mailbox present
    payload0.extend_from_slice(&mailbox.to_be_bytes());
    payload0.extend_from_slice(first_part);
    let enc0 = b32_encode(&payload0);
    let domain0 = format!("{}.{}", enc0, zone);

    // chunk 1 (last): remaining=0, no opts
    let header1 = build_header_u64(0, sid, version, false).to_be_bytes();
    let mut payload1 = Vec::new();
    payload1.extend_from_slice(&header1);
    payload1.extend_from_slice(second_part);
    let enc1 = b32_encode(&payload1);
    let domain1 = format!("{}.{}", enc1, zone);

    let now = 9_999u128;
    let peer = "127.0.0.1:53001".parse().unwrap();
    try_handle_dnsm(
        &domain0,
        &cfg,
        &mut sessions,
        now,
        &mut log,
        peer,
        Some(&db),
    );
    try_handle_dnsm(
        &domain1,
        &cfg,
        &mut sessions,
        now + 1,
        &mut log,
        peer,
        Some(&db),
    );

    // Expect assembled data persisted in DB
    let mut stmt = db
        .prepare(
            "SELECT data FROM messages WHERE session_id=?1 AND mailbox=?2 ORDER BY id DESC LIMIT 1",
        )
        .unwrap();
    let mut rows = stmt
        .query_map(params![sid as i64, format!("{:016x}", mailbox)], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })
        .unwrap();
    let bytes = rows.next().expect("row").unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(data0);
    expected.extend_from_slice(data1);
    assert_eq!(bytes, expected);

    // First chunk should log sid_derived:0
    let log_text = std::fs::read_to_string(tmp.join("log.txt")).unwrap();
    assert!(log_text.contains("\"event\":\"chunk\""));
    assert!(log_text.contains("\"sid_derived\":0"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn ascii_only_rejects_single_chunk_no_session_with_non_ascii() {
    let zone = "x.foo.bar";
    let tmp = std::env::temp_dir().join(format!("dnsm_test_{}", fastrand::u64(..)));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut log = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tmp.join("log.txt"))
            .unwrap(),
    );
    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let mut cfg = cfg_base(zone);
    cfg.accept_ascii_only = true;

    // First+last chunk, no-session, with non-ASCII byte in decoded payload
    let remaining: u16 = 0;
    let session: u64 = 0;
    let version: u8 = 0;
    let is_first = true;
    let header = build_header_u64(remaining, session, version, is_first).to_be_bytes();
    let opts: u8 = OPT_NO_SESSION; // no-session only
    let data = b"abc\xFFdef"; // contains non-ASCII
    let comp = {
        use lzma_rust2::{LzmaOptions, LzmaWriter};
        use std::io::Write;
        let mut w = LzmaWriter::new_use_header(
            Vec::new(),
            &LzmaOptions::default(),
            Some(data.len() as u64),
        )
        .unwrap();
        w.write_all(&data[..]).unwrap();
        w.finish().unwrap()
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(&header);
    payload.push(opts);
    payload.extend_from_slice(&comp);

    let enc = b32_encode(&payload);
    let domain = format!("{}.{}", enc, zone);
    let now = 123u128;
    let peer = "127.0.0.1:53010".parse().unwrap();
    let db = init_tmp_db(&tmp.join("msgs.sqlite"));
    try_handle_dnsm(&domain, &cfg, &mut sessions, now, &mut log, peer, Some(&db));

    // No row inserted
    let sid = session_from_payload(data) as i64;
    let count: i64 = db
        .query_row(
            "SELECT COUNT(1) FROM messages WHERE session_id=?1",
            params![sid],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);

    // Log should contain a reject event
    drop(log);
    let text = std::fs::read_to_string(tmp.join("log.txt")).unwrap();
    assert!(text.contains("\"event\":\"reject\""));
    assert!(text.contains("\"reason\":\"non_ascii\""));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn ascii_only_rejects_multi_chunk_with_non_ascii() {
    let zone = "x.foo.bar";
    let tmp = std::env::temp_dir().join(format!("dnsm_test_{}", fastrand::u64(..)));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut log = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tmp.join("log.txt"))
            .unwrap(),
    );
    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let mut cfg = cfg_base(zone);
    cfg.accept_ascii_only = true;

    // Prepare decoded message with a non-ASCII byte and compress it
    let sid: u64 = 0xABCDEF;
    let mailbox: u64 = 7;
    let decoded = b"hello\x80world"; // non-ASCII in payload
    let compressed = {
        use lzma_rust2::{LzmaOptions, LzmaWriter};
        use std::io::Write;
        let mut w = LzmaWriter::new_use_header(
            Vec::new(),
            &LzmaOptions::default(),
            Some(decoded.len() as u64),
        )
        .unwrap();
        w.write_all(&decoded[..]).unwrap();
        w.finish().unwrap()
    };
    let split = usize::max(1, compressed.len() / 2);
    let (first_part, second_part) = compressed.split_at(split);

    // First chunk with mailbox
    let header0 = build_header_u64(1, sid, 0, true).to_be_bytes();
    let mut payload0 = Vec::new();
    payload0.extend_from_slice(&header0);
    payload0.push(OPT_MAILBOX); // mailbox present
    payload0.extend_from_slice(&mailbox.to_be_bytes());
    payload0.extend_from_slice(first_part);
    let enc0 = b32_encode(&payload0);
    let domain0 = format!("{}.{}", enc0, zone);

    // Second (last) chunk
    let header1 = build_header_u64(0, sid, 0, false).to_be_bytes();
    let mut payload1 = Vec::new();
    payload1.extend_from_slice(&header1);
    payload1.extend_from_slice(second_part);
    let enc1 = b32_encode(&payload1);
    let domain1 = format!("{}.{}", enc1, zone);

    let now = 9_000u128;
    let peer = "127.0.0.1:53011".parse().unwrap();
    let db = init_tmp_db(&tmp.join("msgs.sqlite"));
    try_handle_dnsm(
        &domain0,
        &cfg,
        &mut sessions,
        now,
        &mut log,
        peer,
        Some(&db),
    );
    try_handle_dnsm(
        &domain1,
        &cfg,
        &mut sessions,
        now + 1,
        &mut log,
        peer,
        Some(&db),
    );

    // No row should be inserted
    let count: i64 = db
        .query_row(
            "SELECT COUNT(1) FROM messages WHERE session_id=?1",
            params![sid as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);

    drop(log);
    let text = std::fs::read_to_string(tmp.join("log.txt")).unwrap();
    assert!(text.contains("\"event\":\"reject\""));
    assert!(text.contains("\"reason\":\"non_ascii\""));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn mailbox_txt_negative_with_soa_when_no_messages() {
    let zone = "x.foo.bar";
    let mbox_zone = "m.example.com";
    let cfg = ServerCfg {
        zone_labels: Some(validate_zone_and_labels(zone).unwrap()),
        mailbox_zone_labels: Some(validate_zone_and_labels(mbox_zone).unwrap()),
        progress_every: None,
        ans_ttl: 0,
        neg_ttl: 123,
        pretty_stdout: false,
        accept_ascii_only: false,
    };

    let domain = "00000000deadbeef.m.example.com"; // 16-hex mailbox
    let req = build_query(domain, 16, 1, 0x0D16);
    let hdr = parse_header(&req).unwrap();
    let (_name, qend, _t, _c) = parse_question(&req).unwrap();

    // Simulate main loop branch
    let labels = to_lower_labels(domain);
    let dl = strip_zone(&labels, &cfg.mailbox_zone_labels).unwrap();
    assert_eq!(dl.len(), 1);
    assert_eq!(
        parse_mailbox_id(&dl[0]).as_deref(),
        Some("00000000deadbeef")
    );

    let resp = build_negative_nodata_with_soa(
        &req,
        hdr,
        qend,
        cfg.mailbox_zone_labels.as_ref().unwrap(),
        cfg.neg_ttl,
    );
    assert_eq!(read_u16(&resp[6..8]), 0); // AN=0
    assert_eq!(read_u16(&resp[8..10]), 1); // NS=1 (SOA)
    // TTL of SOA equals neg_ttl
    let mut off = qend; // start of answer/authority
    // Authority SOA starts with NAME = mailbox zone
    for lab in validate_zone_and_labels(mbox_zone).unwrap() {
        off += 1 + lab.len();
    }
    off += 1; // root
    assert_eq!(read_u16(&resp[off..off + 2]), 6); // SOA
    let ttl = u32::from_be_bytes([resp[off + 4], resp[off + 5], resp[off + 6], resp[off + 7]]);
    assert_eq!(ttl, 123);
}

#[test]
fn mailbox_txt_positive_includes_txt_rrs() {
    let mbox_zone = "m.example.com";
    let tmp = std::env::temp_dir().join(format!("dnsm_test_mbx_db_{}", fastrand::u64(..)));
    std::fs::create_dir_all(&tmp).unwrap();
    let db = init_tmp_db(&tmp.join("msgs.sqlite"));
    let mailbox: u64 = 0x42;
    // Seed DB rows in order
    db.execute(
        "INSERT INTO messages (session_id, mailbox, data, received_at) VALUES (1, ?1, ?2, 100)",
        params![format!("{:016x}", mailbox), &b"hello"[..]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO messages (session_id, mailbox, data, received_at) VALUES (2, ?1, ?2, 101)",
        params![format!("{:016x}", mailbox), &b"world"[..]],
    )
    .unwrap();

    let cfg = ServerCfg {
        zone_labels: None,
        mailbox_zone_labels: Some(validate_zone_and_labels(mbox_zone).unwrap()),
        progress_every: None,
        ans_ttl: 55,
        neg_ttl: 300,
        pretty_stdout: false,
        accept_ascii_only: false,
    };

    let domain = "0000000000000042.m.example.com"; // strict 16-hex
    let req = build_query(domain, 16, 1, 0x0D17);
    let hdr = parse_header(&req).unwrap();
    let (_name, qend, _t, _c) = parse_question(&req).unwrap();

    let msgs = {
        let mut v = Vec::new();
        let mut stmt = db
            .prepare("SELECT data FROM messages WHERE mailbox=?1 ORDER BY id ASC")
            .unwrap();
        let rows = stmt
            .query_map(params![format!("{:016x}", mailbox)], |row| {
                let blob: Vec<u8> = row.get(0)?;
                Ok(blob)
            })
            .unwrap();
        for r in rows.flatten() {
            v.push(r);
        }
        v
    };

    let resp = build_mailbox_txt_response(
        &req,
        hdr,
        qend,
        cfg.ans_ttl,
        cfg.mailbox_zone_labels.as_ref().unwrap(),
        &msgs,
        480,
        false,
    );
    assert!(read_u16(&resp[6..8]) >= 1); // AN>=1
    // Inspect first RR TYPE
    let off = qend; // after question
    // First RR starts with name ptr (2), type (2), class (2), ttl (4), rdlen (2)
    assert_eq!(resp[off], 0xC0);
    assert_eq!(resp[off + 1], 0x0C);
    assert_eq!(read_u16(&resp[off + 2..off + 4]), 16); // TXT
    let ttl = u32::from_be_bytes([resp[off + 6], resp[off + 7], resp[off + 8], resp[off + 9]]);
    assert_eq!(ttl, 55);

    let _ = std::fs::remove_dir_all(&tmp);
}
