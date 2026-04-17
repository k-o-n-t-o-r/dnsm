use super::*;

#[test]
fn small_payload_yields_at_least_one_domain() {
    let zone = "x.foo.bar";
    let res = build_domains_for_payload(b"hello", zone).expect("ok");
    assert_eq!(res.len(), 1); // small payload fits in one chunk for a normal zone
    assert!(res[0].ends_with(zone));
    assert!(res[0].len() <= 255);
}

#[test]
fn single_chunk_with_mailbox_sets_flags_and_mailbox() {
    let zone = "x.foo.bar";
    let opts = BuildOptions {
        mailbox: Some(0x42),
    };
    let (domains, info) = build_domains_for_data(b"hi", zone, &opts).expect("ok");
    assert_eq!(domains.len(), 1);
    assert_eq!(info.total_chunks, 1);
    let name = &domains[0];
    let mut parts = name.split('.').collect::<Vec<_>>();
    let zone_labels = validate_zone_and_labels(zone).unwrap();
    for _ in 0..zone_labels.len() {
        parts.pop();
    }
    let b32 = parts.join("");
    let bytes = base32_nopad_decode(&b32).expect("valid base32");
    let (header, hdr_len) = ChunkHeader::from_bytes(&bytes).expect("valid header");
    assert_eq!(header.version, PROTOCOL_VERSION);
    assert!(header.is_first);
    assert!(!header.chunked);
    assert!(header.has_mailbox);
    assert!(!header.is_ping);
    assert_eq!(hdr_len, 1); // single-chunk: 1-byte header
    // mailbox is 48-bit big-endian right after header
    assert!(bytes.len() >= hdr_len + 6);
    let mut mb8 = [0u8; 8];
    mb8[2..8].copy_from_slice(&bytes[hdr_len..hdr_len + 6]);
    assert_eq!(u64::from_be_bytes(mb8), 0x42);
}

#[test]
fn multi_chunk_headers_and_lengths_are_consistent() {
    let zone = "x.foo.bar";
    // Use incompressible-ish data to ensure multi-chunk after LZMA
    let mut big = vec![0u8; 150_000];
    for b in &mut big {
        *b = fastrand::u8(..);
    }
    let opts = BuildOptions { mailbox: Some(7) };
    let (domains, info) = build_domains_for_data(&big, zone, &opts).expect("ok");
    assert!(info.total_chunks >= 2);
    assert_eq!(domains.len(), info.total_chunks);
    // label and qname length constraints
    for d in &domains {
        assert!(d.ends_with(zone));
        assert!(d.len() <= 255);
        for lab in d.split('.') {
            assert!(lab.len() <= 63);
        }
    }
    // Decode first two
    let strip = |s: &str| {
        let mut v = s.split('.').collect::<Vec<_>>();
        let z = validate_zone_and_labels(zone).unwrap();
        for _ in 0..z.len() {
            v.pop();
        }
        base32_nopad_decode(&v.join("")).expect("valid base32")
    };
    let b0 = strip(&domains[0]);
    let b1 = strip(&domains[1]);
    let (header0, hdr0_len) = ChunkHeader::from_bytes(&b0).expect("valid header");
    let (header1, hdr1_len) = ChunkHeader::from_bytes(&b1).expect("valid header");
    assert!(header0.is_first);
    assert!(!header1.is_first);
    assert!(header0.chunked);
    assert!(header1.chunked);
    assert_eq!(hdr0_len, 3); // multi-chunk: 3-byte header
    assert_eq!(hdr1_len, 3);
    // message_id48 should be identical across chunks (right after header)
    let mid0 = &b0[hdr0_len..hdr0_len + 6];
    let mid1 = &b1[hdr1_len..hdr1_len + 6];
    assert_eq!(mid0, mid1);
    assert_eq!(header1.remaining + 1, header0.remaining);
    // First chunk must include mailbox when provided
    assert!(header0.has_mailbox);
}

#[test]
fn zone_validation_and_too_long_zone() {
    // invalid labels
    assert!(validate_zone_and_labels("").is_err());
    assert!(validate_zone_and_labels("-bad.example").is_err());
    assert!(validate_zone_and_labels("bad-.example").is_err());
    assert!(validate_zone_and_labels("bad!.example").is_err());
    // zone just over 255 on the wire: four 63-char labels plus dots
    let long_label = "a".repeat(63);
    let zone = format!(
        "{}.{}.{}.{}",
        long_label, long_label, long_label, long_label
    );
    // build_domains_for_payload should error
    assert!(build_domains_for_payload(b"x", &zone).is_err());
    // but a shorter zone should work
    assert!(build_domains_for_payload(b"x", "x.foo.bar").is_ok());
}

// ---- v2 header tests ----

#[test]
fn v2_single_header_roundtrip() {
    let h = ChunkHeader::new(0, PROTOCOL_VERSION, true, false, false, false);
    assert_eq!(h.header_len(), 1);
    let bytes = h.to_bytes();
    assert_eq!(bytes.len(), 1);
    let (decoded, consumed) = ChunkHeader::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, 1);
    assert_eq!(decoded.version, PROTOCOL_VERSION);
    assert!(decoded.is_first);
    assert!(!decoded.chunked);
    assert!(!decoded.has_mailbox);
    assert!(!decoded.is_ping);
    assert_eq!(decoded.remaining, 0);
}

#[test]
fn v2_multi_header_roundtrip() {
    let h = ChunkHeader::new(42, PROTOCOL_VERSION, true, true, true, false);
    assert_eq!(h.header_len(), 3);
    let bytes = h.to_bytes();
    assert_eq!(bytes.len(), 3);
    let (decoded, consumed) = ChunkHeader::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, 3);
    assert_eq!(decoded.version, PROTOCOL_VERSION);
    assert!(decoded.is_first);
    assert!(decoded.chunked);
    assert!(decoded.has_mailbox);
    assert!(!decoded.is_ping);
    assert_eq!(decoded.remaining, 42);
}

#[test]
fn ping_header_roundtrip() {
    let h = ChunkHeader::new(0, PROTOCOL_VERSION, true, true, false, true);
    assert_eq!(h.header_len(), 1);
    let bytes = h.to_bytes();
    assert_eq!(bytes.len(), 1);
    let (decoded, consumed) = ChunkHeader::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, 1);
    assert!(decoded.is_ping);
    assert!(!decoded.chunked);
    assert!(decoded.has_mailbox);
    assert!(decoded.is_first);
    assert_eq!(decoded.version, PROTOCOL_VERSION);
}

#[test]
fn ping_domain_is_minimal() {
    let zone = "k.dnsm.re";
    let domain = build_ping_domain(0x000000000042, zone).expect("ok");
    assert!(domain.ends_with(zone));
    // 7 raw bytes → ceil(7*8/5) = 12 base32 chars
    // domain = 12 chars + "." + zone = 12 + 1 + 9 = 22
    assert_eq!(domain.len(), 22, "ping domain: {}", domain);
    // Verify it decodes back correctly
    let mut parts = domain.split('.').collect::<Vec<_>>();
    let z = validate_zone_and_labels(zone).unwrap();
    for _ in 0..z.len() {
        parts.pop();
    }
    let b32 = parts.join("");
    assert_eq!(b32.len(), 12);
    let bytes = base32_nopad_decode(&b32).expect("valid base32");
    assert_eq!(bytes.len(), 7); // 1 flags + 6 mailbox
    let (header, hdr_len) = ChunkHeader::from_bytes(&bytes).unwrap();
    assert!(header.is_ping);
    assert_eq!(hdr_len, 1);
    let mut mb8 = [0u8; 8];
    mb8[2..8].copy_from_slice(&bytes[hdr_len..hdr_len + 6]);
    assert_eq!(u64::from_be_bytes(mb8), 0x42);
}

#[test]
fn single_chunk_v2_saves_bytes_vs_v1_overhead() {
    // A single-chunk message with no mailbox should use only 1 byte of header overhead
    let zone = "x.foo.bar";
    let opts = BuildOptions { mailbox: None };
    let (domains, info) = build_domains_for_data(b"hello", zone, &opts).expect("ok");
    assert_eq!(info.total_chunks, 1);
    // Decode and check header is 1 byte
    let mut parts = domains[0].split('.').collect::<Vec<_>>();
    let z = validate_zone_and_labels(zone).unwrap();
    for _ in 0..z.len() {
        parts.pop();
    }
    let b32 = parts.join("");
    let bytes = base32_nopad_decode(&b32).expect("valid base32");
    let (header, hdr_len) = ChunkHeader::from_bytes(&bytes).expect("valid header");
    assert_eq!(hdr_len, 1);
    assert!(!header.chunked);
    assert!(header.is_first);
}
