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

#[test]
fn human_ping_domain_format() {
    let domain = build_human_ping_domain("f8925edd7f13", "k.dnsm.re").expect("ok");
    assert_eq!(domain, "f8925edd7f13.k.dnsm.re");
}

#[test]
fn human_ping_domain_validates_mailbox() {
    assert!(build_human_ping_domain("bad", "k.dnsm.re").is_err());
    assert!(build_human_ping_domain("zzzzzzzzzzzz", "k.dnsm.re").is_err());
}

#[test]
fn human_ping_domain_validates_zone() {
    assert!(build_human_ping_domain("f8925edd7f13", "").is_err());
}

#[test]
fn multi_chunk_key_differs_by_mailbox() {
    let zone = "x.t";
    let mut big = vec![0u8; 1024];
    for (i, b) in big.iter_mut().enumerate() {
        *b = (i * 37 + 13) as u8;
    }
    let mb_a = BuildOptions {
        mailbox: Some(0x000011112222),
    };
    let mb_b = BuildOptions {
        mailbox: Some(0x000033334444),
    };
    let (domains_a, info_a) = build_domains_for_data(&big, zone, &mb_a).unwrap();
    let (domains_b, info_b) = build_domains_for_data(&big, zone, &mb_b).unwrap();
    assert!(info_a.total_chunks > 1);
    assert!(info_b.total_chunks > 1);
    assert_ne!(
        info_a.msg_id48, info_b.msg_id48,
        "same payload with different mailboxes must have different msg_id48"
    );
    assert_ne!(domains_a, domains_b);
}

#[test]
fn multi_chunk_key_no_mailbox_vs_mailbox_no_collision() {
    let zone = "x.t";
    let mailbox: u64 = 0x0000AABBCCDD;
    let mb_bytes = &mailbox.to_be_bytes()[2..8];
    let base_data = vec![0x42u8; 300];
    let mut crafted = base_data.clone();
    crafted.extend_from_slice(mb_bytes);

    let with_mb = BuildOptions {
        mailbox: Some(mailbox),
    };
    let no_mb = BuildOptions { mailbox: None };
    let (_, info_with) = build_domains_for_data(&base_data, zone, &with_mb).unwrap();
    let (_, info_without) = build_domains_for_data(&crafted, zone, &no_mb).unwrap();
    if info_with.total_chunks > 1 && info_without.total_chunks > 1 {
        assert_ne!(
            info_with.msg_id48, info_without.msg_id48,
            "mailbox message must not collide with no-mailbox message whose payload ends with mailbox bytes"
        );
    }
}

#[test]
fn multi_chunk_wire_msg_id_has_full_entropy() {
    let zone = "x.t";
    let mut data = vec![0u8; 1024];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i * 37 + 13) as u8;
    }
    let opts = BuildOptions {
        mailbox: Some(0x0000AABBCCDD),
    };
    let (domains, info) = build_domains_for_data(&data, zone, &opts).unwrap();
    assert!(info.total_chunks > 1);
    let mid = info.msg_id48.expect("multi-chunk must have msg_id48");
    let mid_bytes = mid.to_be_bytes();
    // The wire sends mid_bytes[2..8]; verify those 6 bytes are not zero-padded
    assert_ne!(
        &mid_bytes[2..8],
        &[0u8; 6],
        "wire msg_id bytes must not be all zero"
    );
    // Decode the second domain (non-first chunk) and verify the msg_id on the wire
    let zone_labels = validate_zone_and_labels(zone).unwrap();
    let mut parts: Vec<&str> = domains[1].split('.').collect();
    for _ in 0..zone_labels.len() {
        parts.pop();
    }
    let b32 = parts.join("");
    let bytes = base32_nopad_decode(&b32).expect("valid base32");
    let (header, hdr_len) = ChunkHeader::from_bytes(&bytes).expect("valid header");
    assert!(header.chunked);
    // msg_id48 is the next 6 bytes after the header
    let wire_mid = &bytes[hdr_len..hdr_len + 6];
    assert_eq!(
        wire_mid,
        &mid_bytes[2..8],
        "wire msg_id must match computed msg_id48"
    );
}

#[test]
fn raw_builder_multi_chunk_has_nonzero_distinct_keys() {
    let zone = "x.t";
    fn make_incompressible(seed: u8) -> Vec<u8> {
        let mut v = vec![0u8; 2048];
        for (i, b) in v.iter_mut().enumerate() {
            *b = (i.wrapping_mul(37).wrapping_add(seed as usize)) as u8;
        }
        v
    }
    let payload_a = make_incompressible(1);
    let payload_b = make_incompressible(2);
    let domains_a = build_domains_for_payload(&payload_a, zone).unwrap();
    let domains_b = build_domains_for_payload(&payload_b, zone).unwrap();
    assert!(domains_a.len() > 1);
    assert!(domains_b.len() > 1);
    let extract_mid = |domains: &[String]| -> Vec<u8> {
        let zone_labels = validate_zone_and_labels(zone).unwrap();
        let mut parts: Vec<&str> = domains[1].split('.').collect();
        for _ in 0..zone_labels.len() {
            parts.pop();
        }
        let b32 = parts.join("");
        let bytes = base32_nopad_decode(&b32).unwrap();
        let (_, hdr_len) = ChunkHeader::from_bytes(&bytes).unwrap();
        bytes[hdr_len..hdr_len + 6].to_vec()
    };
    let mid_a = extract_mid(&domains_a);
    let mid_b = extract_mid(&domains_b);
    assert_ne!(mid_a, vec![0u8; 6], "raw builder msg_id must not be zero");
    assert_ne!(mid_b, vec![0u8; 6], "raw builder msg_id must not be zero");
    assert_ne!(
        mid_a, mid_b,
        "different payloads must produce different msg_ids"
    );
}
