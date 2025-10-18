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
    // strip zone
    for _ in 0..zone_labels.len() {
        parts.pop();
    }
    let data_labels_rev = parts; // data labels in order
    let b32 = data_labels_rev.join("");
    let bytes = base32_nopad_decode(&b32).expect("valid base32");
    let mut hdr = [0u8; CHUNK_HEADER_LEN];
    hdr.copy_from_slice(&bytes[..CHUNK_HEADER_LEN]);
    let header = ChunkHeader::from_bytes(&hdr);
    let rem = header.remaining;
    let ver = header.version;
    let first = header.is_first;
    assert_eq!(ver, 1);
    assert!(first);
    assert_eq!(rem, 0);
    assert!(header.has_mailbox);
    assert!(bytes.len() >= CHUNK_HEADER_LEN + 6);
    // mailbox is 48-bit big-endian
    let mut mb8 = [0u8; 8];
    mb8[2..8].copy_from_slice(&bytes[CHUNK_HEADER_LEN..CHUNK_HEADER_LEN + 6]);
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
    let mut hdr0 = [0u8; CHUNK_HEADER_LEN];
    hdr0.copy_from_slice(&b0[..CHUNK_HEADER_LEN]);
    let header0 = ChunkHeader::from_bytes(&hdr0);
    let mut hdr1 = [0u8; CHUNK_HEADER_LEN];
    hdr1.copy_from_slice(&b1[..CHUNK_HEADER_LEN]);
    let header1 = ChunkHeader::from_bytes(&hdr1);
    assert!(header0.is_first);
    assert!(!header1.is_first);
    // message_id48 should be identical across chunks
    let mid0 = &b0[CHUNK_HEADER_LEN..CHUNK_HEADER_LEN + 6];
    let mid1 = &b1[CHUNK_HEADER_LEN..CHUNK_HEADER_LEN + 6];
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
