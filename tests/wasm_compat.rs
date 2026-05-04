#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

use dnsm::{
    BuildOptions, ChunkHeader, PROTOCOL_VERSION, base32_nopad_decode, build_domains_for_data,
    build_ping_domain,
};

fn strip_zone<'a>(name: &'a str, zone: &str) -> String {
    let mut parts: Vec<&str> = name.split('.').collect();
    let zparts: Vec<&str> = zone.split('.').collect();
    for _ in 0..zparts.len() {
        parts.pop();
    }
    parts.join("")
}

#[wasm_bindgen_test]
fn wasm_single_with_mailbox_v2() {
    let zone = "x.foo.bar";
    let opts = BuildOptions {
        mailbox: Some(0xABCD),
    };
    let (domains, info) = build_domains_for_data(b"hi", zone, &opts).expect("ok");
    assert_eq!(info.total_chunks, 1);
    let d = &domains[0];
    assert!(d.ends_with(zone));
    assert!(d.len() <= 255);

    let b32 = strip_zone(d, zone);
    let bytes = base32_nopad_decode(&b32).expect("valid base32");
    let (header, hdr_len) = ChunkHeader::from_bytes(&bytes).expect("valid header");
    assert_eq!(header.version, PROTOCOL_VERSION);
    assert!(header.is_first);
    assert!(!header.chunked);
    assert!(header.has_mailbox);
    assert!(!header.is_ping);
    assert_eq!(hdr_len, 1);
}

#[wasm_bindgen_test]
fn wasm_multi_chunk_v2() {
    let zone = "x.foo.bar";
    let mut data = vec![0u8; 80_000];
    for i in 0..data.len() {
        data[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    let opts = BuildOptions { mailbox: Some(7) };
    let (domains, info) = build_domains_for_data(&data, zone, &opts).expect("ok");
    assert!(info.total_chunks >= 2);
    assert_eq!(domains.len(), info.total_chunks);

    let b0 = base32_nopad_decode(&strip_zone(&domains[0], zone)).unwrap();
    let b1 = base32_nopad_decode(&strip_zone(&domains[1], zone)).unwrap();
    let (h0, _) = ChunkHeader::from_bytes(&b0).unwrap();
    let (h1, _) = ChunkHeader::from_bytes(&b1).unwrap();
    assert!(h0.is_first);
    assert!(!h1.is_first);
    assert!(h0.chunked);
    assert!(h1.chunked);
    assert!(h0.has_mailbox);
    assert_eq!(h1.remaining + 1, h0.remaining);
}

#[wasm_bindgen_test]
fn wasm_ping_domain() {
    let zone = "k.dnsm.re";
    let domain = build_ping_domain(0x42, zone).expect("ok");
    assert!(domain.ends_with(zone));
    assert_eq!(domain.len(), 22);

    let b32 = strip_zone(&domain, zone);
    let bytes = base32_nopad_decode(&b32).unwrap();
    let (header, hdr_len) = ChunkHeader::from_bytes(&bytes).unwrap();
    assert!(header.is_ping);
    assert!(header.has_mailbox);
    assert!(!header.chunked);
    assert_eq!(hdr_len, 1);
    assert_eq!(bytes.len(), 7);
}
