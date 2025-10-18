#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

use dnsm::{BuildOptions, build_domains_for_data};

// Default runner is Node.js. To use a browser runner instead, uncomment:
// wasm_bindgen_test_configure!(run_in_browser);

fn b32_decode(s: &str) -> Vec<u8> {
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.chars() {
        let v: u64 = match ch {
            'A'..='Z' => (ch as u8 - b'A') as u64,
            'a'..='z' => (ch as u8 - b'a') as u64,
            '2'..='7' => 26 + (ch as u8 - b'2') as u64,
            '=' => continue,
            _ => 0,
        };
        acc = (acc << 5) | v;
        acc_bits += 5;
        while acc_bits >= 8 {
            let shift = acc_bits - 8;
            out.push(((acc >> shift) & 0xFF) as u8);
            acc &= (1u64 << shift) - 1;
            acc_bits -= 8;
        }
    }
    out
}

fn strip_zone<'a>(name: &'a str, zone: &str) -> String {
    let mut parts: Vec<&str> = name.split('.').collect();
    let zparts: Vec<&str> = zone.split('.').collect();
    for _ in 0..zparts.len() {
        parts.pop();
    }
    parts.join("")
}

#[wasm_bindgen_test]
fn wasm_single_small_with_mailbox_and_no_session() {
    let zone = "x.foo.bar";
    let opts = BuildOptions {
        mailbox: Some(0xABCD),
    };
    let (domains, info) = build_domains_for_data(b"hi", zone, &opts).expect("ok");
    assert_eq!(info.total_chunks, 1);
    let d = &domains[0];
    assert!(d.ends_with(zone));
    assert!(d.len() <= 255);
    for lab in d.split('.') {
        assert!(lab.len() <= 63);
    }
    let b = b32_decode(&strip_zone(d, zone));
    assert!(b.len() >= 17);
    let opts_byte = b[8];
    assert!(opts_byte & 0x01 != 0); // mailbox
    assert!(opts_byte & 0x02 != 0); // no-session
}

#[wasm_bindgen_test]
fn wasm_multi_chunk_consistency() {
    let zone = "x.foo.bar";
    // Random-looking data to avoid extreme LZMA compression and force multiple chunks
    let mut data = vec![0u8; 80_000];
    for i in 0..data.len() {
        data[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    let opts = BuildOptions { mailbox: Some(7) };
    let (domains, info) = build_domains_for_data(&data, zone, &opts).expect("ok");
    assert!(info.total_chunks >= 2);
    assert_eq!(domains.len(), info.total_chunks);
    let b0 = b32_decode(&strip_zone(&domains[0], zone));
    let b1 = b32_decode(&strip_zone(&domains[1], zone));
    let raw0 = u64::from_be_bytes(b0[0..8].try_into().unwrap());
    let raw1 = u64::from_be_bytes(b1[0..8].try_into().unwrap());
    let r0 = ((raw0 >> 48) & 0xFFFF) as u16;
    let r1 = ((raw1 >> 48) & 0xFFFF) as u16;
    let s0 = (raw0 >> 3) & ((1u64 << 45) - 1);
    let s1 = (raw1 >> 3) & ((1u64 << 45) - 1);
    let first0 = (raw0 & 1) != 0;
    let first1 = (raw1 & 1) == 1; // first1 should be false
    assert!(first0);
    assert!(!first1);
    assert_eq!(s0, s1);
    assert_eq!(r1 + 1, r0);
}
