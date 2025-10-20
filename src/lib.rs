#![allow(clippy::missing_errors_doc)]

// New compact header (24 bits)
pub const CHUNK_HEADER_LEN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub remaining: u16,    // 16 bits
    pub version: u8,       // 4 bits (stored in [7:4])
    pub is_first: bool,    // 1 bit (bit 3)
    pub has_mailbox: bool, // 1 bit (bit 2)
}

impl ChunkHeader {
    pub fn new(remaining: u16, version: u8, is_first: bool, has_mailbox: bool) -> Self {
        Self {
            remaining,
            version: version & 0x0F,
            is_first,
            has_mailbox,
        }
    }

    pub fn to_bytes(self) -> [u8; CHUNK_HEADER_LEN] {
        let mut out = [0u8; CHUNK_HEADER_LEN];
        out[0] = (self.remaining >> 8) as u8;
        out[1] = (self.remaining & 0xFF) as u8;
        let mut b2: u8 = (self.version & 0x0F) << 4;
        if self.is_first {
            b2 |= 1 << 3;
        }
        if self.has_mailbox {
            b2 |= 1 << 2;
        }
        // reserved [1:0] = 0
        out[2] = b2;
        out
    }

    pub fn from_bytes(bytes: &[u8; CHUNK_HEADER_LEN]) -> Self {
        let remaining = u16::from_be_bytes([bytes[0], bytes[1]]);
        let b2 = bytes[2];
        let version = (b2 >> 4) & 0x0F;
        let is_first = (b2 & 0x08) != 0;
        let has_mailbox = (b2 & 0x04) != 0;
        Self {
            remaining,
            version,
            is_first,
            has_mailbox,
        }
    }
}

pub fn to_lower_labels(name: &str) -> Vec<String> {
    name.trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

pub fn validate_zone_and_labels(zone: &str) -> Result<Vec<String>, String> {
    let labels = to_lower_labels(zone.trim());
    if labels.is_empty() {
        return Err("missing or empty <zone>".to_string());
    }
    for (i, lab) in labels.iter().enumerate() {
        let len = lab.len();
        if len == 0 || len > 63 {
            return Err(format!(
                "zone label {} has invalid length {} (1..=63)",
                i + 1,
                len
            ));
        }
        if !lab
            .chars()
            .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '_'))
        {
            return Err(format!(
                "zone label {} contains invalid characters: '{}'",
                i + 1,
                lab
            ));
        }
        if lab.starts_with('-') || lab.ends_with('-') {
            return Err(format!(
                "zone label {} must not start or end with '-' (got '{}')",
                i + 1,
                lab
            ));
        }
    }
    Ok(labels)
}

fn base32_nopad_encode(data: &[u8]) -> String {
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

pub fn base32_nopad_decode(s: &str) -> Option<Vec<u8>> {
    const MAX_BASE32_INPUT: usize = 512;

    if s.len() > MAX_BASE32_INPUT {
        return None;
    }

    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.chars() {
        let v: u64 = match ch {
            'A'..='Z' => (ch as u8 - b'A') as u64,
            'a'..='z' => (ch as u8 - b'a') as u64,
            '2'..='7' => 26 + (ch as u8 - b'2') as u64,
            '=' => continue,
            _ => return None,
        };
        if v >= 32 {
            return None;
        }
        acc = (acc << 5) | v;
        acc_bits += 5;
        while acc_bits >= 8 {
            let shift = acc_bits - 8;
            let byte = ((acc >> shift) & 0xFF) as u8;
            out.push(byte);
            acc &= (1u64 << shift) - 1;
            acc_bits -= 8;
        }
    }
    Some(out)
}

fn compute_payload_capacity(zone_labels: &[String], header_len: usize) -> usize {
    let zone_sum_len: usize = zone_labels.iter().map(|s| s.len()).sum();
    let zone_label_count = zone_labels.len();
    for payload in (0..=4096).rev() {
        let total_bytes = header_len + payload;
        let enc_len = (total_bytes * 8).div_ceil(5);
        let data_label_count = enc_len.div_ceil(63);
        let total_labels = data_label_count + zone_label_count;
        let wire_len = enc_len + zone_sum_len + total_labels + 1; // +1 for root
        if wire_len <= 255 {
            return payload;
        }
    }
    0
}

fn split_labels(s: &str, max_len: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let end = usize::min(i + max_len, s.len());
        out.push(&s[i..end]);
        i = end;
    }
    out
}

pub fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

// Validate a 12-hex mailbox ID (no 0x), returning lowercase on success.
pub fn validate_mailbox_hex12(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() != 12 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(t.to_ascii_lowercase())
}

pub fn parse_hex_bytes_exact(label: &str, byte_len: usize) -> Option<Vec<u8>> {
    let s = label.trim();
    if s.len() != byte_len * 2 {
        return None;
    }
    let mut out = Vec::with_capacity(byte_len);
    let mut chars = s.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let h = hi.to_digit(16)? as u8;
        let l = lo.to_digit(16)? as u8;
        out.push((h << 4) | l);
    }
    Some(out)
}

/// Compute a stable 16-byte message identifier from the decoded payload.
///
/// Semantics: BLAKE3(payload) truncated to the first 16 bytes.
/// This ID is suitable for deduplication and paging and is stable across targets.
pub fn compute_message_id(payload: &[u8]) -> [u8; 16] {
    let h = blake3::hash(payload);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.as_bytes()[..16]);
    out
}

/// Compute a 48-bit message key from payload bytes.
///
/// Semantics: take the first 6 bytes of BLAKE3(payload) and interpret as
/// a big-endian 48-bit integer (stored in a u64 with the top 16 bits zero).
/// Used as a compact key for single-chunk messages.
pub fn compute_message_key48(payload: &[u8]) -> u64 {
    let h = blake3::hash(payload);
    let mut b = [0u8; 8];
    b[..6].copy_from_slice(&h.as_bytes()[..6]);
    u64::from_be_bytes(b)
}

fn build_domain(header: ChunkHeader, extras: &[u8], data: &[u8], zone_labels: &[String]) -> String {
    let mut buf = Vec::with_capacity(CHUNK_HEADER_LEN + extras.len() + data.len());
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(extras);
    buf.extend_from_slice(data);
    let enc = base32_nopad_encode(&buf);
    let mut labels: Vec<String> = split_labels(&enc, 63)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    labels.extend(zone_labels.iter().cloned());
    labels.join(".")
}

#[derive(Default)]
pub struct BuildOptions {
    // mailbox is 48-bit when present; API keeps u64 and masks to 48 bits
    pub mailbox: Option<u64>,
}

pub struct BuildInfo {
    pub total_chunks: usize,
    pub first_payload_len: usize,
    pub payload_per_chunk: usize,
    pub msg_id48: Option<u64>, // present for multi-chunk
}

fn compress_lzma(data: &[u8]) -> Vec<u8> {
    use lzma_rust2::{LzmaOptions, LzmaWriter};
    use std::io::Write;
    let mut w =
        LzmaWriter::new_use_header(Vec::new(), &LzmaOptions::default(), Some(data.len() as u64))
            .expect("lzma init");
    w.write_all(data).expect("lzma write");
    w.finish().expect("lzma finish")
}

pub fn build_domains_for_payload(payload: &[u8], zone: &str) -> Result<Vec<String>, String> {
    let zone_labels = validate_zone_and_labels(zone)?;
    // Non-first and first of multi include msg_id48 (6 bytes)
    let base_payload_len = compute_payload_capacity(&zone_labels, CHUNK_HEADER_LEN + 6);
    if base_payload_len == 0 {
        return Err("zone too long to fit any payload".to_string());
    }
    let version: u8 = 1; // new protocol version

    // Single-chunk first header is only 3 bytes (no msg_id, no mailbox)
    let first_payload_len = compute_payload_capacity(&zone_labels, CHUNK_HEADER_LEN);
    let total_chunks = if payload.len() <= first_payload_len {
        1
    } else {
        1 + (payload.len() - first_payload_len).div_ceil(base_payload_len)
    };
    let rmax = if total_chunks == 0 {
        0
    } else {
        (total_chunks - 1) as u16
    };
    let mut out = Vec::with_capacity(total_chunks);
    let mut sent = 0usize;
    for i in 0..total_chunks {
        let is_first = i == 0;
        let cap = if is_first {
            first_payload_len
        } else {
            base_payload_len
        };
        let end = usize::min(sent + cap, payload.len());
        let data = &payload[sent..end];
        let remaining: u16 = (rmax as usize - i) as u16;
        let header = ChunkHeader::new(remaining, version, is_first, false);
        let extras: Vec<u8> = if total_chunks == 1 || !is_first {
            Vec::new()
        } else {
            vec![0; 6]
        };
        // For build_domains_for_payload (raw payload, no mailbox, and no msg_id computation), we only add msg_id space for multi-first
        let domain = build_domain(header, &extras, data, &zone_labels);
        out.push(domain);
        sent = end;
    }

    Ok(out)
}

pub fn build_domains_for_data(
    data: &[u8],
    zone: &str,
    opts: &BuildOptions,
) -> Result<(Vec<String>, BuildInfo), String> {
    let compressed = compress_lzma(data);
    let zone_labels = validate_zone_and_labels(zone)?;
    // Non-first and first of multi include msg_id48 (6 bytes)
    let payload_len = compute_payload_capacity(&zone_labels, CHUNK_HEADER_LEN + 6);
    if payload_len == 0 {
        return Err("zone too long to fit any payload".to_string());
    }
    let has_mailbox = opts.mailbox.is_some();
    // First single: header + optional 6-byte mailbox.
    let first_single_overhead = CHUNK_HEADER_LEN + if has_mailbox { 6 } else { 0 };
    let first_single_len = compute_payload_capacity(&zone_labels, first_single_overhead);
    let first_multi_overhead = CHUNK_HEADER_LEN + 6 + if has_mailbox { 6 } else { 0 };
    let first_multi_len = compute_payload_capacity(&zone_labels, first_multi_overhead);
    let first_payload_len = if compressed.len() <= first_single_len {
        first_single_len
    } else {
        first_multi_len
    };
    let total_chunks = if compressed.len() <= first_payload_len {
        1
    } else {
        1 + (compressed.len() - first_payload_len).div_ceil(payload_len)
    };
    let rmax: u16 = if total_chunks == 0 {
        0
    } else {
        (total_chunks - 1) as u16
    };
    let version: u8 = 1;
    let mailbox48 = opts.mailbox.map(|v| v & 0x0000_FFFF_FFFF_FFFF);
    // Compute message_id48 from uncompressed data for multi-chunk cases
    let msg_id48: Option<u64> = if total_chunks > 1 {
        Some(compute_message_key48(data))
    } else {
        None
    };

    let mut out = Vec::with_capacity(total_chunks);
    let mut sent = 0usize;
    for i in 0..total_chunks {
        let is_first = i == 0;
        let cap = if is_first {
            first_payload_len
        } else {
            payload_len
        };
        let end = usize::min(sent + cap, compressed.len());
        let data = &compressed[sent..end];
        let remaining: u16 = (rmax as usize - i) as u16;
        let header = ChunkHeader::new(remaining, version, is_first, mailbox48.is_some());
        let mut extras: Vec<u8> = Vec::new();
        if total_chunks > 1 {
            if let Some(mid) = msg_id48 {
                let b = mid.to_be_bytes();
                extras.extend_from_slice(&b[2..8]);
            }
            if is_first && let Some(mb) = mailbox48 {
                let bb = mb.to_be_bytes();
                extras.extend_from_slice(&bb[2..8]);
            }
        } else {
            // single-chunk: include mailbox if present
            if let Some(mb) = mailbox48 {
                let bb = mb.to_be_bytes();
                extras.extend_from_slice(&bb[2..8]);
            }
        }
        let domain = build_domain(header, &extras, data, &zone_labels);
        out.push(domain);
        sent = end;
    }

    Ok((
        out,
        BuildInfo {
            total_chunks,
            first_payload_len,
            payload_per_chunk: payload_len,
            msg_id48,
        },
    ))
}

// ---------------- wasm-bindgen JS API ----------------
#[cfg(target_arch = "wasm32")]
mod wasm_api {
    use super::{BuildOptions, build_domains_for_data};
    use js_sys::Array;
    use wasm_bindgen::prelude::*;

    /// Returns domains for input string with no mailbox and auto session.
    #[wasm_bindgen]
    pub fn domains_for_string(input: &str, zone: &str) -> Array {
        let opts = BuildOptions::default();
        match build_domains_for_data(input.as_bytes(), zone, &opts) {
            Ok((domains, _info)) => domains.into_iter().fold(Array::new(), |arr, s| {
                arr.push(&JsValue::from(s));
                arr
            }),
            Err(e) => wasm_bindgen::throw_str(&e),
        }
    }

    /// Returns domains for input string with mailbox (exactly 12 hex chars, no 0x).
    #[wasm_bindgen]
    pub fn domains_for_string_with_mailbox(input: &str, zone: &str, mailbox_str: &str) -> Array {
        fn parse_hex12(v: &str) -> Result<u64, String> {
            let s = v.trim();
            if s.len() != 12 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("mailbox must be exactly 12 hex chars".to_string());
            }
            u64::from_str_radix(s, 16).map_err(|_| "bad hex".to_string())
        }
        let mailbox = if mailbox_str.trim().is_empty() {
            None
        } else {
            Some(parse_hex12(mailbox_str).unwrap_or_else(|e| wasm_bindgen::throw_str(&e)))
        };
        let opts = BuildOptions { mailbox };
        match build_domains_for_data(input.as_bytes(), zone, &opts) {
            Ok((domains, _info)) => domains.into_iter().fold(Array::new(), |arr, s| {
                arr.push(&JsValue::from(s));
                arr
            }),
            Err(e) => wasm_bindgen::throw_str(&e),
        }
    }
}

#[cfg(test)]
mod tests;
