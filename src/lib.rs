#![allow(clippy::missing_errors_doc)]

// v2 header: flags byte first, variable length.
// Flags byte layout:
//   Bit 7:     is_ping
//   Bit 6:     chunked   (1 = multi-chunk, remaining field present)
//   Bit 5:     has_mailbox
//   Bit 4:     is_first
//   Bits [3:1] version   (3 bits, currently 2)
//   Bit 0:     reserved
//
// When chunked=false: header is 1 byte (flags only).
// When chunked=true:  header is 3 bytes (flags + remaining u16 BE).

pub const PROTOCOL_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub version: u8,       // 3 bits [3:1]
    pub is_ping: bool,     // bit 7
    pub chunked: bool,     // bit 6
    pub has_mailbox: bool, // bit 5
    pub is_first: bool,    // bit 4
    pub remaining: u16,    // present on wire only when chunked=true
}

impl ChunkHeader {
    pub fn new(
        remaining: u16,
        version: u8,
        is_first: bool,
        has_mailbox: bool,
        chunked: bool,
        is_ping: bool,
    ) -> Self {
        Self {
            version: version & 0x07,
            is_ping,
            chunked,
            has_mailbox,
            is_first,
            remaining,
        }
    }

    /// Number of bytes this header occupies on the wire.
    pub fn header_len(&self) -> usize {
        if self.chunked { 3 } else { 1 }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut flags: u8 = 0;
        if self.is_ping {
            flags |= 1 << 7;
        }
        if self.chunked {
            flags |= 1 << 6;
        }
        if self.has_mailbox {
            flags |= 1 << 5;
        }
        if self.is_first {
            flags |= 1 << 4;
        }
        flags |= (self.version & 0x07) << 1;
        let mut out = vec![flags];
        if self.chunked {
            out.extend_from_slice(&self.remaining.to_be_bytes());
        }
        out
    }

    /// Decode a header from the start of `bytes`.
    /// Returns `(header, bytes_consumed)` or `None` if too short.
    pub fn from_bytes(bytes: &[u8]) -> Option<(Self, usize)> {
        if bytes.is_empty() {
            return None;
        }
        let flags = bytes[0];
        let is_ping = (flags & 0x80) != 0;
        let chunked = (flags & 0x40) != 0;
        let has_mailbox = (flags & 0x20) != 0;
        let is_first = (flags & 0x10) != 0;
        let version = (flags >> 1) & 0x07;
        let (remaining, consumed) = if chunked {
            if bytes.len() < 3 {
                return None;
            }
            (u16::from_be_bytes([bytes[1], bytes[2]]), 3)
        } else {
            (0u16, 1)
        };
        Some((
            Self {
                version,
                is_ping,
                chunked,
                has_mailbox,
                is_first,
                remaining,
            },
            consumed,
        ))
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

pub(crate) fn base32_nopad_encode(data: &[u8]) -> String {
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

fn build_domain(header: &ChunkHeader, extras: &[u8], data: &[u8], zone_labels: &[String]) -> String {
    let hdr_bytes = header.to_bytes();
    let mut buf = Vec::with_capacity(hdr_bytes.len() + extras.len() + data.len());
    buf.extend_from_slice(&hdr_bytes);
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
    pub mailbox: Option<u64>,
}

pub struct BuildInfo {
    pub total_chunks: usize,
    pub first_payload_len: usize,
    pub payload_per_chunk: usize,
    pub msg_id48: Option<u64>,
}

pub(crate) fn compress_lzma(data: &[u8]) -> Vec<u8> {
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
    let multi_chunk_overhead = 3 + 6;
    let base_payload_len = compute_payload_capacity(&zone_labels, multi_chunk_overhead);
    if base_payload_len == 0 {
        return Err("zone too long to fit any payload".to_string());
    }

    let first_single_len = compute_payload_capacity(&zone_labels, 1);
    let first_multi_len = compute_payload_capacity(&zone_labels, multi_chunk_overhead);
    let first_payload_len = if payload.len() <= first_single_len {
        first_single_len
    } else {
        first_multi_len
    };
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
        let is_single = total_chunks == 1;
        let cap = if is_first {
            first_payload_len
        } else {
            base_payload_len
        };
        let end = usize::min(sent + cap, payload.len());
        let data = &payload[sent..end];
        let remaining: u16 = (rmax as usize - i) as u16;
        let header = ChunkHeader::new(
            remaining,
            PROTOCOL_VERSION,
            is_first,
            false,
            !is_single,
            false,
        );
        let extras: Vec<u8> = if !is_single && is_first {
            vec![0; 6]
        } else if !is_single {
            vec![0; 6]
        } else {
            Vec::new()
        };
        let domain = build_domain(&header, &extras, data, &zone_labels);
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
    let has_mailbox = opts.mailbox.is_some();

    let multi_nonfirst_overhead = 3 + 6;
    let payload_len = compute_payload_capacity(&zone_labels, multi_nonfirst_overhead);
    if payload_len == 0 {
        return Err("zone too long to fit any payload".to_string());
    }

    let first_single_overhead = 1 + if has_mailbox { 6 } else { 0 };
    let first_single_len = compute_payload_capacity(&zone_labels, first_single_overhead);
    let first_multi_overhead = 3 + 6 + if has_mailbox { 6 } else { 0 };
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
    let mailbox48 = opts.mailbox.map(|v| v & 0x0000_FFFF_FFFF_FFFF);
    let msg_id48: Option<u64> = if total_chunks > 1 {
        Some(compute_message_key48(data))
    } else {
        None
    };

    let mut out = Vec::with_capacity(total_chunks);
    let mut sent = 0usize;
    for i in 0..total_chunks {
        let is_first = i == 0;
        let is_single = total_chunks == 1;
        let cap = if is_first {
            first_payload_len
        } else {
            payload_len
        };
        let end = usize::min(sent + cap, compressed.len());
        let chunk_data = &compressed[sent..end];
        let remaining: u16 = (rmax as usize - i) as u16;
        let header = ChunkHeader::new(
            remaining,
            PROTOCOL_VERSION,
            is_first,
            mailbox48.is_some(),
            !is_single,
            false,
        );
        let mut extras: Vec<u8> = Vec::new();
        if !is_single {
            if let Some(mid) = msg_id48 {
                let b = mid.to_be_bytes();
                extras.extend_from_slice(&b[2..8]);
            }
            if is_first {
                if let Some(mb) = mailbox48 {
                    let bb = mb.to_be_bytes();
                    extras.extend_from_slice(&bb[2..8]);
                }
            }
        } else {
            if let Some(mb) = mailbox48 {
                let bb = mb.to_be_bytes();
                extras.extend_from_slice(&bb[2..8]);
            }
        }
        let domain = build_domain(&header, &extras, chunk_data, &zone_labels);
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

pub fn build_ping_domain(mailbox: u64, zone: &str) -> Result<String, String> {
    let zone_labels = validate_zone_and_labels(zone)?;
    let header = ChunkHeader::new(0, PROTOCOL_VERSION, true, true, false, true);
    let mb = (mailbox & 0x0000_FFFF_FFFF_FFFF).to_be_bytes();
    let domain = build_domain(&header, &mb[2..8], &[], &zone_labels);
    let wire_len: usize = domain.len() + 2; // +1 length prefix for first label, +1 root null
    if wire_len > 255 {
        return Err(format!(
            "ping domain exceeds DNS 255-byte wire limit ({wire_len} bytes)"
        ));
    }
    Ok(domain)
}

// ---------------- wasm-bindgen JS API ----------------
#[cfg(target_arch = "wasm32")]
mod wasm_api {
    use super::{BuildOptions, build_domains_for_data, build_ping_domain};
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

    /// Returns a single ping domain for the given mailbox (exactly 12 hex chars, no 0x).
    #[wasm_bindgen]
    pub fn ping_domain(mailbox_str: &str, zone: &str) -> String {
        fn parse_hex12(v: &str) -> Result<u64, String> {
            let s = v.trim();
            if s.len() != 12 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("mailbox must be exactly 12 hex chars".to_string());
            }
            u64::from_str_radix(s, 16).map_err(|_| "bad hex".to_string())
        }
        let mailbox = parse_hex12(mailbox_str).unwrap_or_else(|e| wasm_bindgen::throw_str(&e));
        match build_ping_domain(mailbox, zone) {
            Ok(d) => d,
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

#[cfg(all(feature = "python", target_arch = "wasm32"))]
compile_error!("The `python` feature cannot be used with wasm32 targets");

// ---------------- PyO3 Python API ----------------
#[cfg(feature = "python")]
mod pyo3_api {
    use super::*;
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;

    fn parse_hex12(v: &str) -> PyResult<u64> {
        let s = v.trim();
        if s.len() != 12 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "mailbox must be exactly 12 hex chars",
            ));
        }
        u64::from_str_radix(s, 16)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("bad hex"))
    }

    #[pyclass(name = "BuildInfo", frozen)]
    pub struct PyBuildInfo {
        #[pyo3(get)]
        total_chunks: usize,
        #[pyo3(get)]
        first_payload_len: usize,
        #[pyo3(get)]
        payload_per_chunk: usize,
        #[pyo3(get)]
        msg_id48: Option<u64>,
    }

    #[pymethods]
    impl PyBuildInfo {
        fn __repr__(&self) -> String {
            format!(
                "BuildInfo(total_chunks={}, first_payload_len={}, payload_per_chunk={}, msg_id48={:?})",
                self.total_chunks, self.first_payload_len, self.payload_per_chunk, self.msg_id48
            )
        }
    }

    impl From<BuildInfo> for PyBuildInfo {
        fn from(b: BuildInfo) -> Self {
            Self {
                total_chunks: b.total_chunks,
                first_payload_len: b.first_payload_len,
                payload_per_chunk: b.payload_per_chunk,
                msg_id48: b.msg_id48,
            }
        }
    }

    #[pyfunction]
    #[pyo3(signature = (data, zone, mailbox=None))]
    fn build_domains(
        data: &[u8],
        zone: &str,
        mailbox: Option<&str>,
    ) -> PyResult<(Vec<String>, PyBuildInfo)> {
        let mailbox = mailbox.map(parse_hex12).transpose()?;
        let opts = BuildOptions { mailbox };
        let (domains, info) = build_domains_for_data(data, zone, &opts)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok((domains, info.into()))
    }

    #[pyfunction]
    fn build_domains_raw(payload: &[u8], zone: &str) -> PyResult<Vec<String>> {
        build_domains_for_payload(payload, zone)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    #[pyfunction]
    #[pyo3(name = "build_ping_domain")]
    fn build_ping_domain_py(mailbox: &str, zone: &str) -> PyResult<String> {
        let mb = parse_hex12(mailbox)?;
        build_ping_domain(mb, zone).map_err(pyo3::exceptions::PyValueError::new_err)
    }

    #[pyfunction]
    #[pyo3(name = "compress_lzma")]
    fn compress_lzma_py<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &compress_lzma(data))
    }

    #[pyfunction]
    fn base32_encode(data: &[u8]) -> String {
        base32_nopad_encode(data)
    }

    #[pyfunction]
    fn base32_decode<'py>(py: Python<'py>, s: &str) -> Option<Bound<'py, PyBytes>> {
        base32_nopad_decode(s).map(|v| PyBytes::new(py, &v))
    }

    #[pyfunction]
    fn message_id<'py>(py: Python<'py>, payload: &[u8]) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &compute_message_id(payload))
    }

    #[pyfunction]
    fn message_key48(payload: &[u8]) -> u64 {
        compute_message_key48(payload)
    }

    #[pyfunction]
    fn validate_zone(zone: &str) -> PyResult<Vec<String>> {
        validate_zone_and_labels(zone).map_err(pyo3::exceptions::PyValueError::new_err)
    }

    #[pyfunction]
    fn validate_mailbox(s: &str) -> Option<String> {
        validate_mailbox_hex12(s)
    }

    #[pymodule]
    pub fn dnsm(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_class::<PyBuildInfo>()?;
        m.add_function(wrap_pyfunction!(build_domains, m)?)?;
        m.add_function(wrap_pyfunction!(build_domains_raw, m)?)?;
        m.add_function(wrap_pyfunction!(build_ping_domain_py, m)?)?;
        m.add_function(wrap_pyfunction!(compress_lzma_py, m)?)?;
        m.add_function(wrap_pyfunction!(base32_encode, m)?)?;
        m.add_function(wrap_pyfunction!(base32_decode, m)?)?;
        m.add_function(wrap_pyfunction!(message_id, m)?)?;
        m.add_function(wrap_pyfunction!(message_key48, m)?)?;
        m.add_function(wrap_pyfunction!(validate_zone, m)?)?;
        m.add_function(wrap_pyfunction!(validate_mailbox, m)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
