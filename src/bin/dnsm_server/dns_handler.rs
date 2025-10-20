use console::style;
use dnsm::{
    CHUNK_HEADER_LEN, ChunkHeader, base32_nopad_decode, compute_message_id, compute_message_key48,
    to_lower_labels,
};
use rusqlite::{Connection, params};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::io::{BufWriter, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const DNS_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy)]
pub(crate) struct DnsHeader {
    pub(crate) id: u16,
    pub(crate) flags: u16,
}

pub(crate) fn read_u16(be: &[u8]) -> u16 {
    u16::from_be_bytes([be[0], be[1]])
}

pub(crate) fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn parse_header(pkt: &[u8]) -> Result<DnsHeader, ()> {
    if pkt.len() < DNS_HEADER_LEN {
        return Err(());
    }
    Ok(DnsHeader {
        id: read_u16(&pkt[0..2]),
        flags: read_u16(&pkt[2..4]),
    })
}

/// Parses a single QNAME starting at offset 12 and returns (domain, next_offset_after_qclass).
/// `next_offset` points just after QTYPE+QCLASS.
pub(crate) fn parse_question(pkt: &[u8]) -> Result<(String, usize, u16, u16), ()> {
    if pkt.len() < DNS_HEADER_LEN + 5 {
        return Err(());
    }
    let mut off = DNS_HEADER_LEN;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if off >= pkt.len() {
            return Err(());
        }
        let len = pkt[off] as usize;
        off += 1;
        if len == 0 {
            break;
        }
        if off + len > pkt.len() {
            return Err(());
        }
        let label = std::str::from_utf8(&pkt[off..off + len]).map_err(|_| ())?;
        labels.push(label.to_string());
        off += len;
    }
    if off + 4 > pkt.len() {
        return Err(());
    }
    let qtype = read_u16(&pkt[off..off + 2]);
    let qclass = read_u16(&pkt[off + 2..off + 4]);
    off += 4;
    Ok((labels.join("."), off, qtype, qclass))
}

pub(crate) fn write_name(buf: &mut Vec<u8>, labels: &[String]) {
    for lab in labels {
        buf.push(lab.len() as u8);
        buf.extend_from_slice(lab.as_bytes());
    }
    buf.push(0);
}

fn build_soa_authority(buf: &mut Vec<u8>, zone_labels: &[String], neg_ttl: u32) {
    write_name(buf, zone_labels);
    write_u16(buf, 6);
    write_u16(buf, 1);
    buf.extend_from_slice(&neg_ttl.to_be_bytes());

    let mut mname: Vec<String> = Vec::with_capacity(zone_labels.len() + 1);
    mname.push("ns".to_string());
    mname.extend(zone_labels.iter().cloned());

    let mut rname: Vec<String> = Vec::with_capacity(zone_labels.len() + 1);
    rname.push("hostmaster".to_string());
    rname.extend(zone_labels.iter().cloned());

    let mut rdata: Vec<u8> = Vec::with_capacity(64);
    write_name(&mut rdata, &mname);
    write_name(&mut rdata, &rname);

    let serial: u32 = (now_millis() as u32) & 0x7FFF_FFFF;
    let refresh: u32 = 3600;
    let retry: u32 = 600;
    let expire: u32 = 86400;
    let minimum: u32 = neg_ttl;
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&refresh.to_be_bytes());
    rdata.extend_from_slice(&retry.to_be_bytes());
    rdata.extend_from_slice(&expire.to_be_bytes());
    rdata.extend_from_slice(&minimum.to_be_bytes());

    write_u16(buf, rdata.len() as u16);
    buf.extend_from_slice(&rdata);
}

pub(crate) fn build_response(
    req: &[u8],
    req_hdr: DnsHeader,
    q_end: usize,
    fixed_ip: Ipv4Addr,
    is_a_query: bool,
    in_zone: bool,
    cfg: &crate::ServerCfg,
) -> Vec<u8> {
    let rd = req_hdr.flags & 0x0100;
    let qr = 0x8000;
    let aa = if in_zone { 0x0400 } else { 0 };
    let opcode_bits = ((req_hdr.flags >> 11) & 0x0F) << 11;
    let (rcode, attach_soa) = if is_a_query {
        (0u16, false)
    } else if in_zone {
        (0u16, true)
    } else {
        (4u16, false)
    };
    let flags = qr | opcode_bits | aa | rd | (rcode & 0x000F);

    let mut resp = Vec::with_capacity(512);
    write_u16(&mut resp, req_hdr.id);
    write_u16(&mut resp, flags);
    write_u16(&mut resp, 1);
    let an_idx = resp.len();
    write_u16(&mut resp, 0);
    let ns_idx = resp.len();
    write_u16(&mut resp, 0);
    write_u16(&mut resp, 0);

    let qlen = q_end - DNS_HEADER_LEN;
    resp.extend_from_slice(&req[DNS_HEADER_LEN..DNS_HEADER_LEN + qlen]);

    let mut an_count: u16 = 0;
    let mut ns_count: u16 = 0;

    if is_a_query {
        resp.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(&mut resp, 1);
        write_u16(&mut resp, 1);
        resp.extend_from_slice(&cfg.ans_ttl.to_be_bytes());
        write_u16(&mut resp, 4);
        resp.extend_from_slice(&fixed_ip.octets());
        an_count = 1;
    }

    if attach_soa && let Some(zone) = cfg.zone_labels.as_ref() {
        build_soa_authority(&mut resp, zone, cfg.neg_ttl);
        ns_count = 1;
    }

    resp[an_idx] = ((an_count >> 8) & 0xFF) as u8;
    resp[an_idx + 1] = (an_count & 0xFF) as u8;
    resp[ns_idx] = ((ns_count >> 8) & 0xFF) as u8;
    resp[ns_idx + 1] = (ns_count & 0xFF) as u8;

    resp
}

pub(crate) fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn strip_zone<'a>(
    labels: &'a [String],
    zone: &Option<Vec<String>>,
) -> Option<&'a [String]> {
    match zone {
        None => None,
        Some(z) => {
            if labels.len() < z.len() {
                return None;
            }
            let tail = &labels[labels.len() - z.len()..];
            if tail == z.as_slice() {
                let head = &labels[..labels.len() - z.len()];
                if head.is_empty() { None } else { Some(head) }
            } else {
                None
            }
        }
    }
}

pub(crate) fn format_socket(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

/// Validate a domain for storage/logging; returns Ok(domain) or an error string.
pub(crate) fn validate_and_sanitize_domain(domain: &str) -> Result<String, String> {
    const MAX_DOMAIN_LENGTH: usize = 255;
    const MAX_LABEL_LENGTH: usize = 63;
    const MAX_LABEL_COUNT: usize = 127; // Reasonable limit for label count

    if domain.is_empty() {
        return Err("empty domain".to_string());
    }

    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(format!(
            "domain too long ({} bytes, max {})",
            domain.len(),
            MAX_DOMAIN_LENGTH
        ));
    }

    let labels: Vec<&str> = domain.split('.').collect();

    if labels.len() > MAX_LABEL_COUNT {
        return Err(format!(
            "too many labels ({}, max {})",
            labels.len(),
            MAX_LABEL_COUNT
        ));
    }

    for (idx, label) in labels.iter().enumerate() {
        if label.is_empty() {
            if idx != labels.len() - 1 {
                return Err(format!("empty label at position {}", idx));
            }
            continue;
        }

        if label.len() > MAX_LABEL_LENGTH {
            return Err(format!(
                "label '{}' too long ({} bytes, max {})",
                label,
                label.len(),
                MAX_LABEL_LENGTH
            ));
        }

        for (char_idx, ch) in label.chars().enumerate() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                if ch.is_control() {
                    return Err(format!("control character (0x{:02x}) in label", ch as u32));
                } else {
                    return Err(format!("invalid character '{}' in label", ch));
                }
            }
            if ch == '-' && (char_idx == 0 || char_idx == label.len() - 1) {
                return Err("label cannot start/end with hyphen".to_string());
            }
        }
    }

    Ok(domain.to_string())
}

/// Sanitize a domain for logs (replace controls/non-ASCII, clamp length).
pub(crate) fn sanitize_domain_for_logging(domain: &str) -> String {
    const MAX_LOG_LENGTH: usize = 255;

    let truncated = if domain.len() > MAX_LOG_LENGTH {
        &domain[..MAX_LOG_LENGTH]
    } else {
        domain
    };

    truncated
        .chars()
        .map(|ch| {
            if ch.is_control() {
                '?'
            } else if ch.is_ascii() {
                ch
            } else {
                '?'
            }
        })
        .collect()
}

fn decompress_lzma_mem(input: &[u8], max_bytes: u32) -> Result<Vec<u8>, String> {
    let mem_limit = if max_bytes == 0 { u32::MAX } else { max_bytes };
    let mut reader = lzma_rust2::LzmaReader::new_mem_limit(Cursor::new(input), mem_limit, None)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if max_bytes > 0 {
        const CHUNK_SIZE: usize = 8192;
        let mut buffer = [0u8; CHUNK_SIZE];
        let mut total_read: u32 = 0;
        loop {
            let n = reader.read(&mut buffer).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }

            let error_message =
                || format!("Decompressed payload exceeds limit of {} bytes.", max_bytes);

            total_read = total_read
                .checked_add(n as u32)
                .ok_or_else(&error_message)?;

            if total_read > max_bytes {
                return Err(error_message());
            }

            out.extend_from_slice(&buffer[..n]);
        }
    } else {
        reader.read_to_end(&mut out).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn log_event(log: &mut BufWriter<std::fs::File>, now: u128, event: &str, rest_fields: &str) {
    let _ = writeln!(
        log,
        "{{\"ts\":{},\"event\":\"{}\"{}}}",
        now, event, rest_fields
    );
}

pub(crate) fn try_handle_dnsm(
    full_domain: &str,
    cfg: &crate::ServerCfg,
    assemblies: &mut HashMap<u64, crate::Assembly>,
    now: u128,
    log: &mut BufWriter<std::fs::File>,
    peer: SocketAddr,
    db: &Connection,
) {
    let labels = to_lower_labels(full_domain);
    let data_labels = match strip_zone(&labels, &cfg.zone_labels) {
        None => return,
        Some(labels_in_zone) => labels_in_zone,
    };

    let mut b32 = String::with_capacity(data_labels.iter().map(|s| s.len()).sum());
    for (idx, lab) in data_labels.iter().enumerate() {
        if !lab
            .chars()
            .all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '2'..='7' | '='))
        {
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"parse_error\",\"label_index\":{},\"label\":\"{}\",\"domain\":\"{}\",\"peer\":\"{}\"}}",
                now,
                idx,
                json_escape(lab),
                json_escape(full_domain),
                json_escape(&format_socket(peer))
            );
            let _ = log.flush();
            if cfg.pretty_stdout {
                let err = style(format!(
                    "[ERR] parse_error label#{} '{}' domain={} peer={}",
                    idx,
                    lab,
                    full_domain,
                    format_socket(peer)
                ))
                .red()
                .bold();
                println!("{}", err);
            }
            return;
        }
        b32.push_str(lab);
    }

    let bytes = match base32_nopad_decode(&b32) {
        Some(v) => v,
        None => {
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"decode_error\",\"reason\":\"invalid_base32\",\"domain\":\"{}\",\"chars\":{},\"labels\":{},\"peer\":\"{}\"}}",
                now,
                json_escape(full_domain),
                b32.len(),
                data_labels.len(),
                json_escape(&format_socket(peer))
            );
            let _ = log.flush();
            if cfg.pretty_stdout {
                let line = style(format!(
                    "[ERR] decode_error invalid_base32 domain={} chars={} labels={} peer={}",
                    full_domain,
                    b32.len(),
                    data_labels.len(),
                    format_socket(peer)
                ))
                .red();
                println!("{}", line);
            }
            return;
        }
    };

    if bytes.len() < 8 {
        let _ = writeln!(
            log,
            "{{\"ts\":{},\"event\":\"decode_error\",\"reason\":\"short_bytes\",\"len\":{},\"domain\":\"{}\",\"peer\":\"{}\"}}",
            now,
            bytes.len(),
            json_escape(full_domain),
            json_escape(&format_socket(peer))
        );
        let _ = log.flush();
        if cfg.pretty_stdout {
            let line = style(format!(
                "[ERR] decode_error short_bytes len={} domain={} peer={}",
                bytes.len(),
                full_domain,
                format_socket(peer)
            ))
            .red();
            println!("{}", line);
        }
        return;
    }

    let mut hdr = [0u8; CHUNK_HEADER_LEN];
    hdr.copy_from_slice(&bytes[..CHUNK_HEADER_LEN]);
    let header = ChunkHeader::from_bytes(&hdr);
    if header.version == 0 {
        return;
    }
    let mut offset = CHUNK_HEADER_LEN;
    let mut mailbox: Option<u64> = None;
    let mut message_key: u64 = 0;
    if header.is_first {
        if header.remaining == 0 {
            if header.has_mailbox {
                if bytes.len() < offset + 6 {
                    return;
                }
                let mut mb = [0u8; 8];
                mb[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                mailbox = Some(u64::from_be_bytes(mb));
                offset += 6;
            }
        } else {
            if bytes.len() < offset + 6 {
                return;
            }
            let mut mid = [0u8; 8];
            mid[2..8].copy_from_slice(&bytes[offset..offset + 6]);
            message_key = u64::from_be_bytes(mid);
            offset += 6;
            if header.has_mailbox {
                if bytes.len() < offset + 6 {
                    return;
                }
                let mut mb = [0u8; 8];
                mb[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                mailbox = Some(u64::from_be_bytes(mb));
                offset += 6;
            }
        }
    } else {
        if bytes.len() < offset + 6 {
            return;
        }
        let mut mid = [0u8; 8];
        mid[2..8].copy_from_slice(&bytes[offset..offset + 6]);
        message_key = u64::from_be_bytes(mid);
        offset += 6;
    }

    let data_len = bytes.len().saturating_sub(offset);

    let _ = writeln!(
        log,
        "{{\"ts\":{},\"event\":\"chunk\",\"key\":{},\"ver\":{},\"first\":{},\"remaining\":{},\"data_len\":{},\"labels\":{},\"peer\":\"{}\"}}",
        now,
        message_key,
        header.version,
        if header.is_first { 1 } else { 0 },
        header.remaining,
        data_len,
        data_labels.len(),
        json_escape(&format_socket(peer))
    );
    let _ = log.flush();
    if cfg.pretty_stdout {
        let first_tag = if header.is_first {
            format!(" {}", style("[first]").cyan().bold())
        } else {
            String::new()
        };
        let last_tag = if header.remaining == 0 {
            format!(" {}", style("[last]").cyan().bold())
        } else {
            String::new()
        };
        let mbox_tag = match mailbox {
            Some(m) => format!(
                " mbox={}",
                style(format!("{:012X}", m & 0x0000_FFFF_FFFF_FFFF)).cyan()
            ),
            None => String::new(),
        };
        let sid_str = format!("key={}", style(format!("{:012X}", message_key)).yellow());
        println!(
            "{} {} ver={}{}{} rem={} data={} labels={}{} peer={}",
            style("[CHUNK]").green().bold(),
            sid_str,
            style(format!("{}", header.version)).blue(),
            first_tag,
            last_tag,
            style(format!("{}", header.remaining)).magenta(),
            style(format!("{}", data_len)).green(),
            style(format!("{}", data_labels.len())).dim(),
            mbox_tag,
            style(format_socket(peer)).magenta()
        );
    }

    if header.is_first && header.remaining == 0 {
        let data = match decompress_lzma_mem(&bytes[offset..], cfg.max_decompressed_bytes) {
            Ok(v) => v,
            Err(err) => {
                log_event(
                    log,
                    now,
                    "decompress_error",
                    &format!(
                        ",\"why\":\"{}\",\"err\":\"{}\"",
                        "single_no_session",
                        json_escape(&err)
                    ),
                );
                return;
            }
        };
        if cfg.accept_ascii_only && !data.iter().all(|b| *b < 0x80) {
            let sid = compute_message_key48(&data);
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"reject\",\"reason\":\"non_ascii\",\"key\":{},\"bytes\":{}}}",
                now,
                sid,
                data.len()
            );
            let _ = log.flush();
            if cfg.pretty_stdout {
                println!(
                    "{} reason=non_ascii key={} bytes={}",
                    style("[REJECT]").red().bold(),
                    sid,
                    data.len()
                );
            }
            return;
        }
        let sid = compute_message_key48(&data);
        let msg_id = compute_message_id(&data);
        if let Err(e) = db.execute(
            "INSERT OR IGNORE INTO messages (message_key, mailbox, data, received_at, message_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                sid as i64,
                mailbox.map(|m| format!("{:012x}", (m & 0x0000_FFFF_FFFF_FFFF))),
                &data,
                now as i64,
                &msg_id[..]
            ],
        ) {
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"db_error\",\"op\":\"insert_single\",\"err\":\"{}\"}}",
                now,
                json_escape(&e.to_string())
            );
        }
        log_event(
            log,
            now,
            "completed",
            &format!(
                ",\"sid\":{},\"rmax\":{},\"bytes\":{}",
                compute_message_key48(&data),
                0,
                data.len()
            ),
        );
        let _ = log.flush();
        return;
    }

    let sid = message_key;
    let sess = assemblies
        .entry(sid)
        .or_insert_with(|| crate::Assembly::new(now));
    sess.last_seen = now;
    if sess.completed {
        return;
    }
    if header.is_first {
        sess.rmax = Some(header.remaining);
        if mailbox.is_some() {
            sess.mailbox = mailbox;
        }
    }
    let data = bytes[offset..].to_vec();
    if let Some(prev) = sess.chunks.get(&header.remaining)
        && prev != &data
    {
        return;
    }
    sess.chunks.insert(header.remaining, data);
    sess.have_r.insert(header.remaining);
    if header.is_first {
        sess.recv_unique += 1;
    }

    if header.remaining == 0 {
        if let Some(rm) = sess.rmax {
            if (rm as usize + 1) != sess.have_r.len() {
                return;
            }
            let mut assembled: Vec<u8> = Vec::new();
            for r in (0..=rm).rev() {
                if let Some(chunk_data) = sess.chunks.get(&r) {
                    assembled.extend_from_slice(chunk_data);
                } else {
                    return;
                }
            }
            let data = match decompress_lzma_mem(&assembled, cfg.max_decompressed_bytes) {
                Ok(v) => v,
                Err(err) => {
                    log_event(
                        log,
                        now,
                        "decompress_error",
                        &format!(
                            ",\"why\":\"{}\",\"err\":\"{}\"",
                            "multi_completed",
                            json_escape(&err)
                        ),
                    );
                    return;
                }
            };
            if cfg.accept_ascii_only && !data.iter().all(|b| *b < 0x80) {
                let sid = compute_message_key48(&data);
                let _ = writeln!(
                    log,
                    "{{\"ts\":{},\"event\":\"reject\",\"reason\":\"non_ascii\",\"key\":{},\"bytes\":{}}}",
                    now,
                    sid,
                    data.len()
                );
                let _ = log.flush();
                if cfg.pretty_stdout {
                    println!(
                        "{} reason=non_ascii key={} bytes={}",
                        style("[REJECT]").red().bold(),
                        sid,
                        data.len()
                    );
                }
                return;
            }

            let msg_id = compute_message_id(&data);
            if let Err(e) = db.execute(
                "INSERT OR IGNORE INTO messages (message_key, mailbox, data, received_at, message_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    sid as i64,
                    sess.mailbox.map(|m| format!("{:012x}", (m & 0x0000_FFFF_FFFF_FFFF))),
                    &data,
                    now as i64,
                    &msg_id[..]
                ],
            ) {
                let _ = writeln!(
                    log,
                    "{{\"ts\":{},\"event\":\"db_error\",\"op\":\"insert_multi\",\"err\":\"{}\"}}",
                    now,
                    json_escape(&e.to_string())
                );
            }
            log_event(
                log,
                now,
                "completed",
                &format!(
                    ",\"sid\":{},\"rmax\":{},\"bytes\":{}",
                    message_key,
                    rm,
                    assembled.len()
                ),
            );
            sess.completed = true;
            let _ = log.flush();
        }
    } else if let Some(rm) = sess.rmax {
        let (missing, ranges) = summarize_missing(rm, &sess.have_r, 4);
        log_event(
            log,
            now,
            "assembly",
            &format!(
                ",\"sid\":{},\"rmax\":{},\"chunks\":{},\"missing\":{},\"ranges\":\"{}\"",
                message_key,
                rm,
                sess.have_r.len(),
                missing,
                json_escape(&ranges)
            ),
        );
    }
}

pub(crate) fn build_txt_rr_into(resp: &mut Vec<u8>, ttl: u32, data: &[u8]) {
    resp.extend_from_slice(&[0xC0, 0x0C]);
    write_u16(resp, 16);
    write_u16(resp, 1);
    resp.extend_from_slice(&ttl.to_be_bytes());

    let mut rdata: Vec<u8> = Vec::with_capacity(data.len() + (data.len() / 255) + 1);
    for chunk in data.chunks(255) {
        rdata.push(chunk.len() as u8);
        rdata.extend_from_slice(chunk);
    }
    write_u16(resp, rdata.len() as u16);
    resp.extend_from_slice(&rdata);
}

pub(crate) fn build_negative_nodata_with_soa(
    req: &[u8],
    req_hdr: DnsHeader,
    q_end: usize,
    zone_labels: &[String],
    neg_ttl: u32,
) -> Vec<u8> {
    let rd = req_hdr.flags & 0x0100;
    let qr = 0x8000;
    let aa = 0x0400;
    let opcode_bits = ((req_hdr.flags >> 11) & 0x0F) << 11;
    let flags = qr | opcode_bits | aa | rd;

    let mut resp = Vec::with_capacity(512);
    write_u16(&mut resp, req_hdr.id);
    write_u16(&mut resp, flags);
    write_u16(&mut resp, 1);
    let an_idx = resp.len();
    write_u16(&mut resp, 0);
    let ns_idx = resp.len();
    write_u16(&mut resp, 0);
    write_u16(&mut resp, 0);

    let qlen = q_end - DNS_HEADER_LEN;
    resp.extend_from_slice(&req[DNS_HEADER_LEN..DNS_HEADER_LEN + qlen]);
    build_soa_authority(&mut resp, zone_labels, neg_ttl);

    resp[an_idx] = 0;
    resp[an_idx + 1] = 0;
    resp[ns_idx] = 0;
    resp[ns_idx + 1] = 1;
    resp
}

pub(crate) fn summarize_missing(
    rmax: u16,
    have: &HashSet<u16>,
    max_ranges: usize,
) -> (u32, String) {
    let mut ranges: Vec<(u16, u16)> = Vec::new();
    let mut missing_count: u32 = 0;
    let mut cur_start: Option<u16> = None;
    for r in (0..=rmax).rev() {
        if have.contains(&r) {
            if let Some(s) = cur_start.take() {
                ranges.push((r + 1, s));
            }
        } else {
            missing_count += 1;
            if cur_start.is_none() {
                cur_start = Some(r);
            }
        }
    }
    if let Some(s) = cur_start.take() {
        ranges.push((0, s));
    }
    ranges.truncate(max_ranges);
    let s = if ranges.is_empty() {
        String::from("-")
    } else {
        ranges
            .into_iter()
            .map(|(a, b)| {
                if a == b {
                    format!("{}", a)
                } else {
                    format!("{}-{}", a, b)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    (missing_count, s)
}

pub(crate) fn gc_assemblies(
    assemblies: &mut HashMap<u64, crate::Assembly>,
    now: u128,
    max_age_ms: u128,
    log: &mut BufWriter<std::fs::File>,
    pretty: bool,
) {
    let to_remove: Vec<u64> = assemblies
        .iter()
        .filter_map(|(sid, s)| {
            if now.saturating_sub(s.last_seen) > max_age_ms {
                Some(*sid)
            } else {
                None
            }
        })
        .collect();
    for sid in to_remove {
        if let Some(sess) = assemblies.remove(&sid) {
            let miss = match sess.rmax {
                Some(rm) => (rm as u32 + 1).saturating_sub(sess.have_r.len() as u32),
                None => 0,
            };
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"assembly_gc\",\"key\":{},\"seen\":{},\"rmax\":{},\"missing\":{}}}",
                now,
                sid,
                sess.have_r.len(),
                sess.rmax.map(|v| v as u64).unwrap_or(0),
                miss
            );
            let _ = log.flush();
            if pretty {
                println!(
                    "{} {} key={} seen={} rmax={} missing={}",
                    style("[GC]").magenta().bold(),
                    style("assembly_gc").magenta().bold(),
                    sid,
                    sess.have_r.len(),
                    sess.rmax
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    miss
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_domain_ok() {
        assert_eq!(
            validate_and_sanitize_domain("example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            validate_and_sanitize_domain("example.com.").unwrap(),
            "example.com."
        );
        assert_eq!(
            validate_and_sanitize_domain("_sip._tcp.example.com").unwrap(),
            "_sip._tcp.example.com"
        );
    }

    #[test]
    fn domain_too_long_errors() {
        let s = format!("{}example.com", "a".repeat(300));
        let err = validate_and_sanitize_domain(&s).unwrap_err();
        assert!(err.contains("domain too long"));
    }

    #[test]
    fn label_too_long_errors() {
        let s = format!("{}.com", "a".repeat(64));
        let err = validate_and_sanitize_domain(&s).unwrap_err();
        assert!(err.contains("too long"));
    }

    #[test]
    fn invalid_char_in_label_errors() {
        let err = validate_and_sanitize_domain("inv@lid.example").unwrap_err();
        assert!(err.contains("invalid character") || err.contains("control character"));
    }

    #[test]
    fn hyphen_edges_error() {
        let err1 = validate_and_sanitize_domain("-abc.com").unwrap_err();
        let err2 = validate_and_sanitize_domain("abc-.com").unwrap_err();
        assert!(err1.contains("hyphen") && err2.contains("hyphen"));
    }

    #[test]
    fn empty_middle_label_errors_trailing_dot_ok() {
        let err = validate_and_sanitize_domain("a..b.com").unwrap_err();
        assert!(err.contains("empty label"));
        assert!(validate_and_sanitize_domain("example.com.").is_ok());
    }

    #[test]
    fn too_many_labels_errors() {
        // 128 one-character labels produce 255 bytes total (within length limit)
        let many = vec!["a"; 128].join(".");
        let err = validate_and_sanitize_domain(&many).unwrap_err();
        assert!(err.contains("too many labels"));
    }

    #[test]
    fn sanitize_replaces_controls_and_non_ascii_and_truncates() {
        let s = "evil\nname";
        let sanitized = sanitize_domain_for_logging(s);
        assert_eq!(sanitized, "evil?name");

        let s2 = "éxample.com"; // non-ASCII leading char
        let sanitized2 = sanitize_domain_for_logging(s2);
        assert!(sanitized2.starts_with('?'));
        assert!(sanitized2.ends_with("xample.com"));

        let long = "a".repeat(300);
        let truncated = sanitize_domain_for_logging(&long);
        assert_eq!(truncated.len(), 255);
    }
}
