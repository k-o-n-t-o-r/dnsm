use console::style;
use dnsm::server_protocol::{CarrierDecodeError, DecodedCarrier};
pub(crate) use dnsm::server_protocol::{
    DNS_HEADER_LEN, DnsHeader, append_opt, has_edns, parse_header, parse_question, read_u16,
    sanitize_domain_for_logging, strip_zone, validate_and_sanitize_domain, write_u16,
};
use dnsm::{PROTOCOL_VERSION, compute_message_id, compute_message_key48, compute_message_key48_v3};
use rusqlite::{Connection, params};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::io::{BufWriter, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

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

pub(crate) fn format_ts_utc(ms: u128) -> String {
    let total_secs = (ms / 1000) as i64;
    let millis = (ms % 1000) as u32;
    let days = total_secs.div_euclid(86_400);
    let secs_in_day = total_secs.rem_euclid(86_400);
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;
    // civil_from_days (Howard Hinnant, "date" algorithms, public domain)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        year, month, d, h, m, s, millis
    )
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

pub(crate) fn format_socket(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

fn decompress_lzma_mem(input: &[u8], max_bytes: u32) -> Result<Vec<u8>, String> {
    // new_mem_limit takes KiB; cap decoder memory (dict + state) independently
    // of output size. 40MB allows dict sizes up to ~32MB which covers all
    // standard LZMA presets; max_bytes separately caps output.
    const DECODER_MEM_LIMIT_KB: u32 = 40 * 1024;
    let mem_limit_kb = if max_bytes == 0 {
        u32::MAX
    } else {
        DECODER_MEM_LIMIT_KB
    };
    let mut reader = lzma_rust2::LzmaReader::new_mem_limit(Cursor::new(input), mem_limit_kb, None)
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

            total_read = total_read.checked_add(n as u32).ok_or_else(error_message)?;

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

fn chunk_fits_limits(
    assembly_bytes: usize,
    assembly_chunks: usize,
    total_assembly_bytes: usize,
    total_assembly_chunks: usize,
    chunk_bytes: usize,
    cfg: &crate::ServerCfg,
) -> bool {
    assembly_chunks < cfg.max_assembly_chunks
        && total_assembly_chunks < cfg.max_total_assembly_chunks
        && assembly_bytes.saturating_add(chunk_bytes) <= cfg.max_assembly_bytes
        && total_assembly_bytes.saturating_add(chunk_bytes) <= cfg.max_total_assembly_bytes
}

fn release_assembly_storage(
    assembly: &mut crate::Assembly,
    total_assembly_chunks: &mut usize,
    total_assembly_bytes: &mut usize,
) {
    *total_assembly_chunks = total_assembly_chunks.saturating_sub(assembly.chunks.len());
    *total_assembly_bytes = total_assembly_bytes.saturating_sub(assembly.stored_bytes);
    assembly.chunks.clear();
    assembly.have_r.clear();
    assembly.stored_bytes = 0;
}

fn remove_assembly(
    assemblies: &mut HashMap<u64, crate::Assembly>,
    total_assembly_chunks: &mut usize,
    total_assembly_bytes: &mut usize,
    sid: u64,
) -> Option<crate::Assembly> {
    let assembly = assemblies.remove(&sid)?;
    *total_assembly_chunks = total_assembly_chunks.saturating_sub(assembly.chunks.len());
    *total_assembly_bytes = total_assembly_bytes.saturating_sub(assembly.stored_bytes);
    Some(assembly)
}

fn finish_assembly(
    assembly: &mut crate::Assembly,
    total_assembly_chunks: &mut usize,
    total_assembly_bytes: &mut usize,
) {
    assembly.completed = true;
    release_assembly_storage(assembly, total_assembly_chunks, total_assembly_bytes);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn try_handle_dnsm(
    full_domain: &str,
    decoded: &Result<DecodedCarrier, CarrierDecodeError>,
    cfg: &crate::ServerCfg,
    assemblies: &mut HashMap<u64, crate::Assembly>,
    total_assembly_chunks: &mut usize,
    total_assembly_bytes: &mut usize,
    now: u128,
    log: &mut BufWriter<std::fs::File>,
    peer: SocketAddr,
    db: &Connection,
    qtype: u16,
) {
    let decoded = match decoded {
        Ok(decoded) => decoded,
        Err(CarrierDecodeError::OutsideZone) => return,
        Err(CarrierDecodeError::InvalidLabel { index, label }) => {
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"parse_error\",\"label_index\":{},\"label\":\"{}\",\"domain\":\"{}\",\"peer\":\"{}\"}}",
                now,
                index,
                json_escape(label),
                json_escape(full_domain),
                json_escape(&format_socket(peer))
            );
            let _ = log.flush();
            if cfg.pretty_stdout {
                println!(
                    "{}",
                    style(format!(
                        "[ERR] parse_error label#{} '{}' domain={} peer={}",
                        index,
                        label,
                        full_domain,
                        format_socket(peer)
                    ))
                    .red()
                    .bold()
                );
            }
            return;
        }
        Err(error) => {
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"decode_error\",\"reason\":\"{}\",\"domain\":\"{}\",\"peer\":\"{}\"}}",
                now,
                error.code(),
                json_escape(full_domain),
                json_escape(&format_socket(peer))
            );
            let _ = log.flush();
            if cfg.pretty_stdout {
                println!(
                    "{}",
                    style(format!(
                        "[ERR] decode_error {} domain={} peer={}",
                        error.code(),
                        full_domain,
                        format_socket(peer)
                    ))
                    .red()
                );
            }
            return;
        }
    };

    let bytes = &decoded.bytes;
    let header = decoded.header;
    if header.version != PROTOCOL_VERSION {
        return;
    }
    let offset = decoded.payload_offset;
    let mailbox = decoded.mailbox;
    let message_key = decoded.message_key.unwrap_or(0);

    // --- Ping handling ---
    if header.is_ping {
        let mbox = mailbox.expect("carrier decoder validates ping mailbox");
        let mbox_hex = format!("{:012x}", mbox);
        let mailbox_bytes = mbox.to_be_bytes();

        // Compute ping-specific message_id: BLAKE3("ping" || mailbox || peer_ip || now_ms)
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ping");
        hasher.update(&mailbox_bytes[2..8]);
        hasher.update(peer.ip().to_string().as_bytes());
        hasher.update(&(now as u64).to_be_bytes());
        let hash = hasher.finalize();
        let msg_id: [u8; 16] = hash.as_bytes()[..16].try_into().unwrap();

        if let Err(e) = db.execute(
            "INSERT OR IGNORE INTO messages (message_key, mailbox, data, received_at, message_id, peer_ip, message_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                0i64,
                &mbox_hex,
                &[] as &[u8],
                now as i64,
                &msg_id[..],
                peer.ip().to_string(),
                "ping",
            ],
        ) {
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"db_error\",\"op\":\"insert_ping\",\"err\":\"{}\"}}",
                now,
                json_escape(&e.to_string())
            );
            if cfg.pretty_stdout {
                println!(
                    "{} {} op=insert_ping err={}",
                    style("[ERR] db_error").red().bold(),
                    style(format!("[{}]", format_ts_utc(now))).dim(),
                    e
                );
            }
        }
        let _ = writeln!(
            log,
            "{{\"ts\":{},\"event\":\"ping\",\"mailbox\":\"{}\",\"peer\":\"{}\"}}",
            now,
            mbox_hex,
            json_escape(&format_socket(peer))
        );
        let _ = log.flush();
        if cfg.pretty_stdout {
            println!(
                "{} {} mbox={} peer={}",
                style("[PING]").magenta().bold(),
                style(format!("[{}]", format_ts_utc(now))).dim(),
                style(&mbox_hex).cyan(),
                style(format_socket(peer)).magenta()
            );
        }
        return;
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
        decoded.data_labels,
        json_escape(&format_socket(peer))
    );
    let _ = log.flush();
    if cfg.pretty_stdout {
        let first_tag = if header.is_first {
            format!(" {}", style("[first]").cyan().bold())
        } else {
            String::new()
        };
        let last_tag = if header.remaining == 0 && !header.chunked {
            format!(" {}", style("[single]").cyan().bold())
        } else if header.remaining == 0 {
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
        let qtype_str = match qtype {
            1 => "A".into(),
            28 => "AAAA".into(),
            _ => format!("{}", qtype),
        };
        println!(
            "{} {} {} ver={}{}{} rem={} data={} labels={}{} peer={} qt={}",
            style("[CHUNK]").green().bold(),
            style(format!("[{}]", format_ts_utc(now))).dim(),
            sid_str,
            style(format!("{}", header.version)).blue(),
            first_tag,
            last_tag,
            style(format!("{}", header.remaining)).magenta(),
            style(format!("{}", data_len)).green(),
            style(format!("{}", decoded.data_labels)).dim(),
            mbox_tag,
            style(format_socket(peer)).magenta(),
            style(qtype_str).dim()
        );
    }

    // --- Single-chunk message ---
    if !header.chunked {
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
                if cfg.pretty_stdout {
                    println!(
                        "{} {} why=single err={}",
                        style("[ERR] decompress_error").red().bold(),
                        style(format!("[{}]", format_ts_utc(now))).dim(),
                        err
                    );
                }
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
                    "{} {} reason=non_ascii key={} bytes={}",
                    style("[REJECT]").red().bold(),
                    style(format!("[{}]", format_ts_utc(now))).dim(),
                    sid,
                    data.len()
                );
            }
            return;
        }
        let sid = compute_message_key48(&data);
        let msg_id = compute_message_id(&data);
        let mut insert_ok = true;
        if let Err(e) = db.execute(
            "INSERT OR IGNORE INTO messages (message_key, mailbox, data, received_at, message_id, peer_ip, message_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                sid as i64,
                mailbox.map(|m| format!("{:012x}", (m & 0x0000_FFFF_FFFF_FFFF))),
                &data,
                now as i64,
                &msg_id[..],
                peer.ip().to_string(),
                "message",
            ],
        ) {
            insert_ok = false;
            let _ = writeln!(
                log,
                "{{\"ts\":{},\"event\":\"db_error\",\"op\":\"insert_single\",\"err\":\"{}\"}}",
                now,
                json_escape(&e.to_string())
            );
            if cfg.pretty_stdout {
                println!(
                    "{} {} op=insert_single err={}",
                    style("[ERR] db_error").red().bold(),
                    style(format!("[{}]", format_ts_utc(now))).dim(),
                    e
                );
            }
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
        if insert_ok && cfg.pretty_stdout {
            let mbox_tag = match mailbox {
                Some(m) => format!(
                    " mbox={}",
                    style(format!("{:012X}", m & 0x0000_FFFF_FFFF_FFFF)).cyan()
                ),
                None => String::new(),
            };
            println!(
                "{} {} key={} chunks=1 bytes={}{} peer={}",
                style("[MSG]").green().bold(),
                style(format!("[{}]", format_ts_utc(now))).dim(),
                style(format!("{:012X}", sid & 0x0000_FFFF_FFFF_FFFF)).yellow(),
                style(format!("{}", data.len())).green(),
                mbox_tag,
                style(format_socket(peer)).magenta()
            );
        }
        return;
    }

    let sid = message_key;

    if header.is_first && usize::from(header.remaining) + 1 > cfg.max_assembly_chunks {
        return;
    }

    if !assemblies.contains_key(&sid)
        && assemblies.len() >= cfg.max_assemblies
        && let Some((&oldest_sid, _)) = assemblies
            .iter()
            .min_by_key(|(_, assembly)| assembly.last_seen)
    {
        remove_assembly(
            assemblies,
            total_assembly_chunks,
            total_assembly_bytes,
            oldest_sid,
        );
    }

    let sess = assemblies
        .entry(sid)
        .or_insert_with(|| crate::Assembly::new(now));
    sess.last_seen = now;
    if sess.completed {
        if header.is_first && mailbox != sess.mailbox {
            release_assembly_storage(sess, total_assembly_chunks, total_assembly_bytes);
            *sess = crate::Assembly::new(now);
        } else {
            return;
        }
    }
    if header.is_first {
        if let Some(existing_rmax) = sess.rmax {
            if existing_rmax != header.remaining || mailbox != sess.mailbox {
                return;
            }
        } else {
            sess.rmax = Some(header.remaining);
            sess.mailbox = mailbox;
        }

        let mut removed_chunks = 0usize;
        let mut removed_bytes = 0usize;
        sess.chunks.retain(|&r, data| {
            let keep = r <= header.remaining;
            if !keep {
                removed_chunks = removed_chunks.saturating_add(1);
                removed_bytes = removed_bytes.saturating_add(data.len());
            }
            keep
        });
        sess.have_r.retain(|&r| r <= header.remaining);
        sess.stored_bytes = sess.stored_bytes.saturating_sub(removed_bytes);
        *total_assembly_chunks = total_assembly_chunks.saturating_sub(removed_chunks);
        *total_assembly_bytes = total_assembly_bytes.saturating_sub(removed_bytes);
    }
    if let Some(rm) = sess.rmax {
        if header.remaining > rm {
            return;
        }
    } else if sess.chunks.len() >= 1024.min(cfg.max_assembly_chunks) {
        return;
    }

    let chunk_data = &bytes[offset..];
    if let Some(previous) = sess.chunks.get(&header.remaining) {
        if previous.as_slice() != chunk_data {
            return;
        }
    } else {
        if !chunk_fits_limits(
            sess.stored_bytes,
            sess.chunks.len(),
            *total_assembly_bytes,
            *total_assembly_chunks,
            chunk_data.len(),
            cfg,
        ) {
            return;
        }
        sess.chunks.insert(header.remaining, chunk_data.to_vec());
        sess.stored_bytes = sess.stored_bytes.saturating_add(chunk_data.len());
        *total_assembly_chunks = total_assembly_chunks.saturating_add(1);
        *total_assembly_bytes = total_assembly_bytes.saturating_add(chunk_data.len());
    }
    sess.have_r.insert(header.remaining);

    if let Some(rm) = sess.rmax {
        if (rm as usize + 1) == sess.have_r.len() {
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
                    if cfg.pretty_stdout {
                        println!(
                            "{} {} key={:012X} why=multi err={}",
                            style("[ERR] decompress_error").red().bold(),
                            style(format!("[{}]", format_ts_utc(now))).dim(),
                            message_key,
                            err
                        );
                    }
                    finish_assembly(sess, total_assembly_chunks, total_assembly_bytes);
                    return;
                }
            };
            let expected_key = compute_message_key48_v3(&data, sess.mailbox);
            if expected_key != sid {
                let _ = writeln!(
                    log,
                    "{{\"ts\":{},\"event\":\"reject\",\"reason\":\"message_key_mismatch\",\"key\":{},\"expected\":{}}}",
                    now, sid, expected_key
                );
                let _ = log.flush();
                if cfg.pretty_stdout {
                    println!(
                        "{} {} reason=message_key_mismatch key={} expected={}",
                        style("[REJECT]").red().bold(),
                        style(format!("[{}]", format_ts_utc(now))).dim(),
                        sid,
                        expected_key
                    );
                }
                finish_assembly(sess, total_assembly_chunks, total_assembly_bytes);
                return;
            }
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
                        "{} {} reason=non_ascii key={} bytes={}",
                        style("[REJECT]").red().bold(),
                        style(format!("[{}]", format_ts_utc(now))).dim(),
                        sid,
                        data.len()
                    );
                }
                finish_assembly(sess, total_assembly_chunks, total_assembly_bytes);
                return;
            }

            let msg_id = compute_message_id(&data);
            let mut insert_ok = true;
            if let Err(e) = db.execute(
                "INSERT OR IGNORE INTO messages (message_key, mailbox, data, received_at, message_id, peer_ip, message_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    sid as i64,
                    sess.mailbox.map(|m| format!("{:012x}", (m & 0x0000_FFFF_FFFF_FFFF))),
                    &data,
                    now as i64,
                    &msg_id[..],
                    peer.ip().to_string(),
                    "message",
                ],
            ) {
                insert_ok = false;
                let _ = writeln!(
                    log,
                    "{{\"ts\":{},\"event\":\"db_error\",\"op\":\"insert_multi\",\"err\":\"{}\"}}",
                    now,
                    json_escape(&e.to_string())
                );
                if cfg.pretty_stdout {
                    println!(
                        "{} {} op=insert_multi key={:012X} err={}",
                        style("[ERR] db_error").red().bold(),
                        style(format!("[{}]", format_ts_utc(now))).dim(),
                        message_key,
                        e
                    );
                }
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
            finish_assembly(sess, total_assembly_chunks, total_assembly_bytes);
            let _ = log.flush();
            if insert_ok && cfg.pretty_stdout {
                let mbox_tag = match sess.mailbox {
                    Some(m) => format!(
                        " mbox={}",
                        style(format!("{:012X}", m & 0x0000_FFFF_FFFF_FFFF)).cyan()
                    ),
                    None => String::new(),
                };
                println!(
                    "{} {} key={} chunks={} bytes={}{} peer={}",
                    style("[MSG]").green().bold(),
                    style(format!("[{}]", format_ts_utc(now))).dim(),
                    style(format!("{:012X}", message_key & 0x0000_FFFF_FFFF_FFFF)).yellow(),
                    style(format!("{}", (rm as u32) + 1)).green(),
                    style(format!("{}", data.len())).green(),
                    mbox_tag,
                    style(format_socket(peer)).magenta()
                );
            }
        } else {
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
    total_assembly_chunks: &mut usize,
    total_assembly_bytes: &mut usize,
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
        if let Some(sess) =
            remove_assembly(assemblies, total_assembly_chunks, total_assembly_bytes, sid)
        {
            let miss = if sess.completed {
                0
            } else {
                match sess.rmax {
                    Some(rm) => (rm as u32 + 1).saturating_sub(sess.have_r.len() as u32),
                    None => 0,
                }
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
                    "{} {} {} key={} seen={} rmax={} missing={}",
                    style("[GC]").magenta().bold(),
                    style(format!("[{}]", format_ts_utc(now))).dim(),
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

    fn test_cfg() -> crate::ServerCfg {
        crate::ServerCfg {
            zone_labels: None,
            mailbox_zone_labels: None,
            ans_ttl: 0,
            neg_ttl: 0,
            pretty_stdout: false,
            accept_ascii_only: false,
            no_response: false,
            max_decompressed_bytes: 1024 * 1024,
            rate_limit_qps: None,
            max_assemblies: 10,
            max_assembly_chunks: 4,
            max_total_assembly_chunks: 6,
            max_assembly_bytes: 100,
            max_total_assembly_bytes: 150,
        }
    }

    #[test]
    fn decompression_accepts_standard_lzma_and_enforces_output_limit() {
        use lzma_rust2::{LzmaOptions, LzmaWriter};

        let payload = vec![b'a'; 4096];
        let mut writer = LzmaWriter::new_use_header(
            Vec::new(),
            &LzmaOptions::default(),
            Some(payload.len() as u64),
        )
        .unwrap();
        writer.write_all(&payload).unwrap();
        let compressed = writer.finish().unwrap();

        assert_eq!(decompress_lzma_mem(&compressed, 8192).unwrap(), payload);
        assert!(decompress_lzma_mem(&compressed, 1024).is_err());
    }

    #[test]
    fn chunk_limits_bound_per_assembly_and_global_storage() {
        let cfg = test_cfg();
        assert!(chunk_fits_limits(50, 2, 75, 3, 25, &cfg));
        assert!(!chunk_fits_limits(50, 4, 75, 3, 1, &cfg));
        assert!(!chunk_fits_limits(50, 2, 75, 6, 1, &cfg));
        assert!(!chunk_fits_limits(90, 2, 90, 3, 11, &cfg));
        assert!(!chunk_fits_limits(50, 2, 140, 3, 11, &cfg));
    }

    #[test]
    fn releasing_an_assembly_updates_global_storage_accounting() {
        let mut assembly = crate::Assembly::new(0);
        assembly.chunks.insert(0, vec![1; 25]);
        assembly.have_r.insert(0);
        assembly.stored_bytes = 25;
        let mut total_chunks = 1;
        let mut total_bytes = 25;

        release_assembly_storage(&mut assembly, &mut total_chunks, &mut total_bytes);

        assert_eq!(total_chunks, 0);
        assert_eq!(total_bytes, 0);
        assert_eq!(assembly.stored_bytes, 0);
        assert!(assembly.chunks.is_empty());
        assert!(assembly.have_r.is_empty());
    }

    #[test]
    fn format_ts_utc_known_values() {
        assert_eq!(format_ts_utc(0), "1970-01-01 00:00:00.000");
        // 2026-04-22 20:58:12.345 UTC = 1776891492345 ms
        assert_eq!(format_ts_utc(1_776_891_492_345), "2026-04-22 20:58:12.345");
        // Leap year boundary
        assert_eq!(format_ts_utc(1_582_934_400_000), "2020-02-29 00:00:00.000");
    }

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

    fn build_query_with_opt(domain: &str) -> (Vec<u8>, usize) {
        let mut pkt = Vec::new();
        write_u16(&mut pkt, 0xABCD); // ID
        write_u16(&mut pkt, 0x0100); // flags: RD
        write_u16(&mut pkt, 1); // QDCOUNT
        write_u16(&mut pkt, 0); // ANCOUNT
        write_u16(&mut pkt, 0); // NSCOUNT
        write_u16(&mut pkt, 1); // ARCOUNT = 1 (OPT)
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        write_u16(&mut pkt, 1); // QTYPE = A
        write_u16(&mut pkt, 1); // QCLASS = IN
        let q_end = pkt.len();
        // OPT pseudo-record
        pkt.push(0x00); // NAME = root
        write_u16(&mut pkt, 41); // TYPE = OPT
        write_u16(&mut pkt, 4096); // CLASS = UDP payload size
        pkt.extend_from_slice(&[0, 0, 0, 0]); // TTL
        write_u16(&mut pkt, 0); // RDLENGTH
        (pkt, q_end)
    }

    #[test]
    fn has_edns_detects_opt_record() {
        let (pkt, q_end) = build_query_with_opt("foo.example");
        assert!(has_edns(&pkt, q_end));
    }

    #[test]
    fn has_edns_false_without_opt() {
        let mut pkt = Vec::new();
        write_u16(&mut pkt, 0xABCD);
        write_u16(&mut pkt, 0x0100);
        write_u16(&mut pkt, 1);
        write_u16(&mut pkt, 0);
        write_u16(&mut pkt, 0);
        write_u16(&mut pkt, 0); // ARCOUNT = 0
        pkt.extend_from_slice(&[
            3, b'f', b'o', b'o', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ]);
        write_u16(&mut pkt, 1);
        write_u16(&mut pkt, 1);
        let q_end = pkt.len();
        assert!(!has_edns(&pkt, q_end));
    }

    #[test]
    fn has_edns_false_on_short_packet() {
        assert!(!has_edns(&[0; 4], 4));
    }

    #[test]
    fn append_opt_sets_arcount_and_type41() {
        let mut resp = Vec::new();
        // Minimal header
        write_u16(&mut resp, 0xABCD);
        write_u16(&mut resp, 0x8180);
        write_u16(&mut resp, 1);
        write_u16(&mut resp, 0);
        write_u16(&mut resp, 0);
        write_u16(&mut resp, 0); // ARCOUNT = 0
        let before_len = resp.len();
        append_opt(&mut resp, 512);
        assert_eq!(read_u16(&resp[10..12]), 1); // ARCOUNT bumped to 1
        // OPT record: 0x00 (name) + TYPE=41 + CLASS=512 + TTL(4) + RDLEN=0 = 11 bytes
        assert_eq!(resp.len() - before_len, 11);
        assert_eq!(resp[before_len], 0x00); // root name
        assert_eq!(read_u16(&resp[before_len + 1..before_len + 3]), 41);
        assert_eq!(read_u16(&resp[before_len + 3..before_len + 5]), 512);
    }

    #[test]
    fn append_opt_increments_existing_arcount() {
        let mut resp = Vec::new();
        write_u16(&mut resp, 0x0001);
        write_u16(&mut resp, 0x8180);
        write_u16(&mut resp, 0);
        write_u16(&mut resp, 0);
        write_u16(&mut resp, 0);
        write_u16(&mut resp, 3); // ARCOUNT = 3
        append_opt(&mut resp, 512);
        assert_eq!(read_u16(&resp[10..12]), 4);
    }
}
