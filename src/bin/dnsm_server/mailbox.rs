use crate::ServerCfg;
use crate::dns_handler::{build_negative_nodata_with_soa, build_txt_rr_into};
use dnsm::server_protocol::{
    DNS_HEADER_LEN, DnsHeader, parse_header, parse_question, read_u16, strip_zone, write_u16,
};
use dnsm::{
    compute_message_id, parse_hex_bytes_exact, to_hex_lower, to_lower_labels,
    validate_mailbox_hex12,
};
use rusqlite::{Connection, params};
use std::collections::HashSet;
use std::io::{BufWriter, Write};
use std::net::TcpStream;

const MAX_MAILBOX_MESSAGES: usize = 1_000;
const MAX_MAILBOX_SCAN_ROWS: usize = 4_000;
const MAX_MAILBOX_RESPONSE_BYTES: usize = 64 * 1024;

pub(crate) struct MailboxPage {
    pub(crate) messages: Vec<Vec<u8>>,
    pub(crate) truncated: bool,
}

pub(crate) fn prepare_message_with_id(msg_id: &[u8], data: &[u8]) -> Vec<u8> {
    let msg_hex = to_hex_lower(&msg_id[..msg_id.len().min(6)]);
    let mut combined = Vec::with_capacity(msg_hex.len() + 1 + data.len());
    combined.extend_from_slice(msg_hex.as_bytes());
    combined.push(b'\t');
    combined.extend_from_slice(data);
    combined
}

pub(crate) fn find_pivot_ts(
    db: &Connection,
    mb_hex: &str,
    mid_label: &str,
) -> rusqlite::Result<Option<i64>> {
    let mailbox_key = mb_hex.to_ascii_lowercase();
    if mid_label.len() == 32 {
        if let Some(mid_bytes) = parse_hex_bytes_exact(mid_label, 16) {
            if let Ok(mut stmt) = db.prepare(
                "SELECT received_at FROM messages WHERE mailbox=?1 AND message_id=?2 LIMIT 1",
            ) && let Ok(ts) = stmt.query_row(params![&mailbox_key, &mid_bytes], |row| {
                row.get::<_, Option<i64>>(0)
            }) && ts.is_some()
            {
                return Ok(ts);
            }
            if let Ok(mut stmt) = db.prepare(
                "SELECT data, received_at FROM messages WHERE mailbox=?1 ORDER BY received_at DESC, id DESC LIMIT 4000",
            ) && let Ok(iter) = stmt.query_map(params![&mailbox_key], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            }) {
                for r in iter.flatten() {
                    let (data, tsv) = r;
                    let mid = compute_message_id(&data);
                    if mid_bytes.as_slice() == mid.as_slice() {
                        return Ok(Some(tsv));
                    }
                }
            }
        }
        return Ok(None);
    }
    if mid_label.len() == 12 {
        if let Some(prefix6) = parse_hex_bytes_exact(mid_label, 6) {
            let token = to_hex_lower(&prefix6);
            if let Ok(mut stmt) = db.prepare(
                "SELECT received_at FROM messages WHERE mailbox=?1 AND substr(hex(message_id),1,12)=upper(?2) LIMIT 1",
            )
                && let Ok(ts) = stmt.query_row(params![&mailbox_key, &token], |row| {
                    row.get::<_, Option<i64>>(0)
                })
                    && ts.is_some() {
                        return Ok(ts);
                    }
            if let Ok(mut stmt) = db.prepare(
                "SELECT data, received_at FROM messages WHERE mailbox=?1 ORDER BY received_at DESC, id DESC LIMIT 4000",
            ) && let Ok(iter) = stmt.query_map(params![&mailbox_key], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            }) {
                for r in iter.flatten() {
                    let (data, tsv) = r;
                    let mid = compute_message_id(&data);
                    if to_hex_lower(&mid[..mid.len().min(6)]) == token {
                        return Ok(Some(tsv));
                    }
                }
            }
        }
        return Ok(None);
    }
    Ok(None)
}

pub(crate) fn collect_distinct_mailbox_messages(
    db: &Connection,
    mb_hex: &str,
    pivot_ts: Option<i64>,
) -> rusqlite::Result<MailboxPage> {
    collect_distinct_mailbox_messages_with_limits(
        db,
        mb_hex,
        pivot_ts,
        MAX_MAILBOX_MESSAGES,
        MAX_MAILBOX_SCAN_ROWS,
        MAX_MAILBOX_RESPONSE_BYTES,
    )
}

fn collect_distinct_mailbox_messages_with_limits(
    db: &Connection,
    mb_hex: &str,
    pivot_ts: Option<i64>,
    max_messages: usize,
    max_scan_rows: usize,
    max_bytes: usize,
) -> rusqlite::Result<MailboxPage> {
    let mailbox_key = mb_hex.to_ascii_lowercase();
    let mut rows_sql = String::from(
        "SELECT data, message_id FROM messages WHERE mailbox = ?1 AND (message_type IS NULL OR message_type = 'message')",
    );
    if pivot_ts.is_some() {
        rows_sql.push_str(" AND received_at < ?2");
    }
    rows_sql.push_str(" ORDER BY received_at DESC, id DESC");

    let mut messages = Vec::new();
    let mut seen_ids: HashSet<Vec<u8>> = HashSet::new();
    let mut scanned_rows = 0usize;
    let mut used_bytes = 0usize;
    let mut truncated = false;
    let mut stmt = db.prepare(&rows_sql)?;

    let mut consume_row = |data: Vec<u8>, mid: Option<Vec<u8>>| {
        scanned_rows = scanned_rows.saturating_add(1);
        if scanned_rows > max_scan_rows {
            truncated = true;
            return false;
        }

        let message_id = mid.unwrap_or_else(|| compute_message_id(&data).to_vec());
        if !seen_ids.insert(message_id.clone()) {
            return true;
        }
        if messages.len() >= max_messages {
            truncated = true;
            return false;
        }

        let prefix_bytes = message_id.len().min(6) * 2 + 1;
        let remaining = max_bytes.saturating_sub(used_bytes);
        if remaining <= prefix_bytes {
            truncated = true;
            return false;
        }
        let take = data.len().min(remaining - prefix_bytes);
        let prepared = prepare_message_with_id(&message_id, &data[..take]);
        used_bytes = used_bytes.saturating_add(prepared.len());
        messages.push(prepared);
        if take < data.len() {
            truncated = true;
            return false;
        }
        true
    };

    if let Some(pivot) = pivot_ts {
        let rows = stmt.query_map(params![&mailbox_key, pivot], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
        })?;
        for row in rows {
            let (data, mid) = row?;
            if !consume_row(data, mid) {
                break;
            }
        }
    } else {
        let rows = stmt.query_map(params![&mailbox_key], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
        })?;
        for row in rows {
            let (data, mid) = row?;
            if !consume_row(data, mid) {
                break;
            }
        }
    }

    Ok(MailboxPage {
        messages,
        truncated,
    })
}

pub(crate) fn build_mailbox_txt_response(
    req: &[u8],
    req_hdr: DnsHeader,
    q_end: usize,
    ttl: u32,
    msgs: &[Vec<u8>],
    budget: usize,
    more_available: bool,
) -> Vec<u8> {
    let rd = req_hdr.flags & 0x0100;
    let qr = 0x8000;
    let aa = 0x0400;
    let opcode_bits = ((req_hdr.flags >> 11) & 0x0F) << 11;
    let flags = qr | opcode_bits | aa | rd;

    let mut resp = Vec::with_capacity(512);
    write_u16(&mut resp, req_hdr.id);
    let flags_idx = resp.len();
    write_u16(&mut resp, flags);
    write_u16(&mut resp, 1);
    let an_idx = resp.len();
    write_u16(&mut resp, 0);
    write_u16(&mut resp, 0);
    write_u16(&mut resp, 0);

    let qlen = q_end - DNS_HEADER_LEN;
    resp.extend_from_slice(&req[DNS_HEADER_LEN..DNS_HEADER_LEN + qlen]);

    let mut an_count: u16 = 0;
    for m in msgs {
        if resp.len() + 11 + m.len() + (m.len() / 255) + 1 > budget {
            break;
        }
        build_txt_rr_into(&mut resp, ttl, m);
        an_count = an_count.saturating_add(1);
    }

    let mut force_tc = false;
    if an_count == 0 && !msgs.is_empty() {
        let m = &msgs[0];
        let available = budget.saturating_sub(resp.len().saturating_add(13));
        let take = m.len().min(200).min(available);
        if take > 0 {
            build_txt_rr_into(&mut resp, ttl, &m[..take]);
            an_count = 1;
        }
        if take < m.len() {
            force_tc = true;
        }
    }

    resp[an_idx] = ((an_count >> 8) & 0xFF) as u8;
    resp[an_idx + 1] = (an_count & 0xFF) as u8;

    if force_tc || more_available || (an_count as usize) < msgs.len() {
        let cur = read_u16(&resp[flags_idx..flags_idx + 2]);
        let with_tc = cur | 0x0200;
        resp[flags_idx] = ((with_tc >> 8) & 0xFF) as u8;
        resp[flags_idx + 1] = (with_tc & 0xFF) as u8;
    }
    resp
}

#[allow(clippy::manual_range_contains, clippy::collapsible_if)]
pub(crate) fn handle_tcp_mailbox_conn(
    stream: &mut TcpStream,
    cfg: &ServerCfg,
    db: &Connection,
) -> std::io::Result<()> {
    use std::io::{Read, Write};

    let mut lenbuf = [0u8; 2];
    stream.read_exact(&mut lenbuf)?;
    let qlen = u16::from_be_bytes(lenbuf) as usize;
    if qlen < DNS_HEADER_LEN || qlen > 4096 {
        return Ok(());
    }
    let mut req = vec![0u8; qlen];
    stream.read_exact(&mut req)?;

    let hdr = match parse_header(&req) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };
    let (domain, q_end, qtype, qclass) = match parse_question(&req) {
        Ok((d, off, t, c)) => (d, off, t, c),
        Err(_) => return Ok(()),
    };
    if qtype != 16 || qclass != 1 {
        return Ok(());
    }

    let labels = to_lower_labels(&domain);
    let mailbox_labels = match strip_zone(&labels, &cfg.mailbox_zone_labels) {
        Some(v) => v,
        None => return Ok(()),
    };
    let (maybe_mid_hex, maybe_mbox) = match mailbox_labels.len() {
        1 => (None, validate_mailbox_hex12(&mailbox_labels[0])),
        2 => (
            Some(mailbox_labels[0].clone()),
            validate_mailbox_hex12(&mailbox_labels[1]),
        ),
        _ => (None, None),
    };
    if let Some(mb_hex) = maybe_mbox {
        let mut pivot_ts: Option<i64> = None;
        if let Some(mid_label) = maybe_mid_hex.as_ref() {
            if let Ok(ts_opt) = find_pivot_ts(db, &mb_hex, mid_label) {
                pivot_ts = ts_opt;
            }
        }
        let page =
            collect_distinct_mailbox_messages(db, &mb_hex, pivot_ts).unwrap_or(MailboxPage {
                messages: Vec::new(),
                truncated: false,
            });

        let zone = cfg.mailbox_zone_labels.as_ref().unwrap();
        let mut resp = if page.messages.is_empty() {
            build_negative_nodata_with_soa(&req, hdr, q_end, zone, cfg.neg_ttl)
        } else {
            build_mailbox_txt_response(
                &req,
                hdr,
                q_end,
                cfg.ans_ttl,
                &page.messages,
                32 * 1024,
                page.truncated,
            )
        };
        if crate::dns_handler::has_edns(&req, q_end) {
            crate::dns_handler::append_opt(&mut resp, 512);
        }
        if !cfg.no_response {
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            stream.write_all(&out)?;
        }
    }
    Ok(())
}

pub(crate) fn log_mailbox_query(
    log: &mut BufWriter<std::fs::File>,
    ts: u128,
    mb_hex: &str,
    msgs_found: usize,
    answers_included: u16,
    pivot_ts: Option<i64>,
) {
    let _ = writeln!(
        log,
        "{{\"ts\":{},\"event\":\"mailbox_query\",\"mailbox\":\"{}\",\"found\":{},\"included\":{},\"paged_before\":{}}}",
        ts,
        mb_hex,
        msgs_found,
        answers_included,
        pivot_ts
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".into())
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_key INTEGER NOT NULL,
                mailbox TEXT,
                data BLOB NOT NULL,
                received_at INTEGER NOT NULL,
                message_id BLOB,
                message_type TEXT DEFAULT 'message'
            );",
        )
        .unwrap();
        db
    }

    #[test]
    fn mailbox_collection_stops_at_byte_budget() {
        let db = init_db();
        let mailbox = "000000000042";
        for (id, data) in [b"newest".as_slice(), b"older".as_slice()]
            .into_iter()
            .enumerate()
        {
            db.execute(
                "INSERT INTO messages (message_key, mailbox, data, received_at, message_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id as i64 + 1,
                    mailbox,
                    data,
                    id as i64 + 1,
                    compute_message_id(data).as_slice(),
                ],
            )
            .unwrap();
        }

        let page = collect_distinct_mailbox_messages_with_limits(
            &db,
            mailbox,
            None,
            10,
            10,
            13 + b"older".len(),
        )
        .unwrap();

        assert_eq!(page.messages.len(), 1);
        assert!(page.truncated);
        assert!(page.messages[0].ends_with(b"older"));
    }
}
