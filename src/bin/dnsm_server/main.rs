use clap::Parser;
use console::style;
use dnsm::{
    CHUNK_HEADER_LEN, ChunkHeader, base32_nopad_decode, to_lower_labels, validate_mailbox_hex12,
    validate_zone_and_labels,
};
use rusqlite::{Connection, params};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

mod dns_handler;
mod mailbox;
mod storage;

#[derive(Clone, Debug)]
pub(crate) struct ServerCfg {
    zone_labels: Option<Vec<String>>,
    mailbox_zone_labels: Option<Vec<String>>,
    #[allow(dead_code)]
    progress_every: Option<u32>,
    ans_ttl: u32,
    neg_ttl: u32,
    pretty_stdout: bool,
    accept_ascii_only: bool,
    no_response: bool,
    max_decompressed_bytes: u32,
    rate_limit_qps: Option<u32>,
    max_assemblies: usize,
}

struct RateLimiter {
    limits: HashMap<IpAddr, QueryWindow>,
    max_qps: u32,
}

struct QueryWindow {
    count: u32,
    window_start: u128,
}

impl RateLimiter {
    fn new(max_qps: u32) -> Self {
        Self {
            limits: HashMap::new(),
            max_qps,
        }
    }

    fn check_and_update(&mut self, ip: IpAddr, now: u128) -> bool {
        const WINDOW_MS: u128 = 1000;

        let entry = self.limits.entry(ip).or_insert(QueryWindow {
            count: 0,
            window_start: now,
        });

        if now - entry.window_start >= WINDOW_MS {
            entry.count = 1;
            entry.window_start = now;
            return true;
        }

        entry.count += 1;
        entry.count <= self.max_qps
    }

    fn cleanup_old_entries(&mut self, now: u128) {
        const MAX_AGE_MS: u128 = 60000;
        self.limits
            .retain(|_, window| now - window.window_start < MAX_AGE_MS);
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "dnsm-server",
    about = "Tiny UDP DNS server",
    override_usage = "dnsm-server [OPTIONS] <ZONE>",
    long_about = "Logs queries, answers A records with a fixed IPv4 address, and can\n\
                  reassemble dnsm payloads when a zone is configured. All runs persist\n\
                  queries and decoded payloads to SQLite.\n\
                  \n\
                  Examples:\n\
                  \n\
                  - dnsm-server x.foo.bar\n\
                  - dnsm-server x.foo.bar --bind 0.0.0.0:5300 --respond_with 127.0.0.1\n\
                  - dnsm-server x.foo.bar --mailbox-zone m.example --tcp-mailbox --ans-ttl 30 --neg-ttl 300",
    disable_help_subcommand = true
)]
struct ServerArgs {
    /// Address to bind (default: 0.0.0.0:53)
    #[arg(long = "bind", value_name = "ADDR", default_value = "0.0.0.0:53")]
    bind_addr: String,

    /// Zone to treat as authoritative for dnsm payloads (required)
    #[arg(value_name = "ZONE")]
    zone: String,

    /// Mailbox TXT zone (optional). When set, TXT queries for
    /// "<mailbox-hex>.<mailbox-zone>" will return accumulated messages
    /// for that mailbox from the SQLite database (when configured).
    #[arg(long = "mailbox-zone", value_name = "MBX_ZONE")]
    mailbox_zone: Option<String>,

    /// Enable DNS over TCP handler for mailbox TXT lookups only
    #[arg(long = "tcp-mailbox")]
    tcp_mailbox: bool,

    /// IPv4 address to answer for A queries (default: 0.0.0.0)
    #[arg(long = "respond_with", value_name = "IP", default_value = "0.0.0.0")]
    fixed_ip_str: String,

    /// Path to append diagnostic event logs (default: dnsm_queries.log)
    /// Note: queries themselves are persisted to SQLite (see --db).
    #[arg(long = "log", value_name = "PATH", default_value = "dnsm_queries.log")]
    log_path: String,

    /// Path to a SQLite database for persistence (messages table is auto-created)
    #[arg(long = "db", value_name = "PATH", default_value = "dnsm.db")]
    db_path: PathBuf,

    /// Log progress every n unique chunks (n > 0)
    #[arg(long = "progress-every", value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    progress_every: Option<u32>,

    /// Garbage-collect inactive assemblies older than this many ms (default: 30000ms = 30s)
    #[arg(long = "gc-ms", value_name = "MS")]
    gc_ms: Option<u128>,

    /// Maximum concurrent assembly sessions (prevents memory exhaustion, default: 10_000)
    #[arg(
        long = "max-assemblies",
        value_name = "COUNT",
        default_value_t = 10_000
    )]
    max_assemblies: usize,

    /// TTL for A-record answers (default: 0)
    #[arg(long = "ans-ttl", value_name = "SEC", default_value_t = 0)]
    ans_ttl: u32,

    /// TTL for negative answers with SOA (default: 300)
    #[arg(long = "neg-ttl", value_name = "SEC", default_value_t = 300)]
    neg_ttl: u32,

    /// Disable ANSI colors in stdout (pretty output is always on)
    #[arg(long = "no-color")]
    no_color: bool,

    /// Accept only messages that decode to ASCII bytes; reject otherwise
    #[arg(long = "accept-ascii-only")]
    accept_ascii_only: bool,

    /// Process queries but send no responses when enabled
    #[arg(long = "no-response")]
    no_response: bool,

    /// Maximum decompressed payload size in bytes (default: 12582912 = 12MB).
    /// Prevents decompression bomb attacks. Set to 0 to disable limit (unsafe).
    #[arg(
        long = "max-decompressed-bytes",
        value_name = "BYTES",
        default_value_t = 12 * 1024 * 1024
    )]
    max_decompressed_bytes: u32,

    /// Maximum queries per second per IP address. Set to 0 to disable rate limiting.
    /// Aims to prevent UDP amplification/reflection attacks. Default: 100 qps.
    #[arg(long = "rate-limit-qps", value_name = "QPS", default_value_t = 100)]
    rate_limit_qps: u32,
}

#[derive(Debug)]
pub(crate) struct Assembly {
    rmax: Option<u16>,
    chunks: HashMap<u16, Vec<u8>>, // remaining -> data
    have_r: HashSet<u16>,
    last_seen: u128,
    recv_unique: u32,
    completed: bool,
    mailbox: Option<u64>, // mailbox assignment (from first chunk options)
}

impl Assembly {
    pub(crate) fn new(now: u128) -> Self {
        Self {
            rmax: None,
            chunks: HashMap::new(),
            have_r: HashSet::new(),
            last_seen: now,
            recv_unique: 0,
            completed: false,
            mailbox: None,
        }
    }
}

fn main() -> std::io::Result<()> {
    let args = ServerArgs::parse();

    if args.tcp_mailbox && args.mailbox_zone.is_none() {
        eprintln!("--tcp-mailbox requires --mailbox-zone");
        std::process::exit(2);
    }

    if args.no_color {
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
    }

    let ServerArgs {
        bind_addr,
        zone,
        mailbox_zone,
        tcp_mailbox,
        fixed_ip_str,
        log_path,
        db_path,
        progress_every,
        gc_ms,
        max_assemblies,
        ans_ttl,
        neg_ttl,
        accept_ascii_only,
        no_response,
        max_decompressed_bytes,
        rate_limit_qps,
        ..
    } = args;

    let fixed_ip = Ipv4Addr::from_str(&fixed_ip_str).unwrap_or_else(|_| {
        eprintln!(
            "Invalid fixed IP '{}', falling back to 0.0.0.0",
            fixed_ip_str
        );
        Ipv4Addr::new(0, 0, 0, 0)
    });

    let socket = UdpSocket::bind(&bind_addr)?;
    // 512 is the classic DNS over UDP max message size (sans EDNS0)
    socket.set_read_timeout(None)?;

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let mut log = BufWriter::new(log_file);

    let zone_labels = match validate_zone_and_labels(&zone) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("invalid ZONE: {}", e);
            std::process::exit(2);
        }
    };

    println!(
        "dnsm listening on {} - answering A with {} - logging to {} - db={}{}{}",
        bind_addr,
        fixed_ip,
        log_path,
        db_path.to_string_lossy(),
        match &zone_labels {
            Some(z) => format!(" - zone={}", z.join(".")),
            None => String::new(),
        },
        if no_response {
            " - responses=disabled"
        } else {
            ""
        }
    );

    let mailbox_zone_labels = match mailbox_zone {
        Some(ref z) => match validate_zone_and_labels(z) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("invalid --mailbox-zone: {}", e);
                std::process::exit(2);
            }
        },
        None => None,
    };

    // Initialize SQLite DB (required)
    let db = match storage::open_db(&db_path) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("failed to open db at {:?}: {}", db_path, e);
            std::process::exit(2);
        }
    };
    storage::configure_pragmas(&db);
    if let Err(e) = storage::ensure_schema(&db) {
        eprintln!("failed to init db schema: {}", e);
        std::process::exit(2);
    }

    let cfg = ServerCfg {
        zone_labels,
        mailbox_zone_labels,
        progress_every,
        ans_ttl,
        neg_ttl,
        pretty_stdout: true,
        accept_ascii_only,
        no_response,
        max_decompressed_bytes,
        rate_limit_qps: if rate_limit_qps > 0 {
            Some(rate_limit_qps)
        } else {
            None
        },
        max_assemblies,
    };
    // Optionally spawn mailbox-only TCP listener
    if tcp_mailbox && cfg.mailbox_zone_labels.as_ref().is_some() {
        let bind_addr_tcp = bind_addr.clone();
        let db_path_tcp = db_path.clone();
        let cfg_tcp = cfg.clone();
        std::thread::spawn(move || match TcpListener::bind(&bind_addr_tcp) {
            Ok(listener) => {
                if cfg_tcp.pretty_stdout {
                    println!(
                        "{} tcp-mailbox on {}",
                        style("[TCP]").blue().bold(),
                        bind_addr_tcp
                    );
                }
                let dbh = match Connection::open(&db_path_tcp) {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!(
                            "failed to open db at {:?} for tcp-mailbox: {}",
                            db_path_tcp, e
                        );
                        return;
                    }
                };
                while let Ok((mut stream, _addr)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    let _ = mailbox::handle_tcp_mailbox_conn(&mut stream, &cfg_tcp, &dbh);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            }
            Err(e) => {
                eprintln!("failed to bind tcp-mailbox on {}: {}", bind_addr_tcp, e);
            }
        });
    }
    let mut assemblies: HashMap<u64, Assembly> = HashMap::new();
    let mut recv_count: u64 = 0;

    let mut rate_limiter = cfg.rate_limit_qps.map(RateLimiter::new);
    let mut rate_limit_cleanup_counter: u32 = 0;

    let mut buf = [0u8; 512];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("recv error: {}", e);
                continue;
            }
        };

        let ts = dns_handler::now_millis();

        if let Some(ref mut limiter) = rate_limiter {
            if !limiter.check_and_update(peer.ip(), ts) {
                if cfg.pretty_stdout {
                    eprintln!(
                        "{} Rate limit exceeded from {} ({} qps max)",
                        style("[RATE_LIMIT]").yellow().bold(),
                        dns_handler::format_socket(peer),
                        limiter.max_qps
                    );
                }
                continue;
            }

            rate_limit_cleanup_counter += 1;
            if rate_limit_cleanup_counter >= 1000 {
                limiter.cleanup_old_entries(ts);
                rate_limit_cleanup_counter = 0;
            }
        }

        let pkt = &buf[..len];

        // Try to parse header and first question
        let (domain, q_end, qtype, qclass, _opcode, hdr) = match dns_handler::parse_header(pkt)
            .and_then(|h| {
                // Opcode is in flags bits 11..14
                let opcode = (h.flags >> 11) & 0x0F;
                // Only standard queries expected, but we'll echo opcode anyway
                dns_handler::parse_question(pkt).map(|(d, off, qt, qc)| (d, off, qt, qc, opcode, h))
            }) {
            Ok(v) => v,
            Err(_) => {
                // Format error; try to send FORMERR with empty question
                if !cfg.no_response
                    && let Ok(hdr) = dns_handler::parse_header(pkt)
                {
                    let rd = hdr.flags & 0x0100;
                    let flags = 0x8000 | rd | 1; // QR + RD + RCODE=1 (FORMERR)
                    let mut resp = Vec::with_capacity(28);
                    dns_handler::write_u16(&mut resp, hdr.id);
                    dns_handler::write_u16(&mut resp, flags);
                    dns_handler::write_u16(&mut resp, 0);
                    dns_handler::write_u16(&mut resp, 0);
                    dns_handler::write_u16(&mut resp, 0);
                    dns_handler::write_u16(&mut resp, 0);
                    let _ = socket.send_to(&resp, peer);
                }
                continue;
            }
        };

        // Log the query to SQLite (instead of file)
        let ts = dns_handler::now_millis();
        let peer_ip = peer.ip().to_string();
        let peer_port = peer.port() as i64;

        let (domain_for_db, domain_validation_error) =
            match dns_handler::validate_and_sanitize_domain(&domain) {
                Ok(valid_domain) => (valid_domain, None),
                Err(err) => {
                    let sanitized = dns_handler::sanitize_domain_for_logging(&domain);
                    (sanitized, Some(err))
                }
            };

        let labels = to_lower_labels(&domain_for_db);
        let in_zone = dns_handler::strip_zone(&labels, &cfg.zone_labels).is_some();
        let in_mbox_zone = dns_handler::strip_zone(&labels, &cfg.mailbox_zone_labels).is_some();

        let mut base32_chars: Option<i64> = None;
        let mut data_labels: Option<i64> = None;
        let mut decode_error: Option<String> = None;
        let mut chunk_first: Option<i64> = None;
        let mut chunk_remaining: Option<i64> = None;
        let mut chunk_version: Option<i64> = None;
        let mut data_len: Option<i64> = None;
        let mut mailbox_hex: Option<String> = None;
        let mut message_key_i64: Option<i64> = None;

        if in_zone && let Some(labels_in_zone) = dns_handler::strip_zone(&labels, &cfg.zone_labels)
        {
            let mut b32 = String::with_capacity(labels_in_zone.iter().map(|s| s.len()).sum());
            for lab in labels_in_zone.iter() {
                b32.push_str(lab);
            }
            base32_chars = Some(b32.len() as i64);
            data_labels = Some(labels_in_zone.len() as i64);
            if let Some(bytes) = base32_nopad_decode(&b32) {
                if bytes.len() < CHUNK_HEADER_LEN {
                    decode_error = Some("short_bytes".to_string());
                } else {
                    let mut hdrb = [0u8; CHUNK_HEADER_LEN];
                    hdrb.copy_from_slice(&bytes[..CHUNK_HEADER_LEN]);
                    let ch = ChunkHeader::from_bytes(&hdrb);
                    chunk_first = Some(if ch.is_first { 1 } else { 0 });
                    chunk_remaining = Some(ch.remaining as i64);
                    chunk_version = Some(ch.version as i64);
                    let mut offset = CHUNK_HEADER_LEN;
                    let mut message_key: u64 = 0;
                    if ch.is_first {
                        if ch.remaining == 0 {
                            if ch.has_mailbox && bytes.len() >= offset + 6 {
                                let mut mb = [0u8; 8];
                                mb[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                                let m = u64::from_be_bytes(mb);
                                mailbox_hex = Some(format!("{:012x}", m & 0x0000_FFFF_FFFF_FFFF));
                                offset += 6;
                            }
                        } else {
                            if bytes.len() >= offset + 6 {
                                let mut mid = [0u8; 8];
                                mid[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                                message_key = u64::from_be_bytes(mid);
                                offset += 6;
                            }
                            if ch.has_mailbox && bytes.len() >= offset + 6 {
                                let mut mb = [0u8; 8];
                                mb[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                                let m = u64::from_be_bytes(mb);
                                mailbox_hex = Some(format!("{:012x}", m & 0x0000_FFFF_FFFF_FFFF));
                                offset += 6;
                            }
                        }
                    } else if bytes.len() >= offset + 6 {
                        let mut mid = [0u8; 8];
                        mid[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                        message_key = u64::from_be_bytes(mid);
                        offset += 6;
                    }
                    data_len = Some(bytes.len().saturating_sub(offset) as i64);
                    if message_key != 0 {
                        message_key_i64 = Some(message_key as i64);
                    }
                }
            } else {
                decode_error = Some("invalid_base32".to_string());
            }
        }

        let _ = db.execute(
            "INSERT INTO queries (
                ts, peer_ip, peer_port, domain, qtype, qclass, opcode, flags,
                in_zone, in_mailbox_zone, base32_chars, data_labels, decode_error,
                chunk_first, chunk_remaining, chunk_version, data_len, mailbox, message_key
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                ts as i64,
                &peer_ip,
                peer_port,
                &domain_for_db,
                qtype as i64,
                qclass as i64,
                ((hdr.flags >> 11) & 0x0F) as i64,
                hdr.flags as i64,
                if in_zone { 1i64 } else { 0i64 },
                if in_mbox_zone { 1i64 } else { 0i64 },
                base32_chars,
                data_labels,
                decode_error,
                chunk_first,
                chunk_remaining,
                chunk_version,
                data_len,
                mailbox_hex,
                message_key_i64,
            ],
        );

        if let Some(ref validation_err) = domain_validation_error
            && cfg.pretty_stdout
        {
            eprintln!(
                "{} domain validation failed: {} (original length: {}, sanitized length: {})",
                style("[VALIDATOR]").red().bold(),
                validation_err,
                domain.len(),
                domain_for_db.len()
            );
        }

        if cfg.pretty_stdout {
            if in_zone {
                // Decode the header from the in-zone dnsm query and show a concise summary
                if let Some(labels_in_zone) = dns_handler::strip_zone(&labels, &cfg.zone_labels) {
                    let mut b32 =
                        String::with_capacity(labels_in_zone.iter().map(|s| s.len()).sum());
                    for lab in labels_in_zone {
                        b32.push_str(lab);
                    }
                    if let Some(bytes) = base32_nopad_decode(&b32) {
                        if bytes.len() >= CHUNK_HEADER_LEN {
                            // Decoded successfully; try_handle_dnsm will print [CHUNK].
                            // Do not print an extra [QUERY] line.
                        } else {
                            println!(
                                "{} {} {} {}",
                                style("[QUERY]").cyan().bold(),
                                style(format!("[{}]", ts)).dim(),
                                style(dns_handler::format_socket(peer)).magenta(),
                                style("[ERR short_bytes]").red()
                            );
                        }
                    } else {
                        println!(
                            "{} {} {} {}",
                            style("[QUERY]").cyan().bold(),
                            style(format!("[{}]", ts)).dim(),
                            style(dns_handler::format_socket(peer)).magenta(),
                            style("[ERR invalid_base32]").red()
                        );
                    }
                }
            } else if in_mbox_zone {
                println!(
                    "{} {} {} {} {}",
                    style("[QUERY]").cyan().bold(),
                    style(format!("[{}]", ts)).dim(),
                    style(dns_handler::format_socket(peer)).magenta(),
                    style("QTYPE=16").white(),
                    style("[mailbox]").dim()
                );
            } else {
                println!(
                    "{} {} {} {} {}",
                    style("[QUERY]").cyan().bold(),
                    style(format!("[{}]", ts)).dim(),
                    style(dns_handler::format_socket(peer)).magenta(),
                    style(format!("QTYPE={}", qtype)).white(),
                    style("[outside]").dim()
                );
            }
        }

        // Try to parse dnsm chunk when zone is configured
        // No tagged-log output anymore; file logs are JSON-only.

        if cfg.zone_labels.is_some() {
            // Use validated/sanitized domain to prevent injection attacks
            dns_handler::try_handle_dnsm(
                &domain_for_db,
                &cfg,
                &mut assemblies,
                ts,
                &mut log,
                peer,
                &db,
            );
            recv_count += 1;
            if recv_count.is_multiple_of(200) {
                let age = gc_ms.unwrap_or_else(|| Duration::from_secs(30).as_millis());
                dns_handler::gc_assemblies(&mut assemblies, ts, age, &mut log, cfg.pretty_stdout);
            }
        }

        // Mailbox TXT lookup support with paging
        #[allow(clippy::collapsible_if)]
        if qtype == 16 && qclass == 1 {
            if let Some(mailbox_labels) = dns_handler::strip_zone(&labels, &cfg.mailbox_zone_labels)
            {
                // Patterns supported:
                //  - <mailbox>.<zone>
                //  - <message_id_hex>.<mailbox>.<zone>  (page older than that message)
                let (maybe_mid_hex, maybe_mbox) = match mailbox_labels.len() {
                    1 => (None, validate_mailbox_hex12(&mailbox_labels[0])),
                    2 => (
                        Some(mailbox_labels[0].clone()),
                        validate_mailbox_hex12(&mailbox_labels[1]),
                    ),
                    _ => (None, None),
                };

                if let Some(mb_hex) = maybe_mbox {
                    // Determine paging pivot (received_at strictly less than pivot_ts when provided)
                    let mut pivot_ts: Option<i64> = None;
                    if let Some(mid_label) = maybe_mid_hex.as_ref() {
                        match mailbox::find_pivot_ts(&db, &mb_hex, mid_label) {
                            Ok(ts_opt) => pivot_ts = ts_opt,
                            Err(e) => {
                                let _ = writeln!(
                                    log,
                                    "{{\\\"ts\\\":{},\\\"event\\\":\\\"db_error\\\",\\\"op\\\":\\\"pivot_lookup\\\",\\\"err\\\":\\\"{}\\\"}}",
                                    ts,
                                    dns_handler::json_escape(&e.to_string())
                                );
                            }
                        }
                    }

                    // Collect distinct messages newest-first, prefixed with 12-hex id + tab
                    let msgs: Vec<Vec<u8>> = match mailbox::collect_distinct_mailbox_messages(
                        &db, &mb_hex, pivot_ts,
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = writeln!(
                                log,
                                "{{\\\"ts\\\":{},\\\"event\\\":\\\"db_error\\\",\\\"op\\\":\\\"select_mailbox\\\",\\\"err\\\":\\\"{}\\\"}}",
                                ts,
                                dns_handler::json_escape(&e.to_string())
                            );
                            Vec::new()
                        }
                    };

                    let zone = cfg.mailbox_zone_labels.as_ref().unwrap();
                    let resp = if msgs.is_empty() {
                        dns_handler::build_negative_nodata_with_soa(
                            pkt,
                            hdr,
                            q_end,
                            zone,
                            cfg.neg_ttl,
                        )
                    } else {
                        // UDP budget: classic 480-ish bytes
                        mailbox::build_mailbox_txt_response(
                            pkt,
                            hdr,
                            q_end,
                            cfg.ans_ttl,
                            &msgs,
                            480,
                            true,
                        )
                    };
                    if !cfg.no_response {
                        let _ = socket.send_to(&resp, peer);
                    }

                    mailbox::log_mailbox_query(
                        &mut log,
                        ts,
                        &mb_hex,
                        msgs.len(),
                        dns_handler::read_u16(&resp[6..8]),
                        pivot_ts,
                    );
                    let _ = log.flush();
                    continue; // handled
                }
            }
        }

        // Only answer TYPE A (1) and CLASS IN (1)
        let is_a_query = qtype == 1 && qclass == 1;
        let resp =
            dns_handler::build_response(pkt, hdr, q_end, fixed_ip, is_a_query, in_zone, &cfg);

        // Best-effort send
        if !cfg.no_response {
            let _ = socket.send_to(&resp, peer);
        }
    }
}

#[cfg(test)]
mod tests {}
