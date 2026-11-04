use clap::Parser;
use console::style;
use dnsm::{
    ChunkHeader, base32_nopad_decode, to_lower_labels, validate_mailbox_hex12,
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
    ans_ttl: u32,
    neg_ttl: u32,
    pretty_stdout: bool,
    accept_ascii_only: bool,
    no_response: bool,
    max_decompressed_bytes: u32,
    rate_limit_qps: Option<u32>,
    max_assemblies: usize,
    max_assembly_chunks: usize,
    max_total_assembly_chunks: usize,
    max_assembly_bytes: usize,
    max_total_assembly_bytes: usize,
}

struct RateLimiter {
    limits: HashMap<IpAddr, QueryWindow>,
    max_qps: u32,
    max_entries: usize,
    last_cleanup: u128,
}

const MAX_RATE_LIMIT_ENTRIES: usize = 100_000;
const RATE_LIMIT_ENTRY_MAX_AGE_MS: u128 = 60_000;
const RATE_LIMIT_CLEANUP_INTERVAL_MS: u128 = 1_000;
const QUERY_RETENTION_MAINTENANCE_MS: u128 = 60 * 60 * 1_000;
const MILLIS_PER_DAY: u128 = 24 * 60 * 60 * 1_000;

struct QueryWindow {
    count: u32,
    window_start: u128,
}

impl RateLimiter {
    fn new(max_qps: u32) -> Self {
        Self::with_max_entries(max_qps, MAX_RATE_LIMIT_ENTRIES)
    }

    fn with_max_entries(max_qps: u32, max_entries: usize) -> Self {
        Self {
            limits: HashMap::new(),
            max_qps,
            max_entries,
            last_cleanup: 0,
        }
    }

    fn check_and_update(&mut self, ip: IpAddr, now: u128) -> bool {
        const WINDOW_MS: u128 = 1_000;

        if now.saturating_sub(self.last_cleanup) >= RATE_LIMIT_CLEANUP_INTERVAL_MS {
            self.cleanup_old_entries(now);
            self.last_cleanup = now;
        }

        if !self.limits.contains_key(&ip) && self.limits.len() >= self.max_entries {
            return false;
        }

        let entry = self.limits.entry(ip).or_insert(QueryWindow {
            count: 0,
            window_start: now,
        });

        if now.saturating_sub(entry.window_start) >= WINDOW_MS {
            entry.count = 1;
            entry.window_start = now;
            return true;
        }

        entry.count += 1;
        entry.count <= self.max_qps
    }

    fn cleanup_old_entries(&mut self, now: u128) {
        self.limits.retain(|_, window| {
            now.saturating_sub(window.window_start) < RATE_LIMIT_ENTRY_MAX_AGE_MS
        });
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

    /// Delete query-log rows older than this many days. Set to 0 to disable retention.
    #[arg(
        long = "query-retention-days",
        value_name = "DAYS",
        default_value_t = 30
    )]
    query_retention_days: u32,

    /// Deprecated no-op retained for command-line compatibility
    #[arg(
        long = "progress-every",
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..),
        hide = true
    )]
    progress_every: Option<u32>,

    /// Garbage-collect inactive assemblies older than this many ms (default: 30000ms = 30s)
    #[arg(long = "gc-ms", value_name = "MS")]
    gc_ms: Option<u128>,

    /// Maximum concurrent assembly sessions (prevents memory exhaustion, default: 10_000).
    /// Must be at least 1.
    #[arg(
        long = "max-assemblies",
        value_name = "COUNT",
        default_value_t = 10_000
    )]
    max_assemblies: usize,

    /// Maximum chunks retained for one incomplete assembly (default: 8192)
    #[arg(
        long = "max-assembly-chunks",
        value_name = "COUNT",
        default_value_t = 8_192
    )]
    max_assembly_chunks: usize,

    /// Maximum chunks retained across all incomplete assemblies (default: 65536)
    #[arg(
        long = "max-total-assembly-chunks",
        value_name = "COUNT",
        default_value_t = 65_536
    )]
    max_total_assembly_chunks: usize,

    /// Maximum compressed bytes retained for one incomplete assembly (default: 2MB)
    #[arg(
        long = "max-assembly-bytes",
        value_name = "BYTES",
        default_value_t = 2 * 1024 * 1024
    )]
    max_assembly_bytes: usize,

    /// Maximum compressed bytes retained across all incomplete assemblies (default: 64MB)
    #[arg(
        long = "max-total-assembly-bytes",
        value_name = "BYTES",
        default_value_t = 64 * 1024 * 1024
    )]
    max_total_assembly_bytes: usize,

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

    /// Maximum decompressed payload size in bytes (default: 1048576 = 1MB).
    /// Prevents decompression bomb attacks. Requires --allow-unlimited-decompress to set 0.
    #[arg(
        long = "max-decompressed-bytes",
        value_name = "BYTES",
        default_value_t = 1024 * 1024
    )]
    max_decompressed_bytes: u32,

    /// Allow --max-decompressed-bytes 0 (no limit). Unsafe: a single query
    /// can decompress to arbitrary size.
    #[arg(long = "allow-unlimited-decompress")]
    allow_unlimited_decompress: bool,

    /// Maximum queries per second per IP address. Set to 0 to disable rate limiting.
    /// Aims to prevent UDP amplification/reflection attacks. Default: 1000 qps.
    #[arg(long = "rate-limit-qps", value_name = "QPS", default_value_t = 1000)]
    rate_limit_qps: u32,
}

#[derive(Debug)]
pub(crate) struct Assembly {
    rmax: Option<u16>,
    chunks: HashMap<u16, Vec<u8>>, // remaining -> data
    have_r: HashSet<u16>,
    stored_bytes: usize,
    last_seen: u128,
    completed: bool,
    mailbox: Option<u64>, // mailbox assignment (from first chunk options)
}

impl Assembly {
    pub(crate) fn new(now: u128) -> Self {
        Self {
            rmax: None,
            chunks: HashMap::new(),
            have_r: HashSet::new(),
            stored_bytes: 0,
            last_seen: now,
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

    if args.progress_every.is_some() {
        eprintln!("warning: --progress-every is deprecated and has no effect");
    }

    if args.max_assemblies == 0 {
        eprintln!("--max-assemblies must be at least 1");
        std::process::exit(2);
    }

    if args.max_assembly_chunks == 0
        || args.max_total_assembly_chunks == 0
        || args.max_assembly_bytes == 0
        || args.max_total_assembly_bytes == 0
    {
        eprintln!("assembly limits must be at least 1");
        std::process::exit(2);
    }

    if args.max_assembly_chunks > args.max_total_assembly_chunks {
        eprintln!("--max-assembly-chunks cannot exceed --max-total-assembly-chunks");
        std::process::exit(2);
    }

    if args.max_assembly_bytes > args.max_total_assembly_bytes {
        eprintln!("--max-assembly-bytes cannot exceed --max-total-assembly-bytes");
        std::process::exit(2);
    }

    if args.max_decompressed_bytes == 0 && !args.allow_unlimited_decompress {
        eprintln!("--max-decompressed-bytes 0 requires --allow-unlimited-decompress");
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
        query_retention_days,
        gc_ms,
        max_assemblies,
        max_assembly_chunks,
        max_total_assembly_chunks,
        max_assembly_bytes,
        max_total_assembly_bytes,
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
    if let Err(e) = storage::run_migrations(&db) {
        eprintln!("failed to run db migrations: {}", e);
        std::process::exit(2);
    }

    let query_retention_ms = (query_retention_days > 0)
        .then(|| u128::from(query_retention_days).saturating_mul(MILLIS_PER_DAY));
    let maintenance_now = dns_handler::now_millis();
    if let Some(retention_ms) = query_retention_ms {
        let cutoff = maintenance_now
            .saturating_sub(retention_ms)
            .min(i64::MAX as u128) as i64;
        if let Err(e) = storage::purge_queries_older_than(&db, cutoff) {
            eprintln!("failed to purge expired query rows: {}", e);
        }
    }
    let mut next_query_maintenance = maintenance_now.saturating_add(QUERY_RETENTION_MAINTENANCE_MS);

    // Force-enable ANSI colors even when stdout isn't a TTY (e.g. under
    // `docker logs`). Honor NO_COLOR=1 for users who opt out explicitly.
    if std::env::var_os("NO_COLOR").is_none() {
        console::set_colors_enabled(true);
        console::set_colors_enabled_stderr(true);
    }

    let cfg = ServerCfg {
        zone_labels,
        mailbox_zone_labels,
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
        max_assembly_chunks,
        max_total_assembly_chunks,
        max_assembly_bytes,
        max_total_assembly_bytes,
    };
    // Optionally spawn mailbox-only TCP listener
    if tcp_mailbox && cfg.mailbox_zone_labels.as_ref().is_some() {
        let bind_addr_tcp = bind_addr.clone();
        let db_path_tcp = db_path.clone();
        let cfg_tcp = cfg.clone();
        std::thread::spawn(move || match TcpListener::bind(&bind_addr_tcp) {
            Ok(listener) => {
                if cfg_tcp.pretty_stdout {
                    let ts = dns_handler::now_millis();
                    println!(
                        "{} {} tcp-mailbox on {}",
                        style("[TCP]").blue().bold(),
                        style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                        bind_addr_tcp
                    );
                }
                let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                const MAX_TCP_CONNS: usize = 64;
                while let Ok((stream, _addr)) = listener.accept() {
                    if active.load(std::sync::atomic::Ordering::Relaxed) >= MAX_TCP_CONNS {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let cfg_conn = cfg_tcp.clone();
                    let db_path_conn = db_path_tcp.clone();
                    let active_conn = active.clone();
                    std::thread::spawn(move || {
                        let mut stream = stream;
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        if let Ok(dbh) = Connection::open(&db_path_conn) {
                            storage::configure_pragmas(&dbh);
                            let _ = mailbox::handle_tcp_mailbox_conn(&mut stream, &cfg_conn, &dbh);
                        }
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        active_conn.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    });
                }
            }
            Err(e) => {
                eprintln!("failed to bind tcp-mailbox on {}: {}", bind_addr_tcp, e);
            }
        });
    }
    let mut assemblies: HashMap<u64, Assembly> = HashMap::new();
    let mut assembly_chunks: usize = 0;
    let mut assembly_bytes: usize = 0;
    let mut recv_count: u64 = 0;

    let mut rate_limiter = cfg.rate_limit_qps.map(RateLimiter::new);

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

        if let Some(retention_ms) = query_retention_ms
            && ts >= next_query_maintenance
        {
            let cutoff = ts.saturating_sub(retention_ms).min(i64::MAX as u128) as i64;
            if let Err(e) = storage::purge_queries_older_than(&db, cutoff) {
                eprintln!("failed to purge expired query rows: {}", e);
            }
            next_query_maintenance = ts.saturating_add(QUERY_RETENTION_MAINTENANCE_MS);
        }

        if let Some(ref mut limiter) = rate_limiter
            && !limiter.check_and_update(peer.ip(), ts)
        {
            if cfg.pretty_stdout {
                eprintln!(
                    "{} {} Rate limit exceeded from {} ({} qps max)",
                    style("[RATE_LIMIT]").yellow().bold(),
                    style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                    dns_handler::format_socket(peer),
                    limiter.max_qps
                );
            }
            continue;
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

        let query_has_edns = dns_handler::has_edns(pkt, q_end);

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

        let is_human_ping = in_zone
            && dns_handler::strip_zone(&labels, &cfg.zone_labels).is_some_and(|stripped| {
                stripped.len() == 1
                    && stripped[0].len() == 12
                    && stripped[0].chars().all(|c| c.is_ascii_hexdigit())
            });

        let mut base32_chars: Option<i64> = None;
        let mut data_labels: Option<i64> = None;
        let mut decode_error: Option<String> = None;
        let mut chunk_first: Option<i64> = None;
        let mut chunk_remaining: Option<i64> = None;
        let mut chunk_version: Option<i64> = None;
        let mut data_len: Option<i64> = None;
        let mut mailbox_hex: Option<String> = None;
        let mut message_key_i64: Option<i64> = None;

        if is_human_ping
            && qclass == 1
            && (qtype == 1 || qtype == 28)
            && let Some(stripped) = dns_handler::strip_zone(&labels, &cfg.zone_labels)
        {
            mailbox_hex = Some(stripped[0].clone());
        }

        if in_zone
            && !is_human_ping
            && let Some(labels_in_zone) = dns_handler::strip_zone(&labels, &cfg.zone_labels)
        {
            let mut b32 = String::with_capacity(labels_in_zone.iter().map(|s| s.len()).sum());
            for lab in labels_in_zone.iter() {
                b32.push_str(lab);
            }
            base32_chars = Some(b32.len() as i64);
            data_labels = Some(labels_in_zone.len() as i64);
            if let Some(bytes) = base32_nopad_decode(&b32) {
                if let Some((ch, hdr_len)) = ChunkHeader::from_bytes(&bytes) {
                    chunk_first = Some(if ch.is_first { 1 } else { 0 });
                    chunk_remaining = Some(ch.remaining as i64);
                    chunk_version = Some(ch.version as i64);
                    let mut offset = hdr_len;
                    let mut message_key: u64 = 0;
                    if ch.is_ping {
                        // Ping: just mailbox after flags byte
                        if ch.has_mailbox && bytes.len() >= offset + 6 {
                            let mut mb = [0u8; 8];
                            mb[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                            let m = u64::from_be_bytes(mb);
                            mailbox_hex = Some(format!("{:012x}", m & 0x0000_FFFF_FFFF_FFFF));
                            offset += 6;
                        }
                    } else if !ch.chunked {
                        // Single-chunk: optional mailbox
                        if ch.has_mailbox && bytes.len() >= offset + 6 {
                            let mut mb = [0u8; 8];
                            mb[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                            let m = u64::from_be_bytes(mb);
                            mailbox_hex = Some(format!("{:012x}", m & 0x0000_FFFF_FFFF_FFFF));
                            offset += 6;
                        }
                    } else {
                        // Multi-chunk: msg_id48 + optional mailbox on first
                        if bytes.len() >= offset + 6 {
                            let mut mid = [0u8; 8];
                            mid[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                            message_key = u64::from_be_bytes(mid);
                            offset += 6;
                        }
                        if ch.is_first && ch.has_mailbox && bytes.len() >= offset + 6 {
                            let mut mb = [0u8; 8];
                            mb[2..8].copy_from_slice(&bytes[offset..offset + 6]);
                            let m = u64::from_be_bytes(mb);
                            mailbox_hex = Some(format!("{:012x}", m & 0x0000_FFFF_FFFF_FFFF));
                            offset += 6;
                        }
                    }
                    data_len = Some(bytes.len().saturating_sub(offset) as i64);
                    if message_key != 0 {
                        message_key_i64 = Some(message_key as i64);
                    }
                } else {
                    decode_error = Some("short_bytes".to_string());
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
                "{} {} domain validation failed: {} (original length: {}, sanitized length: {})",
                style("[VALIDATOR]").red().bold(),
                style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                validation_err,
                domain.len(),
                domain_for_db.len()
            );
        }

        if cfg.pretty_stdout {
            if is_human_ping {
                // Human-ping pretty output is printed by the handler below.
            } else if in_zone {
                // Decode the header from the in-zone dnsm query and show a concise summary
                if let Some(labels_in_zone) = dns_handler::strip_zone(&labels, &cfg.zone_labels) {
                    let mut b32 =
                        String::with_capacity(labels_in_zone.iter().map(|s| s.len()).sum());
                    for lab in labels_in_zone {
                        b32.push_str(lab);
                    }
                    if let Some(bytes) = base32_nopad_decode(&b32) {
                        if ChunkHeader::from_bytes(&bytes).is_some() {
                            // Decoded successfully; try_handle_dnsm will print [CHUNK] or [PING].
                            // Do not print an extra [QUERY] line.
                        } else {
                            println!(
                                "{} {} {} {}",
                                style("[QUERY]").cyan().bold(),
                                style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                                style(dns_handler::format_socket(peer)).magenta(),
                                style("[ERR short_bytes]").red()
                            );
                        }
                    } else {
                        println!(
                            "{} {} {} {}",
                            style("[QUERY]").cyan().bold(),
                            style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                            style(dns_handler::format_socket(peer)).magenta(),
                            style("[ERR invalid_base32]").red()
                        );
                    }
                }
            } else if in_mbox_zone {
                println!(
                    "{} {} {} {} {}",
                    style("[QUERY]").cyan().bold(),
                    style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                    style(dns_handler::format_socket(peer)).magenta(),
                    style("QTYPE=16").white(),
                    style("[mailbox]").dim()
                );
            } else {
                println!(
                    "{} {} {} {} {}",
                    style("[QUERY]").cyan().bold(),
                    style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                    style(dns_handler::format_socket(peer)).magenta(),
                    style(format!("QTYPE={}", qtype)).white(),
                    style("[outside]").dim()
                );
            }
        }

        // Human-readable ping: single 12-hex label before the data zone
        // (e.g. bf1c3a4a3694.k.dnsm.re). Handles A (persist + respond)
        // and AAAA (respond only) to prevent AAAA from falling into the
        // base32 decoder.
        if is_human_ping
            && (qtype == 1 || qtype == 28)
            && qclass == 1
            && let Some(zone_stripped) = dns_handler::strip_zone(&labels, &cfg.zone_labels)
            && zone_stripped.len() == 1
            && let Some(mb_hex) = validate_mailbox_hex12(&zone_stripped[0])
        {
            if qtype == 28 {
                let mut resp =
                    dns_handler::build_response(pkt, hdr, q_end, fixed_ip, false, true, &cfg);
                if query_has_edns {
                    dns_handler::append_opt(&mut resp, 512);
                }
                if !cfg.no_response {
                    let _ = socket.send_to(&resp, peer);
                }
                continue;
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"ping");
            if let Ok(mb_val) = u64::from_str_radix(&mb_hex, 16) {
                let mb_bytes = (mb_val & 0x0000_FFFF_FFFF_FFFF).to_be_bytes();
                hasher.update(&mb_bytes[2..8]);
            }
            hasher.update(peer.ip().to_string().as_bytes());
            hasher.update(&(ts as u64).to_be_bytes());
            let hash = hasher.finalize();
            let msg_id: [u8; 16] = hash.as_bytes()[..16].try_into().unwrap();

            if let Err(e) = db.execute(
                "INSERT OR IGNORE INTO messages (message_key, mailbox, data, received_at, message_id, peer_ip, message_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    0i64,
                    &mb_hex,
                    &[] as &[u8],
                    ts as i64,
                    &msg_id[..],
                    peer.ip().to_string(),
                    "ping",
                ],
            ) {
                let _ = writeln!(
                    log,
                    "{{\"ts\":{},\"event\":\"db_error\",\"op\":\"insert_ping\",\"err\":\"{}\"}}",
                    ts,
                    dns_handler::json_escape(&e.to_string())
                );
                let _ = log.flush();
                if cfg.pretty_stdout {
                    println!(
                        "{} {} op=insert_ping err={}",
                        style("[ERR] db_error").red().bold(),
                        style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                        e
                    );
                }
            } else {
                let _ = writeln!(
                    log,
                    "{{\"ts\":{},\"event\":\"ping\",\"mailbox\":\"{}\",\"peer\":\"{}\"}}",
                    ts,
                    mb_hex,
                    dns_handler::json_escape(&dns_handler::format_socket(peer))
                );
                let _ = log.flush();
                if cfg.pretty_stdout {
                    println!(
                        "{} {} mbox={} peer={}",
                        style("[PING]").magenta().bold(),
                        style(format!("[{}]", dns_handler::format_ts_utc(ts))).dim(),
                        style(&mb_hex).cyan(),
                        style(dns_handler::format_socket(peer)).magenta(),
                    );
                }
            }

            let mut resp = dns_handler::build_response(pkt, hdr, q_end, fixed_ip, true, true, &cfg);
            if query_has_edns {
                dns_handler::append_opt(&mut resp, 512);
            }
            if !cfg.no_response {
                let _ = socket.send_to(&resp, peer);
            }
            continue;
        }

        // Try to parse dnsm chunk when zone is configured
        // No tagged-log output anymore; file logs are JSON-only.

        if cfg.zone_labels.is_some() && !is_human_ping && (qtype == 1 || qtype == 28) {
            // Only process A/AAAA queries as data carriers; NS and other
            // query types from resolvers are not dnsm chunks.
            dns_handler::try_handle_dnsm(
                &domain_for_db,
                &cfg,
                &mut assemblies,
                &mut assembly_chunks,
                &mut assembly_bytes,
                ts,
                &mut log,
                peer,
                &db,
                qtype,
            );
            recv_count += 1;
            if recv_count.is_multiple_of(200) {
                let age = gc_ms.unwrap_or_else(|| Duration::from_secs(30).as_millis());
                dns_handler::gc_assemblies(
                    &mut assemblies,
                    &mut assembly_chunks,
                    &mut assembly_bytes,
                    ts,
                    age,
                    &mut log,
                    cfg.pretty_stdout,
                );
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
                    let page = match mailbox::collect_distinct_mailbox_messages(
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
                            mailbox::MailboxPage {
                                messages: Vec::new(),
                                truncated: false,
                            }
                        }
                    };

                    let zone = cfg.mailbox_zone_labels.as_ref().unwrap();
                    let mut resp = if page.messages.is_empty() {
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
                            &page.messages,
                            480,
                            page.truncated,
                        )
                    };
                    if query_has_edns {
                        dns_handler::append_opt(&mut resp, 512);
                    }
                    if !cfg.no_response {
                        let _ = socket.send_to(&resp, peer);
                    }

                    mailbox::log_mailbox_query(
                        &mut log,
                        ts,
                        &mb_hex,
                        page.messages.len(),
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
        let mut resp =
            dns_handler::build_response(pkt, hdr, q_end, fixed_ip, is_a_query, in_zone, &cfg);

        if query_has_edns {
            dns_handler::append_opt(&mut resp, 512);
        }

        // Best-effort send
        if !cfg.no_response {
            let _ = socket.send_to(&resp, peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deprecated_progress_option_remains_parseable() {
        let args =
            ServerArgs::try_parse_from(["dnsm-server", "x.example", "--progress-every", "10"])
                .unwrap();
        assert_eq!(args.progress_every, Some(10));
    }

    #[test]
    fn rate_limiter_drops_new_ips_at_capacity_without_blocking_known_ips() {
        let mut limiter = RateLimiter::with_max_entries(10, 2);
        let first = IpAddr::from([192, 0, 2, 1]);
        let second = IpAddr::from([192, 0, 2, 2]);
        let third = IpAddr::from([192, 0, 2, 3]);

        assert!(limiter.check_and_update(first, 1));
        assert!(limiter.check_and_update(second, 1));
        assert!(!limiter.check_and_update(third, 1));
        assert!(limiter.check_and_update(first, 2));
        assert_eq!(limiter.limits.len(), 2);
    }

    #[test]
    fn rate_limiter_reclaims_stale_entries_on_timed_cleanup() {
        let mut limiter = RateLimiter::with_max_entries(10, 1);
        let old = IpAddr::from([192, 0, 2, 1]);
        let new = IpAddr::from([192, 0, 2, 2]);

        assert!(limiter.check_and_update(old, 1));
        assert!(limiter.check_and_update(new, RATE_LIMIT_ENTRY_MAX_AGE_MS + 1));
        assert!(!limiter.limits.contains_key(&old));
        assert!(limiter.limits.contains_key(&new));
    }
}
