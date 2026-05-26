use clap::{ArgAction, Parser};
use console::style;
use dnsm::{BuildInfo, BuildOptions, build_domains_for_data, build_human_ping_domain};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::str::FromStr;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "dnsm",
    about = "Send data via DNS queries",
    long_about = "Reads from stdin and emits DNS queries carrying the data, or prints\n\
                  hostnames (one per chunk) when --dont-query is used.\n\
                  \n\
                  Examples:\n\
                  \n\
                  - echo 'hello' | dnsm\n\
                  - echo 'hello' | dnsm abcdef123456\n\
                  - echo 'hello' | dnsm abcdef123456 --zone x.foo.bar -n\n\
                  - dnsm --ping\n\
    - head -c 200000 /dev/urandom | dnsm --resolver-ip 127.0.0.1:5353",
    disable_help_subcommand = true
)]
struct ClientArgs {
    /// Mailbox ID (exactly 12 hex chars). Random if omitted.
    #[arg(value_name = "MAILBOX", value_parser = parse_mailbox_hex12_arg)]
    mailbox: Option<String>,

    /// Zone/apex the payload labels are appended to
    #[arg(long = "zone", value_name = "ZONE", default_value = "k.dnsm.re")]
    zone: String,

    /// Send to this resolver (default: first nameserver in /etc/resolv.conf)
    #[arg(long = "resolver-ip", value_name = "HOST[:PORT]")]
    resolver_ip: Option<String>,

    /// Do not send; print hostnames (one per chunk)
    #[arg(short = 'n', long = "dont-query", action = ArgAction::SetTrue)]
    dont_query: bool,

    /// Wait up to this many ms for a reply to each query (0 disables)
    #[arg(long = "await-reply-ms", value_name = "MS", default_value_t = 3000)]
    await_reply_ms: u64,

    /// Sleep this many ms between queries
    #[arg(long = "delay-ms", value_name = "MS", default_value_t = 5)]
    delay_ms: u64,

    /// Append a human-readable send log to this file
    #[arg(long = "sent-log", value_name = "PATH")]
    sent_log: Option<String>,

    /// Generate a random mailbox ID (conflicts with positional MAILBOX)
    #[arg(long = "random-mailbox", action = ArgAction::SetTrue, conflicts_with = "mailbox")]
    random_mailbox: bool,

    /// Send a minimal ping (no message content).
    /// Produces `<mailbox>.<zone>` (e.g. bf1c3a4a3694.k.dnsm.re).
    #[arg(long = "ping", action = ArgAction::SetTrue)]
    ping: bool,

    /// Verbose progress to stderr
    #[arg(long = "debug", action = ArgAction::SetTrue)]
    debug: bool,

    /// Suppress colored progress output (plain text only)
    #[arg(short = 'p', long = "plain", action = ArgAction::SetTrue)]
    plain: bool,

    /// Disable ANSI colors
    #[arg(long = "no-color", action = ArgAction::SetTrue)]
    no_color: bool,

    /// Also write bracketed tags to --sent-log
    #[arg(long = "tagged-log", action = ArgAction::SetTrue)]
    tagged_log: bool,
}

fn parse_mailbox_hex12_arg(v: &str) -> Result<String, String> {
    let s = v.trim();
    if s.len() != 12 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid mailbox '{}': expected exactly 12 hex chars (no 0x)",
            v
        ));
    }
    Ok(s.to_ascii_lowercase())
}

struct DnsResponse {
    id: u16,
    rcode: u8,
    answer_ip: Option<Ipv4Addr>,
}

fn skip_dns_name(buf: &[u8], len: usize, start: usize) -> Option<usize> {
    let mut off = start;
    loop {
        if off >= len {
            return None;
        }
        let b = buf[off];
        if b == 0 {
            return Some(off + 1);
        }
        if b & 0xC0 == 0xC0 {
            if off + 2 > len {
                return None;
            }
            return Some(off + 2);
        }
        off += 1 + b as usize;
    }
}

fn parse_dns_response(buf: &[u8], len: usize) -> Option<DnsResponse> {
    if len < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = (flags & 0x000F) as u8;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut off = skip_dns_name(buf, len, 12)?;
    if off + 4 > len {
        return None;
    }
    off += 4; // QTYPE + QCLASS

    let mut answer_ip = None;
    for _ in 0..ancount {
        off = skip_dns_name(buf, len, off)?;
        if off + 10 > len {
            break;
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
        off += 10;
        if off + rdlen > len {
            break;
        }
        if rtype == 1 && rdlen == 4 && answer_ip.is_none() {
            answer_ip = Some(Ipv4Addr::new(
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ));
        }
        off += rdlen;
    }
    Some(DnsResponse {
        id,
        rcode,
        answer_ip,
    })
}

fn build_query_from_domain(domain: &str) -> Vec<u8> {
    fn write_u16(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    let mut q = Vec::new();
    let id = fastrand::u16(..);
    write_u16(&mut q, id);
    write_u16(&mut q, 0x0100); // RD
    write_u16(&mut q, 1); // QD
    write_u16(&mut q, 0); // AN
    write_u16(&mut q, 0); // NS
    write_u16(&mut q, 0); // AR
    for lab in domain.split('.') {
        q.push(lab.len() as u8);
        q.extend_from_slice(lab.as_bytes());
    }
    q.push(0);
    write_u16(&mut q, 1); // TYPE A
    write_u16(&mut q, 1); // CLASS IN
    q
}

fn parse_system_resolver() -> Option<String> {
    // Very small parser: read the first 'nameserver' entry in /etc/resolv.conf
    // Returns host string (IPv4, IPv6, or hostname) without port.
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("nameserver") {
            let rest = rest.trim();
            if rest.is_empty() {
                continue;
            }
            // Split on whitespace
            let mut parts = rest.split_whitespace();
            if let Some(host) = parts.next() {
                // Basic sanity: prefer an IP literal but accept hostnames
                return Some(host.to_string());
            }
        }
    }
    None
}

fn to_target_addr(host_or_ip: &str) -> String {
    // Cases:
    // 1) bracketed IPv6 with optional port: "[::1]:5353" or "[::1]" -> ensure port
    // 2) raw IPv6 without brackets: "2001:db8::1" -> add brackets + :53
    // 3) hostname or IPv4 with optional :port
    if host_or_ip.starts_with('[') {
        // Bracketed IPv6, possibly with :port. Only treat as having a port when we see "]:" after the closing bracket.
        if let Some(idx) = host_or_ip.find(']') {
            let rest = &host_or_ip[idx..];
            if rest.starts_with("]:") {
                host_or_ip.to_string()
            } else {
                format!("{}:53", host_or_ip)
            }
        } else {
            // Malformed; best effort
            format!("{}:53", host_or_ip)
        }
    } else if Ipv6Addr::from_str(host_or_ip).is_ok() {
        format!("[{}]:53", host_or_ip)
    } else if host_or_ip.contains(':') {
        // Assume host:port
        host_or_ip.to_string()
    } else {
        format!("{}:53", host_or_ip)
    }
}

fn main() -> io::Result<()> {
    let ClientArgs {
        zone,
        resolver_ip,
        dont_query,
        await_reply_ms,
        delay_ms,
        sent_log,
        mailbox: mailbox_arg,
        random_mailbox: _,
        ping,
        debug,
        plain,
        no_color,
        tagged_log,
    } = ClientArgs::parse();

    if no_color {
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
    }

    let mailbox_hex: String = match mailbox_arg {
        Some(mb) => mb,
        None => {
            let mut buf = [0u8; 6];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| {
                    use std::io::Read;
                    f.read_exact(&mut buf)
                })
                .unwrap_or_else(|_| {
                    let v = fastrand::u64(..) & 0x0000_FFFF_FFFF_FFFF;
                    buf.copy_from_slice(&v.to_be_bytes()[2..]);
                });
            format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
            )
        }
    };

    let mailbox_u64: u64 = match u64::from_str_radix(&mailbox_hex, 16) {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "dnsm: invalid mailbox '{}': must be 12 hex chars",
                mailbox_hex
            );
            std::process::exit(2);
        }
    };

    // --- Ping mode ---
    if ping {
        let domain = match build_human_ping_domain(&mailbox_hex, &zone) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("dnsm: {}", e);
                std::process::exit(2);
            }
        };
        eprintln!("dnsm: zone={} ping mailbox={}", zone, mailbox_hex);
        if dont_query {
            println!("{}", domain);
        } else {
            let target_host = if let Some(ref addr) = resolver_ip {
                Some(addr.clone())
            } else {
                parse_system_resolver()
            };
            if let Some(host) = target_host {
                let target = to_target_addr(&host);
                let s = UdpSocket::bind("0.0.0.0:0")?;
                s.connect(&target)
                    .map_err(|e| io::Error::other(format!("connect {}: {}", target, e)))?;
                if await_reply_ms > 0 {
                    s.set_read_timeout(Some(std::time::Duration::from_millis(await_reply_ms)))?;
                }
                let q = build_query_from_domain(&domain);
                let id = u16::from_be_bytes([q[0], q[1]]);
                s.send(&q)?;
                if await_reply_ms > 0 {
                    let mut ack_ok = false;
                    let mut resp_ip: Option<Ipv4Addr> = None;
                    let mut buf = [0u8; 512];
                    match s.recv(&mut buf) {
                        Ok(n) if n >= 12 => {
                            if let Some(resp) = parse_dns_response(&buf, n)
                                && resp.id == id
                                && resp.rcode == 0
                            {
                                ack_ok = true;
                                resp_ip = resp.answer_ip;
                            }
                        }
                        _ => {}
                    }
                    let ip_str = resp_ip.map(|ip| format!(" ip={}", ip)).unwrap_or_default();
                    if ack_ok {
                        if !plain {
                            println!(
                                "{} {}{}",
                                style("[OK]").green().bold(),
                                domain,
                                style(&ip_str).dim()
                            );
                        } else {
                            println!("{} ok{}", domain, ip_str);
                        }
                    } else if !plain {
                        println!(
                            "{} {} after={}ms",
                            style("[TIMEOUT]").yellow().bold(),
                            domain,
                            await_reply_ms
                        );
                    } else {
                        println!("{} timeout after={}ms", domain, await_reply_ms);
                    }
                } else if !plain {
                    println!("{} {}", style("[SEND]").green().bold(), domain);
                } else {
                    println!("{} sent", domain);
                }
            } else {
                println!("{}", domain);
            }
        }
        if zone == "k.dnsm.re" {
            eprintln!("\nInbox: https://dnsm.re/#/inbox/{}", mailbox_hex);
        }
        return Ok(());
    }

    // --- Normal message mode ---
    let mut stdin_data = Vec::new();
    io::stdin().read_to_end(&mut stdin_data)?;

    if let Ok(s) = std::str::from_utf8(&stdin_data) {
        let trimmed = s.trim_end();
        if trimmed.len() != stdin_data.len() {
            stdin_data.truncate(trimmed.len());
        }
    }

    let opts = BuildOptions {
        mailbox: Some(mailbox_u64),
    };
    let (domains, info): (Vec<String>, BuildInfo) =
        match build_domains_for_data(&stdin_data, &zone, &opts) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("dnsm: {}", e);
                std::process::exit(2);
            }
        };

    let mut sock: Option<UdpSocket> = None;
    let mut logfile: Option<io::BufWriter<std::fs::File>> = None;
    if let Some(path) = &sent_log {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        logfile = Some(io::BufWriter::new(f));
    }
    if !dont_query {
        let target_host = if let Some(ref addr) = resolver_ip {
            Some(addr.clone())
        } else {
            parse_system_resolver()
        };
        if let Some(host) = target_host {
            let target = to_target_addr(&host);
            let s = UdpSocket::bind("0.0.0.0:0")?;
            s.connect(&target)
                .map_err(|e| io::Error::other(format!("connect {}: {}", target, e)))?;
            if await_reply_ms > 0 {
                s.set_read_timeout(Some(std::time::Duration::from_millis(await_reply_ms)))?;
            }
            eprintln!("dnsm: sending via resolver {}", target);
            if !plain {
                eprintln!(
                    "{} {}",
                    style("[INFO]").cyan().bold(),
                    style(format!("resolver {}", target)).cyan()
                );
            }
            sock = Some(s);
        } else {
            eprintln!(
                "dnsm: no --resolver-ip and could not parse /etc/resolv.conf; printing hostnames"
            );
        }
    }

    if !plain {
        eprintln!(
            "{} {}={} {}={} {}={} {}={}",
            style("[INFO]").cyan().bold(),
            style("zone").dim(),
            style(&zone).cyan(),
            style("first_payload").dim(),
            style(info.first_payload_len).cyan(),
            style("payload_per_chunk").dim(),
            style(info.payload_per_chunk).cyan(),
            style("total_chunks").dim(),
            style(info.total_chunks).cyan(),
        );
        eprintln!(
            "{} {}={}  {} {}",
            style("[INFO]").cyan().bold(),
            style("mailbox").dim(),
            style(&mailbox_hex).cyan(),
            style("View inbox at").white(),
            style(format!("https://dnsm.re/#/inbox/{}", mailbox_hex)).bold()
        );
        eprintln!();
    } else {
        eprintln!(
            "dnsm: zone={} first_payload={} payload_per_chunk={} total_chunks={} mailbox={}",
            zone, info.first_payload_len, info.payload_per_chunk, info.total_chunks, mailbox_hex
        );
    }

    for (i, qname) in domains.iter().enumerate() {
        let remaining: u16 = (info.total_chunks - 1 - i) as u16;
        if let Some(ref s) = sock {
            let q = build_query_from_domain(qname);
            let id = u16::from_be_bytes([q[0], q[1]]);
            if debug {
                eprintln!(
                    "SEND idx={} remaining={} qname_len={} labels={} id={}",
                    i,
                    remaining,
                    qname.len(),
                    qname.split('.').count(),
                    id
                );
            }
            s.send(&q)?;

            let mut ack_ok = false;
            let mut resp_ip: Option<Ipv4Addr> = None;
            if await_reply_ms > 0 {
                let mut buf = [0u8; 512];
                match s.recv(&mut buf) {
                    Ok(n) if n >= 12 => {
                        if let Some(resp) = parse_dns_response(&buf, n)
                            && resp.id == id
                            && resp.rcode == 0
                        {
                            ack_ok = true;
                            resp_ip = resp.answer_ip;
                        }
                    }
                    _ => {}
                }
            }

            if await_reply_ms > 0 {
                let ip_str = resp_ip.map(|ip| format!(" ip={}", ip)).unwrap_or_default();
                if ack_ok {
                    if !plain {
                        println!(
                            "{} {}{}",
                            style("[OK]").green().bold(),
                            qname,
                            style(&ip_str).dim()
                        );
                    } else {
                        println!("{} ok{}", qname, ip_str);
                    }
                } else if !plain {
                    println!(
                        "{} {} after={}ms",
                        style("[TIMEOUT]").yellow().bold(),
                        qname,
                        await_reply_ms
                    );
                } else {
                    println!("{} timeout after={}ms", qname, await_reply_ms);
                }
            } else if !plain {
                println!("{} {}", style("[SEND]").green().bold(), qname);
            } else {
                println!("{} sent", qname);
            }

            if let Some(ref mut lf) = logfile {
                let _ = writeln!(
                    lf,
                    "SENT idx={} remaining={} qname_len={} labels={} id={} ack={} time_ms={}",
                    i,
                    remaining,
                    qname.len(),
                    qname.split('.').count(),
                    id,
                    if await_reply_ms == 0 {
                        "-"
                    } else if ack_ok {
                        "ok"
                    } else {
                        "timeout"
                    },
                    await_reply_ms
                );
                if tagged_log {
                    let _ = writeln!(
                        lf,
                        "[SEND] idx={} remaining={} qname_len={} labels={} id={}",
                        i,
                        remaining,
                        qname.len(),
                        qname.split('.').count(),
                        id
                    );
                    if await_reply_ms > 0 {
                        let tag = if ack_ok { "[ACK]" } else { "[TIMEOUT]" };
                        let _ =
                            writeln!(lf, "{} id={} idx={} after={}ms", tag, id, i, await_reply_ms);
                    }
                }
                let _ = lf.flush();
            }

            if delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        } else {
            println!("{}", qname);
        }
    }

    if zone == "k.dnsm.re" {
        eprintln!("\nInbox: https://dnsm.re/#/inbox/{}", mailbox_hex);
    }

    Ok(())
}

#[cfg(test)]
#[path = "dnsm/tests.rs"]
mod tests;
