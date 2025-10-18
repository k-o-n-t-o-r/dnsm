use clap::{ArgAction, Parser};
use console::style;
use dnsm::{BuildInfo, BuildOptions, build_domains_for_data};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, UdpSocket};
use std::str::FromStr;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "dnsm-client",
    about = "Send data via DNS queries",
    long_about = "Reads from stdin and emits DNS queries carrying the data, or prints\n\
                  hostnames (one per chunk) when --dont-query is used.\n\
                  \n\
                  Examples:\n\
                  \n\
                  - echo 'hello' | dnsm-client x.foo.bar --dont-query\n\
                  - echo 'hello' | dnsm-client x.foo.bar --await-reply-ms 50 --delay-ms 2 --debug\n\
    - head -c 200000 /dev/urandom | dnsm-client x.foo.bar --resolver-ip 127.0.0.1:5353",
    disable_help_subcommand = true
)]
struct ClientArgs {
    /// Zone/apex the payload labels are appended to
    #[arg(value_name = "ZONE")]
    zone: String,

    /// Send to this resolver (default: first nameserver in /etc/resolv.conf)
    #[arg(long = "resolver-ip", value_name = "HOST[:PORT]")]
    resolver_ip: Option<String>,

    /// Do not send; print hostnames (one per chunk)
    #[arg(short = 'n', long = "dont-query", action = ArgAction::SetTrue)]
    dont_query: bool,

    /// Wait up to this many ms for a reply to each query (0 disables)
    #[arg(long = "await-reply-ms", value_name = "MS", default_value_t = 0)]
    await_reply_ms: u64,

    /// Sleep this many ms between queries
    #[arg(long = "delay-ms", value_name = "MS", default_value_t = 5)]
    delay_ms: u64,

    /// Append a human-readable send log to this file
    #[arg(long = "sent-log", value_name = "PATH")]
    sent_log: Option<String>,

    /// Optional mailbox ID (exactly 12 hex chars, no 0x)
    #[arg(long = "mailbox", value_name = "HEX12", value_parser = parse_mailbox_hex12_arg)]
    mailbox: Option<String>,

    /// Generate a random mailbox ID (conflicts with --mailbox)
    #[arg(long = "random-mailbox", action = ArgAction::SetTrue, conflicts_with = "mailbox")]
    random_mailbox: bool,

    /// Verbose progress to stderr
    #[arg(long = "debug", action = ArgAction::SetTrue)]
    debug: bool,

    /// Print send progress to stdout with colors (does not affect --dont-query output)
    #[arg(short = 'p', long = "pretty", action = ArgAction::SetTrue)]
    pretty_stdout: bool,

    /// Disable ANSI colors even when --pretty is used
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
            "invalid --mailbox '{}': expected exactly 12 hex chars (no 0x)",
            v
        ));
    }
    Ok(s.to_ascii_lowercase())
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
        random_mailbox,
        debug,
        pretty_stdout,
        no_color,
        tagged_log,
    } = ClientArgs::parse();

    if no_color {
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
    }

    let mailbox_hex: Option<String> = if random_mailbox {
        let v = fastrand::u64(..) & 0x0000_FFFF_FFFF_FFFF;
        Some(format!("{:012x}", v))
    } else {
        mailbox_arg
    };

    // Read stdin
    let mut stdin = Vec::new();
    io::stdin().read_to_end(&mut stdin)?;
    // Build domains using shared library (handles LZMA + mailbox + sizing)
    let mailbox_u64: Option<u64> = match mailbox_hex.as_deref() {
        None => None,
        Some(s) => match u64::from_str_radix(s, 16) {
            Ok(v) => Some(v),
            Err(_) => {
                eprintln!(
                    "dnsm-client: invalid --mailbox '{}': must be 12 hex chars",
                    s
                );
                std::process::exit(2);
            }
        },
    };

    let opts = BuildOptions {
        mailbox: mailbox_u64,
    };
    let (domains, info): (Vec<String>, BuildInfo) =
        match build_domains_for_data(&stdin, &zone, &opts) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("dnsm-client: {}", e);
                std::process::exit(2);
            }
        };

    // If not --dont-query, set up UDP socket to either --resolver-ip or system resolver
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
            eprintln!("dnsm-client: sending via resolver {}", target);
            if pretty_stdout {
                println!(
                    "{} {}",
                    style("[INFO]").cyan().bold(),
                    style(format!("resolver {}", target)).cyan()
                );
            }
            sock = Some(s);
        } else {
            eprintln!(
                "dnsm-client: no --resolver-ip and could not parse /etc/resolv.conf; printing hostnames"
            );
        }
    }

    eprintln!(
        "dnsm-client: zone={} first_payload={} payload_per_chunk={} total_chunks={}{}",
        zone,
        info.first_payload_len,
        info.payload_per_chunk,
        info.total_chunks,
        match mailbox_hex.as_deref() {
            Some(s) => format!(" mailbox={}", s),
            None => String::new(),
        }
    );

    if pretty_stdout && let Some(ref s) = mailbox_hex {
        println!(
            "{} {}",
            style("[INFO]").cyan().bold(),
            style(format!("mailbox {}", s)).cyan()
        );
    }

    for (i, qname) in domains.iter().enumerate() {
        let remaining: u16 = (info.total_chunks - 1 - i) as u16;
        if let Some(ref s) = sock {
            let sent_chunks = i + 1;
            let pct = if info.total_chunks == 0 {
                100.0
            } else {
                (sent_chunks as f64 / info.total_chunks as f64) * 100.0
            };
            eprintln!(
                "dnsm-client: progress {}/{} ({:.1}%)",
                sent_chunks, info.total_chunks, pct
            );
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
            if pretty_stdout {
                println!(
                    "{} idx={} remaining={} qname_len={} labels={} id={}",
                    style("[SEND]").green().bold(),
                    i,
                    remaining,
                    qname.len(),
                    qname.split('.').count(),
                    id
                );
            }
            s.send(&q)?;

            let mut ack_ok = false;
            if await_reply_ms > 0 {
                let mut buf = [0u8; 512];
                match s.recv(&mut buf) {
                    Ok(n) if n >= 2 => {
                        let rid = u16::from_be_bytes([buf[0], buf[1]]);
                        if rid == id {
                            ack_ok = true;
                        }
                    }
                    _ => {}
                }
            }

            if pretty_stdout && await_reply_ms > 0 {
                if ack_ok {
                    println!("{} id={} idx={}", style("[ACK]").green().bold(), id, i);
                } else {
                    println!(
                        "{} id={} idx={} after={}ms",
                        style("[TIMEOUT]").yellow().bold(),
                        id,
                        i,
                        await_reply_ms
                    );
                }
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

    Ok(())
}

#[cfg(test)]
#[path = "dnsm_client/tests.rs"]
mod tests;
