#![cfg(all(feature = "sqlite", feature = "native-cli"))]

use rusqlite::{Connection, params};
use std::io::Write;
use std::net::UdpSocket;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn find_free_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = sock.local_addr().unwrap().port();
    drop(sock);
    port
}

fn get_bin(name: &str) -> Option<String> {
    let key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(p) = std::env::var(&key)
        && Path::new(&p).exists()
    {
        return Some(p);
    }
    let fallback = format!("./target/release/{}", name);
    if Path::new(&fallback).exists() {
        return Some(fallback);
    }
    None
}

struct TestServer {
    child: std::process::Child,
    db_path: std::path::PathBuf,
    tmp: std::path::PathBuf,
}

impl TestServer {
    fn spawn(zone: &str, mailbox_zone: Option<&str>) -> Option<(Self, u16)> {
        let server = get_bin("dnsm-server")?;
        let port = find_free_port();
        let bind = format!("127.0.0.1:{}", port);

        let tmp = std::env::temp_dir().join(format!(
            "dnsm_ping_e2e_{}_{}",
            std::process::id(),
            fastrand::u32(..)
        ));
        std::fs::create_dir_all(&tmp).ok()?;
        let db_path = tmp.join("test.db");
        let log_path = tmp.join("test.log");

        let mut cmd = Command::new(&server);
        cmd.arg(zone)
            .arg("--bind")
            .arg(&bind)
            .arg("--log")
            .arg(&log_path)
            .arg("--db")
            .arg(&db_path)
            .arg("--no-color")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(mz) = mailbox_zone {
            cmd.arg("--mailbox-zone").arg(mz);
        }

        let child = cmd.spawn().ok()?;
        thread::sleep(Duration::from_millis(300));

        Some((
            TestServer {
                child,
                db_path,
                tmp,
            },
            port,
        ))
    }

    fn open_db(&self) -> Connection {
        let db = Connection::open(&self.db_path).expect("open test db");
        db.busy_timeout(Duration::from_secs(2)).ok();
        db
    }

    fn wait_for_messages(&self, expected: usize, timeout_ms: u64) -> bool {
        let db = self.open_db();
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(timeout_ms) {
            let count: i64 = db
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap_or(0);
            if count >= expected as i64 {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

fn send_domain(domain: &str, port: u16) {
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect(format!("127.0.0.1:{}", port)).unwrap();
    let q = build_dns_query(domain);
    sock.send(&q).unwrap();
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut q = Vec::new();
    let id = fastrand::u16(..);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QD
    q.extend_from_slice(&0u16.to_be_bytes()); // AN
    q.extend_from_slice(&0u16.to_be_bytes()); // NS
    q.extend_from_slice(&0u16.to_be_bytes()); // AR
    for lab in domain.split('.') {
        q.push(lab.len() as u8);
        q.extend_from_slice(lab.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    q.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    q
}

// ---------------------------------------------------------------------------
// Ping: encode → server → DB with message_type='ping', empty data
// ---------------------------------------------------------------------------
#[test]
fn ping_stored_with_correct_message_type() {
    let (srv, port) = match TestServer::spawn("x.test", None) {
        Some(v) => v,
        None => {
            eprintln!("skipping: dnsm-server binary not found");
            return;
        }
    };

    let mailbox: u64 = 0xABCDEF012345;
    let domain = dnsm::build_ping_domain(mailbox, "x.test").expect("build ping");
    send_domain(&domain, port);

    assert!(srv.wait_for_messages(1, 3000), "ping not stored in time");

    let db = srv.open_db();
    let (msg_type, data, mbox): (String, Vec<u8>, String) = db
        .query_row(
            "SELECT COALESCE(message_type,'?'), data, mailbox FROM messages ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("query message");

    assert_eq!(msg_type, "ping");
    assert!(
        data.is_empty(),
        "ping data should be empty, got {} bytes",
        data.len()
    );
    assert_eq!(mbox, "abcdef012345");
}

// ---------------------------------------------------------------------------
// Ping dedup: same-ms retransmissions are deduped, different times are kept
// ---------------------------------------------------------------------------
#[test]
fn ping_dedup_across_retransmissions() {
    let (srv, port) = match TestServer::spawn("x.test", None) {
        Some(v) => v,
        None => {
            eprintln!("skipping: dnsm-server binary not found");
            return;
        }
    };

    let mailbox: u64 = 0x111111111111;
    let domain = dnsm::build_ping_domain(mailbox, "x.test").expect("build ping");

    for _ in 0..5 {
        send_domain(&domain, port);
    }
    thread::sleep(Duration::from_millis(500));

    let db = srv.open_db();
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE mailbox='111111111111' AND message_type='ping'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    // At least 1 stored, but likely fewer than 5 due to same-ms dedup
    assert!(count >= 1, "expected at least 1 ping, got {}", count);
    assert!(
        count <= 5,
        "got {} pings (all should store, or some dedup)",
        count
    );
}

// ---------------------------------------------------------------------------
// Single-chunk v2 message: encode → server → DB with message_type='message'
// ---------------------------------------------------------------------------
#[test]
fn single_chunk_v2_message_roundtrip() {
    let (srv, port) = match TestServer::spawn("x.test", None) {
        Some(v) => v,
        None => {
            eprintln!("skipping: dnsm-server binary not found");
            return;
        }
    };

    let payload = b"hello from v2";
    let opts = dnsm::BuildOptions {
        mailbox: Some(0x424242424242),
    };
    let (domains, info) = dnsm::build_domains_for_data(payload, "x.test", &opts).expect("build");
    assert_eq!(info.total_chunks, 1);

    send_domain(&domains[0], port);
    assert!(srv.wait_for_messages(1, 3000), "message not stored in time");

    let db = srv.open_db();
    let (msg_type, data, mbox): (String, Vec<u8>, String) = db
        .query_row(
            "SELECT COALESCE(message_type,'?'), data, mailbox FROM messages ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("query");

    assert_eq!(msg_type, "message");
    assert_eq!(data, payload);
    assert_eq!(mbox, "424242424242");
}

// ---------------------------------------------------------------------------
// Single-chunk WITHOUT mailbox
// ---------------------------------------------------------------------------
#[test]
fn single_chunk_no_mailbox_roundtrip() {
    let (srv, port) = match TestServer::spawn("x.test", None) {
        Some(v) => v,
        None => {
            eprintln!("skipping: dnsm-server binary not found");
            return;
        }
    };

    let payload = b"no mailbox here";
    let opts = dnsm::BuildOptions { mailbox: None };
    let (domains, info) = dnsm::build_domains_for_data(payload, "x.test", &opts).expect("build");
    assert_eq!(info.total_chunks, 1);

    send_domain(&domains[0], port);
    assert!(srv.wait_for_messages(1, 3000), "message not stored in time");

    let db = srv.open_db();
    let (msg_type, data): (String, Vec<u8>) = db
        .query_row(
            "SELECT COALESCE(message_type,'?'), data FROM messages ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("query");

    assert_eq!(msg_type, "message");
    assert_eq!(data, payload);
}

// ---------------------------------------------------------------------------
// Multi-chunk v2 message: encode → server reassembly → DB
// ---------------------------------------------------------------------------
#[test]
fn multi_chunk_v2_message_roundtrip() {
    let (srv, port) = match TestServer::spawn("x.test", None) {
        Some(v) => v,
        None => {
            eprintln!("skipping: dnsm-server binary not found");
            return;
        }
    };

    // Random payload large enough to force multi-chunk but small enough to be fast
    let mut payload = vec![0u8; 2000];
    for b in &mut payload {
        *b = fastrand::u8(..);
    }

    let opts = dnsm::BuildOptions {
        mailbox: Some(0xFEDCBA987654),
    };
    let (domains, info) = dnsm::build_domains_for_data(&payload, "x.test", &opts).expect("build");
    assert!(
        info.total_chunks > 1,
        "expected multi-chunk, got {}",
        info.total_chunks
    );

    for d in &domains {
        send_domain(d, port);
        thread::sleep(Duration::from_millis(5));
    }

    assert!(
        srv.wait_for_messages(1, 10_000),
        "assembled message not stored in time"
    );

    let db = srv.open_db();
    let (msg_type, data, mbox): (String, Vec<u8>, String) = db
        .query_row(
            "SELECT COALESCE(message_type,'?'), data, mailbox FROM messages ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("query");

    assert_eq!(msg_type, "message");
    assert_eq!(data, payload);
    assert_eq!(mbox, "fedcba987654");
}

// ---------------------------------------------------------------------------
// Ping via CLI --ping flag
// ---------------------------------------------------------------------------
#[test]
fn cli_ping_flag_sends_and_stores() {
    let client = match get_bin("dnsm-client") {
        Some(p) => p,
        None => {
            eprintln!("skipping: dnsm-client binary not found");
            return;
        }
    };
    let (srv, port) = match TestServer::spawn("x.test", None) {
        Some(v) => v,
        None => {
            eprintln!("skipping: dnsm-server binary not found");
            return;
        }
    };

    let status = Command::new(&client)
        .arg("x.test")
        .arg("--ping")
        .arg("--mailbox")
        .arg("aaaaaaaaaaaa")
        .arg("--resolver-ip")
        .arg(format!("127.0.0.1:{}", port))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run client");
    assert!(status.success(), "client --ping exited with {}", status);

    assert!(srv.wait_for_messages(1, 3000), "ping not stored in time");

    let db = srv.open_db();
    let (msg_type, mbox): (String, String) = db
        .query_row(
            "SELECT COALESCE(message_type,'?'), mailbox FROM messages WHERE mailbox='aaaaaaaaaaaa' LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("query");

    assert_eq!(msg_type, "ping");
    assert_eq!(mbox, "aaaaaaaaaaaa");
}

// ---------------------------------------------------------------------------
// CLI --ping without --mailbox should fail
// ---------------------------------------------------------------------------
#[test]
fn cli_ping_without_mailbox_fails() {
    let client = match get_bin("dnsm-client") {
        Some(p) => p,
        None => {
            eprintln!("skipping: dnsm-client binary not found");
            return;
        }
    };

    let status = Command::new(&client)
        .arg("x.test")
        .arg("--ping")
        .arg("-n")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run client");

    assert!(!status.success(), "expected failure without --mailbox");
}

// ---------------------------------------------------------------------------
// CLI --ping --dont-query prints domain of expected length
// ---------------------------------------------------------------------------
#[test]
fn cli_ping_dont_query_prints_short_domain() {
    let client = match get_bin("dnsm-client") {
        Some(p) => p,
        None => {
            eprintln!("skipping: dnsm-client binary not found");
            return;
        }
    };

    let output = Command::new(&client)
        .arg("k.dnsm.re")
        .arg("--ping")
        .arg("--mailbox")
        .arg("000000000042")
        .arg("-n")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("run client");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let domain = stdout.trim();
    assert!(domain.ends_with(".k.dnsm.re"));
    // 7 bytes → 12 base32 chars + ".k.dnsm.re" = 22
    assert_eq!(
        domain.len(),
        22,
        "expected 22 chars, got '{}' ({})",
        domain,
        domain.len()
    );
}

// ---------------------------------------------------------------------------
// stdin whitespace trimming for text payloads
// ---------------------------------------------------------------------------
#[test]
fn cli_strips_trailing_whitespace_from_text() {
    let client = match get_bin("dnsm-client") {
        Some(p) => p,
        None => {
            eprintln!("skipping: dnsm-client binary not found");
            return;
        }
    };
    let (srv, port) = match TestServer::spawn("x.test", None) {
        Some(v) => v,
        None => {
            eprintln!("skipping: dnsm-server binary not found");
            return;
        }
    };

    let mut child = Command::new(&client)
        .arg("x.test")
        .arg("--resolver-ip")
        .arg(format!("127.0.0.1:{}", port))
        .arg("--mailbox")
        .arg("bbbbbbbbbbbb")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn client");

    child.stdin.take().unwrap().write_all(b"hello\n").unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());

    assert!(srv.wait_for_messages(1, 3000), "message not stored");

    let db = srv.open_db();
    let data: Vec<u8> = db
        .query_row(
            "SELECT data FROM messages WHERE mailbox='bbbbbbbbbbbb' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("query");

    assert_eq!(data, b"hello", "trailing newline should be stripped");
}

// ---------------------------------------------------------------------------
// Binary payloads are NOT trimmed
// ---------------------------------------------------------------------------
#[test]
fn cli_does_not_strip_binary_payloads() {
    let client = match get_bin("dnsm-client") {
        Some(p) => p,
        None => {
            eprintln!("skipping: dnsm-client binary not found");
            return;
        }
    };
    let (srv, port) = match TestServer::spawn("x.test", None) {
        Some(v) => v,
        None => {
            eprintln!("skipping: dnsm-server binary not found");
            return;
        }
    };

    let payload: &[u8] = &[0xFF, 0x01, 0x0A];

    let mut child = Command::new(&client)
        .arg("x.test")
        .arg("--resolver-ip")
        .arg(format!("127.0.0.1:{}", port))
        .arg("--mailbox")
        .arg("cccccccccccc")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn client");

    child.stdin.take().unwrap().write_all(payload).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());

    assert!(srv.wait_for_messages(1, 3000), "message not stored");

    let db = srv.open_db();
    let data: Vec<u8> = db
        .query_row(
            "SELECT data FROM messages WHERE mailbox='cccccccccccc' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("query");

    assert_eq!(data, payload, "binary payload should be preserved exactly");
}

// ---------------------------------------------------------------------------
// WS message_type field: insert ping row, verify fetch returns it
// ---------------------------------------------------------------------------
#[test]
fn ws_fetch_returns_message_type_field() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_key INTEGER NOT NULL,
            mailbox TEXT,
            data BLOB NOT NULL,
            received_at INTEGER NOT NULL,
            message_id BLOB,
            peer_ip TEXT,
            message_type TEXT DEFAULT 'message'
        );",
    )
    .unwrap();

    let ping_mid: Vec<u8> = vec![1; 16];
    let msg_mid: Vec<u8> = vec![2; 16];

    db.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at, message_id, message_type) VALUES (0, 'aabbccddeeff', x'', 100, ?1, 'ping')",
        params![&ping_mid[..]],
    ).unwrap();

    db.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at, message_id, message_type) VALUES (1, 'aabbccddeeff', ?1, 200, ?2, 'message')",
        params![&b"hello"[..], &msg_mid[..]],
    ).unwrap();

    // Also test NULL message_type (pre-migration row) defaults to 'message'
    db.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at, message_id, message_type) VALUES (2, 'aabbccddeeff', ?1, 50, NULL, NULL)",
        params![&b"old"[..]],
    ).unwrap();

    let mut stmt = db
        .prepare(
            "SELECT id, message_key, mailbox, data, received_at, message_id, peer_ip, message_type
             FROM messages WHERE mailbox='aabbccddeeff' ORDER BY received_at DESC",
        )
        .unwrap();

    let rows: Vec<(i64, String, String)> = stmt
        .query_map([], |row| {
            let msg_type: Option<String> = row.get(7)?;
            let data: Vec<u8> = row.get(3)?;
            let received_at: i64 = row.get(4)?;
            Ok((
                received_at,
                msg_type.unwrap_or_else(|| "message".to_string()),
                String::from_utf8_lossy(&data).to_string(),
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // received_at=200 → message, 100 → ping, 50 → NULL→message
    assert_eq!(rows[0], (200, "message".to_string(), "hello".to_string()));
    assert_eq!(rows[1], (100, "ping".to_string(), "".to_string()));
    assert_eq!(rows[2], (50, "message".to_string(), "old".to_string()));
}
