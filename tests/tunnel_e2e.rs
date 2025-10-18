#![cfg(all(feature = "sqlite", feature = "native-cli"))]

use rusqlite::{Connection, params};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TEST_PORT: u16 = 55353;

fn get_bin(name: &str) -> Option<String> {
    let key1 = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(p) = std::env::var(&key1)
        && Path::new(&p).exists()
    {
        return Some(p);
    }
    // Fallback to release path
    let fallback = format!("./target/release/{}", name);
    if Path::new(&fallback).exists() {
        return Some(fallback);
    }
    None
}

fn wait_for_row<F>(timeout_ms: u64, mut check: F) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(timeout_ms) {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn tunnel_random_payloads_end_to_end() {
    let server = match get_bin("dnsm-server") {
        Some(p) => p,
        None => {
            eprintln!("skipping e2e tunnel test: dnsm-server binary not found");
            return;
        }
    };
    let client = match get_bin("dnsm-client") {
        Some(p) => p,
        None => {
            eprintln!("skipping e2e tunnel test: dnsm-client binary not found");
            return;
        }
    };

    let port = TEST_PORT;
    let bind_addr = format!("127.0.0.1:{}", port);
    let fixed_ip = "13.33.33.37";
    let zone = "foo.bar";

    let mut db_dir = std::env::temp_dir();
    db_dir.push(format!(
        "dnsm_e2e_db_{}_{}",
        std::process::id(),
        fastrand::u32(..)
    ));
    fs::create_dir_all(&db_dir).expect("mkdir db dir");
    let db_path = db_dir.join("msgs.sqlite");
    let db = Connection::open(&db_path).expect("open db");
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_key INTEGER NOT NULL,
            mailbox TEXT,
            data BLOB NOT NULL,
            received_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_key ON messages(message_key);",
    )
    .expect("init schema");

    let mut log_path = std::env::temp_dir();
    log_path.push(format!("dnsm_e2e_{}.log", std::process::id()));

    // Start server
    let mut child = Command::new(&server)
        .arg(&bind_addr)
        .arg(zone)
        .arg(fixed_ip)
        .arg(&log_path)
        .arg(db_path.to_string_lossy().as_ref())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("launch server");

    thread::sleep(Duration::from_millis(200));

    // If server exited early, skip test (likely cannot bind in this environment)
    if let Ok(Some(status)) = child.try_wait() {
        eprintln!(
            "skipping e2e tunnel test: server exited early with status {:?}",
            status
        );
        return;
    }

    let sizes: &[usize] = &[1, 2, 30, 59, 60, 61, 127, 1024, 4096, 8191, 16 * 1024];

    for &sz in sizes {
        let mut data = vec![0u8; sz];
        for b in &mut data {
            *b = fastrand::u8(..);
        }

        // Launch client and feed stdin
        let mut cli = Command::new(&client)
            .arg(zone)
            .args(["--resolver-ip", &bind_addr])
            .args(["--await-reply-ms", "20"]) // small ack wait keeps things orderly
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn client");
        if let Some(mut stdin) = cli.stdin.take() {
            stdin.write_all(&data).expect("write stdin");
        }
        let _ = cli.wait();

        // Peek server log for a chunk event (JSON lines)
        let mut saw_chunk = false;
        if let Ok(contents) = fs::read_to_string(&log_path)
            && contents.contains("\"event\":\"chunk\"")
        {
            saw_chunk = true;
        }

        // Wait for server to persist the assembled message
        let ok = wait_for_row(5000, || {
            let exists: i64 = db
                .query_row("SELECT COUNT(1) FROM messages", params![], |row| row.get(0))
                .unwrap_or(0);
            exists > 0
        });
        if !ok {
            let log_dump =
                fs::read_to_string(&log_path).unwrap_or_else(|_| String::from("<no log>"));
            panic!(
                "server did not persist message (size {}), saw_chunk={}\nLOG:\n{}",
                sz, saw_chunk, log_dump
            );
        }
        let assembled: Vec<u8> = db
            .query_row(
                "SELECT data FROM messages ORDER BY id DESC LIMIT 1",
                params![],
                |row| row.get(0),
            )
            .expect("fetch data");
        assert_eq!(assembled, data, "mismatch for size {}", sz);
        // Cleanup row to keep DB lean
        let _ = db.execute("DELETE FROM messages", params![]);
    }

    // 250 randomized runs with length in [1, max_for_test]
    // Compute per-chunk payload capacity for this zone (same math as client)
    let zone_labels: Vec<String> = zone
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let zone_sum_len: usize = zone_labels.iter().map(|s| s.len()).sum();
    let zone_label_count = zone_labels.len();
    let payload_per_chunk = {
        let mut lo = 0usize;
        let mut hi = 4096usize;
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            let total_bytes = 8 + mid;
            let enc_len = (total_bytes * 8).div_ceil(5);
            let data_label_count = enc_len.div_ceil(63);
            let total_labels = data_label_count + zone_label_count;
            let wire_len = enc_len + zone_sum_len + total_labels + 1; // +1 for root dot
            if wire_len <= 255 {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    };
    let _max_supported_bytes = payload_per_chunk.saturating_mul(65_536);
    // Cap to keep test runtime reasonable: up to 128 chunks worth per run
    let max_for_test = usize::max(1, payload_per_chunk.saturating_mul(128));

    for _ in 0..250 {
        let sz = 1 + fastrand::usize(..max_for_test);
        let mut data = vec![0u8; sz];
        for b in &mut data {
            *b = fastrand::u8(..);
        }

        let mut cli = Command::new(&client)
            .arg(zone)
            .args(["--resolver-ip", &bind_addr])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn client fuzz");
        if let Some(mut stdin) = cli.stdin.take() {
            stdin.write_all(&data).expect("write stdin (fuzz)");
        }
        let _ = cli.wait();

        let ok = wait_for_row(10_000, || {
            let exists: i64 = db
                .query_row("SELECT COUNT(1) FROM messages", params![], |row| row.get(0))
                .unwrap_or(0);
            exists > 0
        });
        if !ok {
            let log_dump =
                fs::read_to_string(&log_path).unwrap_or_else(|_| String::from("<no log>"));
            panic!(
                "fuzz: server did not persist message (size {})\nLOG:\n{}",
                sz, log_dump
            );
        }
        let assembled: Vec<u8> = db
            .query_row(
                "SELECT data FROM messages ORDER BY id DESC LIMIT 1",
                params![],
                |row| row.get(0),
            )
            .expect("fetch data (fuzz)");
        assert_eq!(assembled, data, "fuzz mismatch size {}", sz);
        let _ = db.execute("DELETE FROM messages", params![]);
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&log_path);
    let _ = fs::remove_dir_all(&db_dir);
}
