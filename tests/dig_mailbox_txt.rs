#![cfg(all(feature = "sqlite", feature = "native-cli"))]

use rusqlite::{Connection, params};
use std::net::UdpSocket;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn have_dig() -> bool {
    Command::new("dig")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn find_free_udp_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = sock.local_addr().expect("local_addr").port();
    drop(sock);
    port
}

fn wait_for_server(port: u16, attempts: usize, delay_ms: u64) -> bool {
    for _ in 0..attempts {
        let status = Command::new("dig")
            .args([
                "+short",
                "@127.0.0.1",
                "-p",
                &port.to_string(),
                "x.example",
                "A",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if let Ok(s) = status
            && s.success()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(delay_ms));
    }
    false
}

#[test]
fn dig_mailbox_txt_returns_messages() {
    if !have_dig() {
        eprintln!("skipping: 'dig' not installed");
        return;
    }

    let server_path = std::env::var("CARGO_BIN_EXE_dnsm_server")
        .unwrap_or_else(|_| "./target/release/dnsm-server".to_string());
    if !Path::new(&server_path).exists() {
        eprintln!("skipping: server binary not found at {}", server_path);
        return;
    }

    // Prepare sqlite db with messages for mailbox 0x42 (stored as 12-hex string)
    let tmp = std::env::temp_dir().join(format!("dnsm_it_mbx_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("msgs.sqlite");
    let conn = Connection::open(&db_path).unwrap();
    let _ = conn.execute("DROP TABLE IF EXISTS messages", []);
    conn.execute(
        "CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_key INTEGER NOT NULL,
            mailbox TEXT,
            data BLOB NOT NULL,
            received_at INTEGER NOT NULL,
            message_id BLOB
        )",
        [],
    )
    .unwrap();
    // Ensure fresh schema
    conn.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (1, '000000000042', ?1, 1)",
        params![&b"hello"[..]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (2, '000000000042', ?1, 2)",
        params![&b"world"[..]],
    )
    .unwrap();

    let port = find_free_udp_port();
    let bind_addr = format!("127.0.0.1:{}", port);

    // Start server with zone + mailbox-zone + positional fixed_ip, log_path, db
    let mut child = Command::new(server_path.clone())
        .arg("x.example")
        .arg("--bind")
        .arg(&bind_addr)
        .arg("--mailbox-zone")
        .arg("m.example")
        .arg("--respond_with")
        .arg("127.0.0.1")
        .arg("--log")
        .arg(tmp.join("log.txt").to_string_lossy().to_string())
        .arg("--db")
        .arg(db_path.to_string_lossy().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("launch server");

    assert!(
        wait_for_server(port, 100, 50),
        "server did not become ready on time"
    );

    // Query TXT for 000000000042.m.example
    let output = Command::new("dig")
        .args([
            "+short",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "000000000042.m.example",
            "TXT",
        ])
        .output()
        .expect("run dig");

    // Teardown first to avoid flaking on windows-like envs (not used here but safe)
    let _ = child.kill();
    let _ = child.wait();

    // Assert the TXT includes our messages (content may be prefixed by session id)
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("hello") || !stdout.contains("world") {
        eprintln!("dig output: {}", stdout);
    }
    assert!(stdout.contains("hello"));
    assert!(stdout.contains("world"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dig_mailbox_txt_dedupes_messages() {
    if !have_dig() {
        eprintln!("skipping: 'dig' not installed");
        return;
    }

    let server_path = std::env::var("CARGO_BIN_EXE_dnsm_server")
        .unwrap_or_else(|_| "./target/release/dnsm-server".to_string());
    if !std::path::Path::new(&server_path).exists() {
        eprintln!("skipping: server binary not found at {}", server_path);
        return;
    }

    // Prepare sqlite db with duplicate messages for mailbox 0x42
    let tmp = std::env::temp_dir().join(format!("dnsm_it_mbx_dedup_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("msgs.sqlite");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_key INTEGER NOT NULL,
            mailbox TEXT,
            data BLOB NOT NULL,
            received_at INTEGER NOT NULL,
            message_id BLOB
        );",
    )
    .unwrap();
    // Insert duplicates of "hello" and a single "world"
    for (sid, ts) in &[(1i64, 1i64), (2, 2), (3, 3)] {
        conn.execute(
            "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (?1, '000000000042', ?2, ?3)",
            rusqlite::params![sid, &b"hello"[..], ts],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (4, '000000000042', ?1, 4)",
        params![&b"world"[..]],
    )
    .unwrap();

    let port = find_free_udp_port();
    let bind_addr = format!("127.0.0.1:{}", port);

    // Start server with zone + mailbox-zone + positional fixed_ip, log_path, db
    let mut child = std::process::Command::new(server_path.clone())
        .arg("x.example")
        .arg("--bind")
        .arg(&bind_addr)
        .arg("--mailbox-zone")
        .arg("m.example")
        .arg("--respond_with")
        .arg("127.0.0.1")
        .arg("--log")
        .arg(tmp.join("log.txt").to_string_lossy().to_string())
        .arg("--db")
        .arg(db_path.to_string_lossy().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("launch server");

    assert!(
        wait_for_server(port, 100, 50),
        "server did not become ready on time"
    );

    // Query TXT for 000000000042.m.example
    let output = std::process::Command::new("dig")
        .args([
            "+short",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "000000000042.m.example",
            "TXT",
        ])
        .output()
        .expect("run dig");

    // Teardown
    let _ = child.kill();
    let _ = child.wait();

    // Expect exactly one "hello" and one "world" in the TXT answers
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hello_count = stdout.matches("hello").count();
    let world_count = stdout.matches("world").count();
    if hello_count != 1 || world_count != 1 {
        eprintln!("dig output: {}", stdout);
    }
    assert_eq!(hello_count, 1);
    assert_eq!(world_count, 1);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dig_mailbox_txt_paging_by_message_returns_older() {
    if !have_dig() {
        eprintln!("skipping: 'dig' not installed");
        return;
    }

    let server_path = std::env::var("CARGO_BIN_EXE_dnsm_server")
        .unwrap_or_else(|_| "./target/release/dnsm-server".to_string());
    if !std::path::Path::new(&server_path).exists() {
        eprintln!("skipping: server binary not found at {}", server_path);
        return;
    }

    let tmp = std::env::temp_dir().join(format!("dnsm_it_mbx_page_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("msgs.sqlite");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_key INTEGER NOT NULL,
            mailbox TEXT,
            data BLOB NOT NULL,
            received_at INTEGER NOT NULL,
            message_id BLOB
        );",
    )
    .unwrap();
    // Three messages with increasing received_at
    let mbox_hex = "000000000042";
    conn.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (1, ?1, ?2, 10)",
        rusqlite::params![mbox_hex, &b"m1"[..]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (2, ?1, ?2, 20)",
        rusqlite::params![mbox_hex, &b"m2"[..]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (3, ?1, ?2, 30)",
        rusqlite::params![mbox_hex, &b"m3"[..]],
    )
    .unwrap();

    let port = find_free_udp_port();
    let bind_addr = format!("127.0.0.1:{}", port);

    let mut child = std::process::Command::new(server_path.clone())
        .arg("x.example")
        .arg("--bind")
        .arg(&bind_addr)
        .arg("--mailbox-zone")
        .arg("m.example")
        .arg("--respond_with")
        .arg("127.0.0.1")
        .arg("--log")
        .arg(tmp.join("log.txt").to_string_lossy().to_string())
        .arg("--db")
        .arg(db_path.to_string_lossy().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("launch server");

    assert!(
        wait_for_server(port, 100, 50),
        "server did not become ready on time"
    );

    // First page: latest-first for mailbox
    let output1 = std::process::Command::new("dig")
        .args([
            "+short",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "000000000042.m.example",
            "TXT",
        ])
        .output()
        .expect("run dig");
    let s1 = String::from_utf8_lossy(&output1.stdout);
    let lines: Vec<&str> = s1.lines().collect();
    assert!(lines.len() >= 2, "unexpected dig output: {}", s1);
    // Second line corresponds to the second-newest message
    let line2 = lines[1].trim();
    // Extract the session prefix up to the first backslash (dig escapes TAB as \009)
    let msg_hex = line2
        .trim_start_matches('"')
        .split('\\')
        .next()
        .unwrap_or("");

    // Page older than that message id: expect only m1
    let query2 = format!("{}.000000000042.m.example", msg_hex);
    let output2 = std::process::Command::new("dig")
        .args([
            "+short",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            &query2,
            "TXT",
        ])
        .output()
        .expect("run dig page 2");
    let s2 = String::from_utf8_lossy(&output2.stdout);
    assert!(s2.contains("m1"), "expected m1 in page, got: {}", s2);
    assert!(!s2.contains("m2"), "did not expect m2 in page, got: {}", s2);
    assert!(!s2.contains("m3"), "did not expect m3 in page, got: {}", s2);

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&tmp);
}
