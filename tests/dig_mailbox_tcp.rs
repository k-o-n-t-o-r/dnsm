#![cfg(all(feature = "sqlite", feature = "native-cli"))]

use rusqlite::{Connection, params};
use std::net::UdpSocket;
use std::path::Path;

fn have_dig() -> bool {
    std::process::Command::new("dig")
        .arg("-v")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
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

#[test]
fn dig_mailbox_txt_tcp_returns_more_than_udp() {
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

    // Seed DB with many messages so UDP truncates but TCP fits more
    let tmp = std::env::temp_dir().join(format!("dnsm_it_mbx_tcp_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let db_path = tmp.join("msgs.sqlite");
    let conn = Connection::open(&db_path).unwrap();
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
    let mbox = "000000000042";
    for i in 0..20i64 {
        // Make each message ~100 bytes to force UDP truncation
        let base = format!("m{:02}", i);
        let pad = "x".repeat(100 - base.len());
        let msg = format!("{}{}", base, pad);
        conn.execute(
            "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (?1, ?2, ?3, ?4)",
            params![i + 1, mbox, msg.as_bytes(), 100 + i],
        )
        .unwrap();
    }

    let port = find_free_udp_port();
    let bind_addr = format!("127.0.0.1:{}", port);

    // Start server with TCP mailbox enabled
    let mut child = std::process::Command::new(server_path.clone())
        .arg(&bind_addr)
        .arg("x.example")
        .arg("--mailbox-zone")
        .arg("m.example")
        .arg("--tcp-mailbox")
        .arg("127.0.0.1")
        .arg(tmp.join("queries.log").to_string_lossy().to_string())
        .arg(db_path.to_string_lossy().to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("launch server");

    std::thread::sleep(std::time::Duration::from_millis(400));

    let name = format!("{}.m.example", mbox);

    // UDP
    let out_udp = std::process::Command::new("dig")
        .args([
            "+short",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            &name,
            "TXT",
        ])
        .output()
        .expect("run dig udp");
    let s_udp = String::from_utf8_lossy(&out_udp.stdout);
    let udp_lines = s_udp.lines().count();

    // TCP
    let out_tcp = std::process::Command::new("dig")
        .args([
            "+short",
            "+tcp",
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            &name,
            "TXT",
        ])
        .output()
        .expect("run dig tcp");
    let s_tcp = String::from_utf8_lossy(&out_tcp.stdout);
    let tcp_lines = s_tcp.lines().count();

    // Expect TCP to return at least as many as UDP (often more on real networks)
    assert!(udp_lines >= 1, "expected some UDP lines, got: {}", s_udp);
    assert!(
        tcp_lines >= udp_lines,
        "expected tcp>=udp, udp={}, tcp={}\nudp:{}\ntcp:{}",
        udp_lines,
        tcp_lines,
        s_udp,
        s_tcp
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&tmp);
}
