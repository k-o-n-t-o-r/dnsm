use std::fs;
use std::net::UdpSocket;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[test]
fn dig_queries_are_logged() {
    if !have_dig() {
        eprintln!("skipping dig-based test: 'dig' not installed");
        return;
    }

    let server_path = std::env::var("CARGO_BIN_EXE_dnsm_server")
        .unwrap_or_else(|_| "./target/release/dnsm-server".to_string());
    if !Path::new(&server_path).exists() {
        eprintln!(
            "skipping dig-based test: server binary not found at {}",
            server_path
        );
        return;
    }

    let port = find_free_udp_port();
    let bind_addr = format!("127.0.0.1:{}", port);
    let fixed_ip = "203.0.113.77"; // TEST-NET-3

    let mut log_path = std::env::temp_dir();
    log_path.push(format!(
        "dnsm_it_{}_{}.log",
        std::process::id(),
        now_millis()
    ));

    // Start server
    let mut child = Command::new(server_path)
        .arg("x.example")
        .arg("--bind")
        .arg(&bind_addr)
        .arg("--respond_with")
        .arg(fixed_ip)
        .arg("--log")
        .arg(&log_path)
        .arg("--db")
        .arg(log_path.with_extension("sqlite"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("launch server");

    // Give it a moment to bind
    thread::sleep(Duration::from_millis(200));

    let domain = format!(
        "rand{}{}.example",
        std::process::id(),
        now_millis() % 10_000
    );

    // Issue a few queries, then poll the SQLite per-query log for a match
    for _ in 0..3 {
        let _ = Command::new("dig")
            .args([
                "+short",
                "@127.0.0.1",
                "-p",
                &port.to_string(),
                &domain,
                "A",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .status();
        thread::sleep(Duration::from_millis(50));
    }

    // Poll up to ~1s for the row to be written
    let mut ok = false;
    let db_path = log_path.with_extension("sqlite");
    let mut tries = 0;
    while tries < 20 {
        tries += 1;
        if db_path.exists()
            && let Ok(conn) = rusqlite::Connection::open(&db_path)
        {
            let mut stmt = conn
                .prepare("SELECT COUNT(*) FROM queries WHERE domain=?1 AND qtype=1 AND qclass=1")
                .unwrap();
            let cnt: i64 = stmt.query_row([&domain], |row| row.get(0)).unwrap_or(0);
            if cnt > 0 {
                ok = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Teardown
    let _ = child.kill();
    let _ = child.wait();

    assert!(ok, "server did not log expected dig query");

    // Cleanup
    let _ = fs::remove_file(&log_path);
    let _ = fs::remove_file(&db_path);
}
