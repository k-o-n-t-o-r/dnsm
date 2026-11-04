use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::Engine;
use clap::Parser;
use dnsm::{to_hex_lower, validate_mailbox_hex12};
use futures::{FutureExt, SinkExt, StreamExt};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_stream::wrappers::IntervalStream;
use warp::ws::{self, Message};
use warp::{Filter, Rejection, Reply, http::StatusCode};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "dnsm-ws",
    about = "WebSocket + HTTP gateway for dnsm mailboxes",
    disable_help_subcommand = true
)]
struct Args {
    /// Address to bind (default: 0.0.0.0:8787)
    #[arg(long = "bind", default_value = "0.0.0.0:8787")]
    bind: String,

    /// Path to the SQLite DB used by dnsm-server
    #[arg(long = "db", value_name = "DB_PATH")]
    db_path: PathBuf,

    /// Poll interval in milliseconds to check for new messages
    #[arg(long = "poll-ms", default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..))]
    poll_ms: u64,

    /// Allow cross-origin requests from any origin
    #[arg(long = "allow-all-origins")]
    allow_all_origins: bool,
}

#[derive(Clone)]
struct AppState {
    db_path: Arc<PathBuf>,
    poll_every: Duration,
    shutdown: Arc<Notify>,
}

const MAX_HISTORY_MESSAGES: usize = 1_000;
const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_LIVE_BATCH_MESSAGES: usize = 100;
const MAX_LIVE_BATCH_BYTES: usize = 16 * 1024 * 1024;

#[derive(Serialize)]
struct ApiMessage {
    id: i64,
    message_key: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    message_hex: String,
    mailbox: String,
    data_b64: String,
    received_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_ip: Option<String>,
    message_type: String,
}

struct HistoryPage {
    messages: Vec<ApiMessage>,
    truncated: bool,
}

#[derive(Debug, Default, Deserialize)]
struct WsQuery {
    after_id: Option<i64>,
}

fn open_readonly_db<P: AsRef<Path>>(p: P) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        p,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

// Use the shared library mailbox validator

fn has_message_type_column(db: &Connection) -> bool {
    db.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name='message_type'")
        .and_then(|mut s| s.exists([]))
        .unwrap_or(false)
}

fn fetch_all_messages(db: &Connection, mailbox_hex: &str) -> rusqlite::Result<HistoryPage> {
    fetch_all_messages_with_limits(db, mailbox_hex, MAX_HISTORY_MESSAGES, MAX_HISTORY_BYTES)
}

fn fetch_all_messages_with_limits(
    db: &Connection,
    mailbox_hex: &str,
    max_messages: usize,
    max_bytes: usize,
) -> rusqlite::Result<HistoryPage> {
    let has_mt = has_message_type_column(db);
    let sql = if has_mt {
        "SELECT id, message_key, mailbox, data, received_at, message_id, peer_ip, message_type
         FROM messages WHERE mailbox=?1 ORDER BY received_at DESC, id DESC LIMIT ?2"
    } else {
        "SELECT id, message_key, mailbox, data, received_at, message_id, peer_ip, NULL
         FROM messages WHERE mailbox=?1 ORDER BY received_at DESC, id DESC LIMIT ?2"
    };
    let scan_limit = max_messages.saturating_mul(4).saturating_add(1) as i64;
    let mut stmt = db.prepare(sql)?;
    let rows = stmt.query_map(params![mailbox_hex, scan_limit], |row| {
        let id: i64 = row.get(0)?;
        let message_key: i64 = row.get(1)?;
        let mailbox: String = row.get(2)?;
        let data: Vec<u8> = row.get(3)?;
        let received_at: i64 = row.get(4)?;
        let msg_id: Option<Vec<u8>> = row.get(5)?;
        let peer_ip: Option<String> = row.get(6)?;
        let message_type: Option<String> = row.get(7)?;
        Ok((
            id,
            message_key,
            mailbox,
            data,
            received_at,
            msg_id,
            peer_ip,
            message_type,
        ))
    })?;
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut messages = Vec::new();
    let mut total_bytes = 0usize;
    let mut scanned_rows = 0i64;
    let mut truncated = false;
    for r in rows {
        scanned_rows += 1;
        let (id, message_key, mailbox, data, received_at, msg_id, peer_ip, message_type) = r?;
        let message_id = msg_id.unwrap_or_else(|| dnsm::compute_message_id(&data).to_vec());
        if !seen.insert(message_id.clone()) {
            continue;
        }
        if messages.len() >= max_messages || total_bytes.saturating_add(data.len()) > max_bytes {
            truncated = true;
            break;
        }
        total_bytes = total_bytes.saturating_add(data.len());
        messages.push(ApiMessage {
            id,
            message_key,
            message_hex: to_hex_lower(&message_id),
            mailbox,
            data_b64: base64::engine::general_purpose::STANDARD.encode(&data),
            received_at,
            peer_ip,
            message_type: message_type.unwrap_or_else(|| "message".to_string()),
        });
    }
    if scanned_rows >= scan_limit {
        truncated = true;
    }
    Ok(HistoryPage {
        messages,
        truncated,
    })
}

fn fetch_new_messages_after(
    db: &Connection,
    mailbox_hex: &str,
    after_id: i64,
) -> rusqlite::Result<Vec<ApiMessage>> {
    fetch_new_messages_after_with_limits(
        db,
        mailbox_hex,
        after_id,
        MAX_LIVE_BATCH_MESSAGES,
        MAX_LIVE_BATCH_BYTES,
    )
}

fn fetch_new_messages_after_with_limits(
    db: &Connection,
    mailbox_hex: &str,
    after_id: i64,
    max_messages: usize,
    max_bytes: usize,
) -> rusqlite::Result<Vec<ApiMessage>> {
    let has_mt = has_message_type_column(db);
    let sql = if has_mt {
        "SELECT id, message_key, mailbox, data, received_at, message_id, peer_ip, message_type
         FROM messages WHERE mailbox=?1 AND id > ?2 ORDER BY id ASC LIMIT ?3"
    } else {
        "SELECT id, message_key, mailbox, data, received_at, message_id, peer_ip, NULL
         FROM messages WHERE mailbox=?1 AND id > ?2 ORDER BY id ASC LIMIT ?3"
    };
    let mut stmt = db.prepare(sql)?;
    let rows = stmt.query_map(params![mailbox_hex, after_id, max_messages as i64], |row| {
        let id: i64 = row.get(0)?;
        let message_key: i64 = row.get(1)?;
        let mailbox: String = row.get(2)?;
        let data: Vec<u8> = row.get(3)?;
        let received_at: i64 = row.get(4)?;
        let msg_id: Option<Vec<u8>> = row.get(5)?;
        let peer_ip: Option<String> = row.get(6)?;
        let message_type: Option<String> = row.get(7)?;
        Ok(ApiMessage {
            id,
            message_key,
            message_hex: msg_id.map(|b| to_hex_lower(&b)).unwrap_or_default(),
            mailbox,
            data_b64: base64::engine::general_purpose::STANDARD.encode(&data),
            received_at,
            peer_ip,
            message_type: message_type.unwrap_or_else(|| "message".to_string()),
        })
    })?;
    let mut out = Vec::new();
    let mut total_bytes = 0usize;
    for row in rows {
        let message = row?;
        let data_bytes = message.data_b64.len().saturating_mul(3) / 4;
        if !out.is_empty() && total_bytes.saturating_add(data_bytes) > max_bytes {
            break;
        }
        total_bytes = total_bytes.saturating_add(data_bytes);
        out.push(message);
    }
    Ok(out)
}

fn max_id(db: &Connection, mailbox_hex: &str) -> rusqlite::Result<i64> {
    let mut stmt = db.prepare("SELECT COALESCE(MAX(id), 0) FROM messages WHERE mailbox=?1")?;
    let max_id: i64 = stmt.query_row(params![mailbox_hex], |row| row.get(0))?;
    Ok(max_id)
}

fn initial_last_id(
    db: &Connection,
    mailbox_hex: &str,
    requested_after_id: Option<i64>,
) -> rusqlite::Result<i64> {
    match requested_after_id {
        Some(id) if id >= 0 => Ok(id),
        _ => max_id(db, mailbox_hex),
    }
}

async fn handle_list_messages(
    state: AppState,
    mailbox: String,
) -> Result<warp::reply::Response, Rejection> {
    let response = if let Some(mb) = validate_mailbox_hex12(&mailbox) {
        match open_readonly_db(&*state.db_path).and_then(|db| fetch_all_messages(&db, &mb)) {
            Ok(page) => warp::reply::with_status(
                warp::reply::with_header(
                    warp::reply::json(&page.messages),
                    "x-dnsm-history-truncated",
                    if page.truncated { "true" } else { "false" },
                ),
                StatusCode::OK,
            )
            .into_response(),
            Err(e) => warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "error": "db_query_failed",
                    "reason": e.to_string(),
                })),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .into_response(),
        }
    } else {
        warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "error": "invalid_mailbox",
                "hint": "expected 12 lowercase hex chars",
            })),
            StatusCode::BAD_REQUEST,
        )
        .into_response()
    };
    Ok(response)
}

async fn handle_ws(
    state: AppState,
    mailbox: String,
    query: WsQuery,
    ws: ws::Ws,
) -> Result<impl Reply, Rejection> {
    if let Some(mb) = validate_mailbox_hex12(&mailbox) {
        let resp = ws
            .on_upgrade(move |socket| ws_session(state, mb, query.after_id, socket))
            .into_response();
        Ok(resp)
    } else {
        let body = warp::reply::json(&serde_json::json!({
            "error": "invalid_mailbox",
            "hint": "expected 12 lowercase hex chars",
        }));
        Ok(warp::reply::with_status(body, StatusCode::BAD_REQUEST).into_response())
    }
}

async fn ws_session(
    state: AppState,
    mailbox_hex: String,
    requested_after_id: Option<i64>,
    ws: ws::WebSocket,
) {
    let (mut ws_tx, mut ws_rx) = ws.split();

    // Open a dedicated read-only connection for this session
    let db = match open_readonly_db(&*state.db_path) {
        Ok(c) => c,
        Err(e) => {
            let _ = ws_tx
                .send(Message::text(
                    serde_json::json!({"error":"db_open_failed", "reason": e.to_string()})
                        .to_string(),
                ))
                .await;
            return;
        }
    };

    // A history cursor closes the HTTP-backlog/WebSocket-upgrade gap. Clients
    // without one retain the old live-only behavior and start at the current max id.
    let mut last_id = match initial_last_id(&db, &mailbox_hex, requested_after_id) {
        Ok(v) => v,
        Err(e) => {
            let _ = ws_tx
                .send(Message::text(
                    serde_json::json!({"error":"db_query_failed", "reason": e.to_string()})
                        .to_string(),
                ))
                .await;
            return;
        }
    };

    // Spawn a polling task that periodically checks for new rows
    let mut ticker = IntervalStream::new(tokio::time::interval(state.poll_every));

    // Drive both incoming messages (for close) and periodic polling
    loop {
        tokio::select! {
            _ = ticker.next() => {
                match fetch_new_messages_after(&db, &mailbox_hex, last_id) {
                    Ok(new_msgs) => {
                        if !new_msgs.is_empty() {
                            last_id = new_msgs.last().unwrap().id;
                            // Send one message per row to keep client code simple
                            for m in new_msgs {
                                let txt = match serde_json::to_string(&m) {
                                    Ok(s) => s,
                                    Err(_) => continue,
                                };
                                if ws_tx.send(Message::text(txt)).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = ws_tx
                            .send(Message::text(
                                serde_json::json!({"error":"db_query_failed", "reason": e.to_string()}).to_string(),
                            ))
                            .await;
                    }
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(m)) => {
                        if m.is_close() { break; }
                        if m.is_ping() {
                            // Best-effort pong; ignore send error
                            let _ = ws_tx.send(Message::pong(m.as_bytes().to_vec())).await;
                        }
                        // Ignore any other incoming text/binary
                    }
                    Some(Err(_)) => break,
                    None => break,
                }
            }
            _ = state.shutdown.notified().fuse() => {
                let _ = ws_tx.send(Message::close()).await;
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let Args {
        bind,
        db_path,
        poll_ms,
        allow_all_origins,
    } = Args::parse();
    let state = AppState {
        db_path: Arc::new(db_path),
        poll_every: Duration::from_millis(poll_ms),
        shutdown: Arc::new(Notify::new()),
    };

    // Basic health endpoint
    let health = warp::path("healthz").and(warp::path::end()).map(|| "ok");

    // GET /api/mailbox/{mailbox}/messages
    let api_state = state.clone();
    let list_route = warp::path!("api" / "mailbox" / String / "messages")
        .and(warp::get())
        .and_then(move |mailbox: String| {
            let st = api_state.clone();
            async move { handle_list_messages(st, mailbox).await }
        });

    // WS /ws/{mailbox}
    let ws_state = state.clone();
    let ws_route = warp::path!("ws" / String)
        .and(warp::query::<WsQuery>())
        .and(warp::ws())
        .and_then(move |mailbox: String, query: WsQuery, ws: ws::Ws| {
            let st = ws_state.clone();
            async move { handle_ws(st, mailbox, query, ws).await }
        });

    // CORS
    let cors = if allow_all_origins {
        warp::cors()
            .allow_any_origin()
            .allow_headers(["content-type"])
            .expose_headers(["x-dnsm-history-truncated"])
            .allow_methods(["GET"])
    } else {
        // Default: allow same-origin (handled by browsers) - no explicit CORS
        warp::cors()
    };

    let routes = health.or(list_route).or(ws_route).with(cors);

    let addr: SocketAddr = bind.parse().expect("invalid --bind address");
    println!(
        "dnsm-ws listening on {} - db=\"{}\"",
        addr,
        state.db_path.display()
    );
    warp::serve(routes).run(addr).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};

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
                peer_ip TEXT,
                message_type TEXT DEFAULT 'message'
            );",
        )
        .unwrap();
        db
    }

    #[test]
    fn fetch_all_returns_distinct_newest_first_with_message_hex() {
        let db = init_db();
        let mb = "000000000042";
        // Insert duplicates and different messages with varying received_at
        let mid_world: Vec<u8> = {
            let mbv = u64::from_str_radix(mb, 16).unwrap();
            let mut hasher = blake3::Hasher::new();
            hasher.update(&mbv.to_be_bytes());
            hasher.update(&(100u64 / 180).to_be_bytes());
            hasher.update(b"world");
            hasher.finalize().as_bytes()[..16].to_vec()
        };
        let mid_hello: Vec<u8> = {
            let mbv = u64::from_str_radix(mb, 16).unwrap();
            let mut hasher = blake3::Hasher::new();
            hasher.update(&mbv.to_be_bytes());
            hasher.update(&(200u64 / 180).to_be_bytes());
            hasher.update(b"hello");
            hasher.finalize().as_bytes()[..16].to_vec()
        };
        db.execute(
            "INSERT INTO messages (message_key, mailbox, data, received_at, message_id) VALUES (1, ?1, ?2, 100, ?3)",
            params![mb, &b"world"[..], &mid_world[..]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO messages (message_key, mailbox, data, received_at, message_id) VALUES (2, ?1, ?2, 200, ?3)",
            params![mb, &b"hello"[..], &mid_hello[..]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO messages (message_key, mailbox, data, received_at, message_id) VALUES (3, ?1, ?2, 150, ?3)",
            params![mb, &b"hello"[..], &mid_hello[..]],
        )
        .unwrap();

        let page = fetch_all_messages(&db, mb).expect("ok");
        assert!(!page.truncated);
        assert!(page.messages.len() >= 2);
        // Newest-first distinct: hello (key=2) first, then world (key=1)
        assert_eq!(page.messages[0].message_key, 2);
        assert_eq!(page.messages[0].message_hex.len(), 32);
        let d0 = base64::engine::general_purpose::STANDARD
            .decode(&page.messages[0].data_b64)
            .unwrap();
        assert_eq!(&d0, b"hello");
        let d1 = base64::engine::general_purpose::STANDARD
            .decode(&page.messages[1].data_b64)
            .unwrap();
        assert_eq!(&d1, b"world");
    }

    #[test]
    fn fetch_all_stops_at_byte_budget() {
        let db = init_db();
        let mb = "000000000042";
        for (key, data) in [(1, b"new".as_slice()), (2, b"older".as_slice())] {
            db.execute(
                "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (?1, ?2, ?3, ?1)",
                params![key, mb, data],
            )
            .unwrap();
        }

        let page = fetch_all_messages_with_limits(&db, mb, 10, b"older".len()).unwrap();
        assert_eq!(page.messages.len(), 1);
        assert!(page.truncated);
    }

    #[test]
    fn live_batches_resume_after_byte_budget() {
        let db = init_db();
        let mb = "000000000042";
        for key in 1..=2 {
            db.execute(
                "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (?1, ?2, X'010203', ?1)",
                params![key, mb],
            )
            .unwrap();
        }

        let first = fetch_new_messages_after_with_limits(&db, mb, 0, 10, 3).unwrap();
        assert_eq!(first.len(), 1);
        let second = fetch_new_messages_after_with_limits(&db, mb, first[0].id, 10, 3).unwrap();
        assert_eq!(second.len(), 1);
        assert!(second[0].id > first[0].id);
    }

    #[test]
    fn explicit_websocket_cursor_closes_backlog_gap() {
        let db = init_db();
        let mb = "000000000042";
        db.execute(
            "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (1, ?1, X'01', 1)",
            [mb],
        )
        .unwrap();
        let backlog_cursor = max_id(&db, mb).unwrap();
        db.execute(
            "INSERT INTO messages (message_key, mailbox, data, received_at) VALUES (2, ?1, X'02', 2)",
            [mb],
        )
        .unwrap();

        assert_eq!(initial_last_id(&db, mb, Some(backlog_cursor)).unwrap(), 1);
        let live = fetch_new_messages_after(&db, mb, backlog_cursor).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, 2);
    }
}
