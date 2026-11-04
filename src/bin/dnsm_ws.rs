use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
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
use warp::{
    Filter, Rejection, Reply,
    http::{
        StatusCode, Uri,
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, HeaderValue, REFERRER_POLICY,
            X_CONTENT_TYPE_OPTIONS,
        },
    },
};

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

    /// Maximum HTTP and WebSocket upgrade requests per minute per IP. Set to 0 to disable.
    #[arg(long = "requests-per-minute", default_value_t = 120)]
    requests_per_minute: u32,

    /// Maximum concurrent WebSocket connections per IP. Set to 0 to disable.
    #[arg(long = "max-ws-connections-per-ip", default_value_t = 8)]
    max_ws_connections_per_ip: u32,

    /// Origin allowed to read the HTTP API and open browser WebSockets. Repeatable.
    #[arg(long = "allowed-origin", value_name = "ORIGIN")]
    allowed_origins: Vec<String>,

    /// Allow cross-origin requests from any origin
    #[arg(long = "allow-all-origins")]
    allow_all_origins: bool,

    /// Include sender IP addresses in mailbox API responses
    #[arg(long = "expose-peer-ip")]
    expose_peer_ip: bool,
}

#[derive(Clone)]
struct AppState {
    db_path: Arc<PathBuf>,
    poll_every: Duration,
    shutdown: Arc<Notify>,
    traffic: Arc<Mutex<TrafficLimiter>>,
    allowed_origins: Arc<HashSet<String>>,
    allow_all_origins: bool,
    expose_peer_ip: bool,
}

struct TrafficEntry {
    window_start: Instant,
    requests: u32,
    active_websockets: u32,
    last_seen: Instant,
}

struct TrafficLimiter {
    clients: HashMap<IpAddr, TrafficEntry>,
    requests_per_minute: u32,
    max_websockets_per_ip: u32,
    last_cleanup: Instant,
}

impl TrafficLimiter {
    fn new(requests_per_minute: u32, max_websockets_per_ip: u32) -> Self {
        Self {
            clients: HashMap::new(),
            requests_per_minute,
            max_websockets_per_ip,
            last_cleanup: Instant::now(),
        }
    }

    fn cleanup(&mut self, now: Instant) {
        const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
        const MAX_IDLE: Duration = Duration::from_secs(120);
        if now.saturating_duration_since(self.last_cleanup) < CLEANUP_INTERVAL {
            return;
        }
        self.clients.retain(|_, entry| {
            entry.active_websockets > 0 || now.saturating_duration_since(entry.last_seen) < MAX_IDLE
        });
        self.last_cleanup = now;
    }

    fn check_request(&mut self, ip: IpAddr, now: Instant) -> bool {
        const WINDOW: Duration = Duration::from_secs(60);
        self.cleanup(now);
        let entry = self.clients.entry(ip).or_insert(TrafficEntry {
            window_start: now,
            requests: 0,
            active_websockets: 0,
            last_seen: now,
        });
        entry.last_seen = now;
        if now.saturating_duration_since(entry.window_start) >= WINDOW {
            entry.window_start = now;
            entry.requests = 0;
        }
        if self.requests_per_minute > 0 && entry.requests >= self.requests_per_minute {
            return false;
        }
        entry.requests = entry.requests.saturating_add(1);
        true
    }

    fn acquire_websocket(&mut self, ip: IpAddr, now: Instant) -> bool {
        if !self.check_request(ip, now) {
            return false;
        }
        let entry = self.clients.get_mut(&ip).expect("request entry exists");
        if self.max_websockets_per_ip > 0 && entry.active_websockets >= self.max_websockets_per_ip {
            return false;
        }
        entry.active_websockets = entry.active_websockets.saturating_add(1);
        true
    }

    fn release_websocket(&mut self, ip: IpAddr) {
        if let Some(entry) = self.clients.get_mut(&ip) {
            entry.active_websockets = entry.active_websockets.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }
}

struct WebSocketPermit {
    traffic: Arc<Mutex<TrafficLimiter>>,
    ip: IpAddr,
}

impl Drop for WebSocketPermit {
    fn drop(&mut self) {
        self.traffic
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .release_websocket(self.ip);
    }
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

fn secure_response(mut response: warp::reply::Response) -> warp::reply::Response {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    response
}

fn error_response(error: &str, status: StatusCode) -> warp::reply::Response {
    secure_response(
        warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": error})),
            status,
        )
        .into_response(),
    )
}

fn rate_limited_response() -> warp::reply::Response {
    let mut response = error_response("rate_limited", StatusCode::TOO_MANY_REQUESTS);
    response
        .headers_mut()
        .insert("retry-after", HeaderValue::from_static("60"));
    response
}

fn canonical_origin(value: &str) -> Result<String, String> {
    let uri: Uri = value
        .parse()
        .map_err(|_| format!("invalid origin: {value}"))?;
    let scheme = uri
        .scheme_str()
        .filter(|scheme| matches!(*scheme, "http" | "https"))
        .ok_or_else(|| format!("origin must use http or https: {value}"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| format!("origin has no host: {value}"))?;
    if uri.path() != "/" || uri.query().is_some() {
        return Err(format!("origin must not contain a path or query: {value}"));
    }
    Ok(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.as_str().to_ascii_lowercase()
    ))
}

fn origin_allowed(state: &AppState, origin: Option<&str>) -> bool {
    origin.is_none_or(|origin| {
        state.allow_all_origins
            || canonical_origin(origin)
                .is_ok_and(|canonical| state.allowed_origins.contains(&canonical))
    })
}

fn request_allowed(state: &AppState, remote: Option<SocketAddr>) -> bool {
    let Some(ip) = remote.map(|addr| addr.ip()) else {
        return true;
    };
    state
        .traffic
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .check_request(ip, Instant::now())
}

fn acquire_websocket_permit(
    state: &AppState,
    remote: Option<SocketAddr>,
) -> Result<Option<WebSocketPermit>, ()> {
    let Some(ip) = remote.map(|addr| addr.ip()) else {
        return Ok(None);
    };
    let mut traffic = state
        .traffic
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !traffic.acquire_websocket(ip, Instant::now()) {
        return Err(());
    }
    drop(traffic);
    Ok(Some(WebSocketPermit {
        traffic: state.traffic.clone(),
        ip,
    }))
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

fn fetch_all_messages(
    db: &Connection,
    mailbox_hex: &str,
    expose_peer_ip: bool,
) -> rusqlite::Result<HistoryPage> {
    fetch_all_messages_with_limits(
        db,
        mailbox_hex,
        MAX_HISTORY_MESSAGES,
        MAX_HISTORY_BYTES,
        expose_peer_ip,
    )
}

fn fetch_all_messages_with_limits(
    db: &Connection,
    mailbox_hex: &str,
    max_messages: usize,
    max_bytes: usize,
    expose_peer_ip: bool,
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
            peer_ip: expose_peer_ip.then_some(peer_ip).flatten(),
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
    expose_peer_ip: bool,
) -> rusqlite::Result<Vec<ApiMessage>> {
    fetch_new_messages_after_with_limits(
        db,
        mailbox_hex,
        after_id,
        MAX_LIVE_BATCH_MESSAGES,
        MAX_LIVE_BATCH_BYTES,
        expose_peer_ip,
    )
}

fn fetch_new_messages_after_with_limits(
    db: &Connection,
    mailbox_hex: &str,
    after_id: i64,
    max_messages: usize,
    max_bytes: usize,
    expose_peer_ip: bool,
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
            peer_ip: expose_peer_ip.then_some(peer_ip).flatten(),
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

async fn run_blocking_db<T, F>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> rusqlite::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| format!("database worker failed: {error}"))?
        .map_err(|error| error.to_string())
}

async fn handle_list_messages(
    state: AppState,
    mailbox: String,
    remote: Option<SocketAddr>,
) -> Result<warp::reply::Response, Rejection> {
    if !request_allowed(&state, remote) {
        return Ok(rate_limited_response());
    }
    let response = if let Some(mb) = validate_mailbox_hex12(&mailbox) {
        let db_path = state.db_path.clone();
        let expose_peer_ip = state.expose_peer_ip;
        match run_blocking_db(move || {
            let db = open_readonly_db(&*db_path)?;
            fetch_all_messages(&db, &mb, expose_peer_ip)
        })
        .await
        {
            Ok(page) => secure_response(
                warp::reply::with_status(
                    warp::reply::with_header(
                        warp::reply::json(&page.messages),
                        "x-dnsm-history-truncated",
                        if page.truncated { "true" } else { "false" },
                    ),
                    StatusCode::OK,
                )
                .into_response(),
            ),
            Err(e) => {
                eprintln!("mailbox history query failed: {e}");
                error_response("db_query_failed", StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        error_response("invalid_mailbox", StatusCode::BAD_REQUEST)
    };
    Ok(response)
}

async fn handle_ws(
    state: AppState,
    mailbox: String,
    query: WsQuery,
    origin: Option<String>,
    remote: Option<SocketAddr>,
    ws: ws::Ws,
) -> Result<warp::reply::Response, Rejection> {
    if !origin_allowed(&state, origin.as_deref()) {
        return Ok(error_response("origin_not_allowed", StatusCode::FORBIDDEN));
    }
    let permit = match acquire_websocket_permit(&state, remote) {
        Ok(permit) => permit,
        Err(()) => return Ok(rate_limited_response()),
    };
    if let Some(mb) = validate_mailbox_hex12(&mailbox) {
        let resp = ws
            .on_upgrade(move |socket| ws_session(state, mb, query.after_id, permit, socket))
            .into_response();
        Ok(secure_response(resp))
    } else {
        Ok(error_response("invalid_mailbox", StatusCode::BAD_REQUEST))
    }
}

async fn ws_session(
    state: AppState,
    mailbox_hex: String,
    requested_after_id: Option<i64>,
    _permit: Option<WebSocketPermit>,
    ws: ws::WebSocket,
) {
    let (mut ws_tx, mut ws_rx) = ws.split();

    // A history cursor closes the HTTP-backlog/WebSocket-upgrade gap. Clients
    // without one retain the old live-only behavior and start at the current max id.
    let initial_db_path = state.db_path.clone();
    let initial_mailbox = mailbox_hex.clone();
    let mut last_id = match run_blocking_db(move || {
        let db = open_readonly_db(&*initial_db_path)?;
        initial_last_id(&db, &initial_mailbox, requested_after_id)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("websocket cursor query failed: {e}");
            let _ = ws_tx
                .send(Message::text(
                    serde_json::json!({"error":"db_query_failed"}).to_string(),
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
                let poll_db_path = state.db_path.clone();
                let poll_mailbox = mailbox_hex.clone();
                let expose_peer_ip = state.expose_peer_ip;
                match run_blocking_db(move || {
                    let db = open_readonly_db(&*poll_db_path)?;
                    fetch_new_messages_after(&db, &poll_mailbox, last_id, expose_peer_ip)
                }).await {
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
                        eprintln!("websocket poll query failed: {e}");
                        let _ = ws_tx
                            .send(Message::text(
                                serde_json::json!({"error":"db_query_failed"}).to_string(),
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

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() {
    let Args {
        bind,
        db_path,
        poll_ms,
        requests_per_minute,
        max_ws_connections_per_ip,
        allowed_origins,
        allow_all_origins,
        expose_peer_ip,
    } = Args::parse();
    let allowed_origins: HashSet<String> = allowed_origins
        .iter()
        .map(|origin| canonical_origin(origin))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|error| {
            eprintln!("{error}");
            std::process::exit(2);
        });
    let state = AppState {
        db_path: Arc::new(db_path),
        poll_every: Duration::from_millis(poll_ms),
        shutdown: Arc::new(Notify::new()),
        traffic: Arc::new(Mutex::new(TrafficLimiter::new(
            requests_per_minute,
            max_ws_connections_per_ip,
        ))),
        allowed_origins: Arc::new(allowed_origins),
        allow_all_origins,
        expose_peer_ip,
    };

    // Basic health endpoint
    let health = warp::path("healthz")
        .and(warp::path::end())
        .map(|| secure_response("ok".into_response()));

    // GET /api/mailbox/{mailbox}/messages
    let api_state = state.clone();
    let list_route = warp::path!("api" / "mailbox" / String / "messages")
        .and(warp::get())
        .and(warp::addr::remote())
        .and_then(move |mailbox: String, remote: Option<SocketAddr>| {
            let st = api_state.clone();
            async move { handle_list_messages(st, mailbox, remote).await }
        });

    // WS /ws/{mailbox}
    let ws_state = state.clone();
    let ws_route = warp::path!("ws" / String)
        .and(warp::query::<WsQuery>())
        .and(warp::header::optional::<String>("origin"))
        .and(warp::addr::remote())
        .and(warp::ws())
        .and_then(
            move |mailbox: String,
                  query: WsQuery,
                  origin: Option<String>,
                  remote: Option<SocketAddr>,
                  ws: ws::Ws| {
                let st = ws_state.clone();
                async move { handle_ws(st, mailbox, query, origin, remote, ws).await }
            },
        );

    // CORS
    let cors = if allow_all_origins {
        warp::cors()
            .allow_any_origin()
            .allow_headers(["content-type"])
            .expose_headers(["x-dnsm-history-truncated"])
            .allow_methods(["GET"])
    } else {
        warp::cors()
            .allow_origins(state.allowed_origins.iter().map(String::as_str))
            .allow_headers(["content-type"])
            .expose_headers(["x-dnsm-history-truncated"])
            .allow_methods(["GET"])
    };

    let routes = health.or(list_route).or(ws_route).with(cors);

    let addr: SocketAddr = bind.parse().expect("invalid --bind address");
    println!(
        "dnsm-ws listening on {} - db=\"{}\"",
        addr,
        state.db_path.display()
    );
    let shutdown = state.shutdown.clone();
    warp::serve(routes)
        .bind(addr)
        .await
        .graceful(async move {
            wait_for_shutdown_signal().await;
            shutdown.notify_waiters();
        })
        .run()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};

    fn test_state(allowed_origins: &[&str]) -> AppState {
        AppState {
            db_path: Arc::new(PathBuf::new()),
            poll_every: Duration::from_secs(1),
            shutdown: Arc::new(Notify::new()),
            traffic: Arc::new(Mutex::new(TrafficLimiter::new(0, 0))),
            allowed_origins: Arc::new(
                allowed_origins
                    .iter()
                    .map(|origin| origin.to_string())
                    .collect(),
            ),
            allow_all_origins: false,
            expose_peer_ip: false,
        }
    }

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

    #[tokio::test]
    async fn database_work_runs_on_blocking_pool() {
        let caller = std::thread::current().id();
        let worker = run_blocking_db(|| Ok(std::thread::current().id()))
            .await
            .unwrap();
        assert_ne!(caller, worker);
    }

    #[test]
    fn origins_are_canonicalized_and_paths_are_rejected() {
        assert_eq!(
            canonical_origin("https://dnsm.re/").unwrap(),
            "https://dnsm.re"
        );
        assert!(canonical_origin("https://dnsm.re/path").is_err());
        assert!(canonical_origin("file:///tmp/test").is_err());

        let state = test_state(&["https://dnsm.re"]);
        assert!(origin_allowed(&state, None));
        assert!(origin_allowed(&state, Some("https://DNSM.RE")));
        assert!(!origin_allowed(&state, Some("https://evil.example")));
    }

    #[test]
    fn request_rate_limit_resets_after_one_minute() {
        let ip = IpAddr::from([192, 0, 2, 1]);
        let start = Instant::now();
        let mut limiter = TrafficLimiter::new(2, 1);

        assert!(limiter.check_request(ip, start));
        assert!(limiter.check_request(ip, start));
        assert!(!limiter.check_request(ip, start));
        assert!(limiter.check_request(ip, start + Duration::from_secs(60)));
    }

    #[test]
    fn websocket_limit_is_released() {
        let ip = IpAddr::from([192, 0, 2, 1]);
        let start = Instant::now();
        let mut limiter = TrafficLimiter::new(0, 1);

        assert!(limiter.acquire_websocket(ip, start));
        assert!(!limiter.acquire_websocket(ip, start));
        limiter.release_websocket(ip);
        assert!(limiter.acquire_websocket(ip, start));
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

        let page = fetch_all_messages(&db, mb, false).expect("ok");
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
    fn peer_ip_is_hidden_unless_enabled() {
        let db = init_db();
        let mb = "000000000042";
        db.execute(
            "INSERT INTO messages (message_key, mailbox, data, received_at, peer_ip) VALUES (1, ?1, X'01', 1, '198.51.100.7')",
            [mb],
        )
        .unwrap();

        let hidden = fetch_all_messages(&db, mb, false).unwrap();
        assert_eq!(hidden.messages[0].peer_ip, None);
        let visible = fetch_all_messages(&db, mb, true).unwrap();
        assert_eq!(visible.messages[0].peer_ip.as_deref(), Some("198.51.100.7"));
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

        let page = fetch_all_messages_with_limits(&db, mb, 10, b"older".len(), false).unwrap();
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

        let first = fetch_new_messages_after_with_limits(&db, mb, 0, 10, 3, false).unwrap();
        assert_eq!(first.len(), 1);
        let second =
            fetch_new_messages_after_with_limits(&db, mb, first[0].id, 10, 3, false).unwrap();
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
        let live = fetch_new_messages_after(&db, mb, backlog_cursor, false).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, 2);
    }
}
