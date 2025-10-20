use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_key INTEGER NOT NULL,
    mailbox TEXT CHECK(mailbox IS NULL OR length(mailbox) = 12),
    data BLOB NOT NULL CHECK(length(data) <= 16777216),
    received_at INTEGER NOT NULL,
    message_id BLOB CHECK(message_id IS NULL OR length(message_id) = 16)
);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages(mailbox);
CREATE INDEX IF NOT EXISTS idx_messages_key ON messages(message_key);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_messages_mailbox_msgid
    ON messages(mailbox, message_id)
    WHERE message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    peer_ip TEXT NOT NULL CHECK(length(peer_ip) <= 45),
    peer_port INTEGER NOT NULL,
    domain TEXT NOT NULL CHECK(length(domain) <= 255),
    qtype INTEGER NOT NULL,
    qclass INTEGER NOT NULL,
    opcode INTEGER NOT NULL,
    flags INTEGER NOT NULL,
    in_zone INTEGER NOT NULL,
    in_mailbox_zone INTEGER NOT NULL,
    base32_chars INTEGER,
    data_labels INTEGER,
    decode_error TEXT CHECK(decode_error IS NULL OR length(decode_error) <= 255),
    chunk_first INTEGER,
    chunk_remaining INTEGER,
    chunk_version INTEGER,
    data_len INTEGER,
    mailbox TEXT CHECK(mailbox IS NULL OR length(mailbox) = 12),
    message_key INTEGER
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);
CREATE INDEX IF NOT EXISTS idx_queries_peer ON queries(peer_ip);

CREATE VIEW IF NOT EXISTS v_queries AS
SELECT
  id,
  ts,
  datetime(ts/1000, 'unixepoch') AS ts_utc,
  peer_ip,
  peer_port,
  domain,
  qtype,
  qclass,
  opcode,
  flags,
  in_zone,
  in_mailbox_zone,
  base32_chars,
  data_labels,
  decode_error,
  chunk_first,
  chunk_remaining,
  chunk_version,
  data_len,
  mailbox,
  message_key
FROM queries;

CREATE VIEW IF NOT EXISTS v_top_domains AS
SELECT domain, COUNT(*) AS hits
FROM queries
GROUP BY domain
ORDER BY hits DESC;

CREATE VIEW IF NOT EXISTS v_top_peers AS
SELECT peer_ip, COUNT(*) AS hits
FROM queries
GROUP BY peer_ip
ORDER BY hits DESC;

CREATE VIEW IF NOT EXISTS v_qtype_counts AS
SELECT qtype, in_zone, in_mailbox_zone, COUNT(*) AS cnt
FROM queries
GROUP BY qtype, in_zone, in_mailbox_zone
ORDER BY cnt DESC;

CREATE VIEW IF NOT EXISTS v_decode_errors AS
SELECT decode_error, COUNT(*) AS cnt
FROM queries
WHERE decode_error IS NOT NULL
GROUP BY decode_error
ORDER BY cnt DESC;

CREATE VIEW IF NOT EXISTS v_dnsm_chunks AS
SELECT chunk_version, chunk_first, chunk_remaining, COUNT(*) AS cnt
FROM queries
WHERE in_zone = 1
GROUP BY chunk_version, chunk_first, chunk_remaining
ORDER BY cnt DESC;

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    key TEXT NOT NULL,
    value INTEGER NOT NULL
);

CREATE VIEW IF NOT EXISTS v_mailbox_activity AS
SELECT mailbox, COUNT(*) AS chunks, MIN(ts) AS first_ts, MAX(ts) AS last_ts
FROM queries
WHERE mailbox IS NOT NULL
GROUP BY mailbox
ORDER BY last_ts DESC;
"#;

pub(crate) fn open_db(db_path: &Path) -> rusqlite::Result<Connection> {
    Connection::open(db_path)
}

pub(crate) fn configure_pragmas(db: &Connection) {
    let _ = db.busy_timeout(Duration::from_millis(5000));
    let _ = db.execute_batch(
        "PRAGMA journal_mode=WAL;\n\
         PRAGMA synchronous=NORMAL;\n\
         PRAGMA foreign_keys=ON;\n\
         PRAGMA temp_store=MEMORY;\n\
         PRAGMA wal_autocheckpoint=1000;\n\
         PRAGMA mmap_size=268435456;",
    );
}

pub(crate) fn ensure_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA_SQL)
}
