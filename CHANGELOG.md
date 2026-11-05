# Changelog

## 0.3.0 - 2026-11-05

### Security and reliability

- Verify mailbox-aware multi-chunk message keys after reassembly.
- Bound assembly memory, mailbox history, WebSocket batches, and per-IP API traffic.
- Deny browser origins unless explicitly allowed and hide sender IPs by default.
- Move SQLite work off asynchronous runtime threads and add graceful shutdown.
- Retain query logs for 30 days by default and use a separate five-second mailbox negative TTL.

### Behavior changes

- Preserve stdin bytes exactly, including trailing whitespace and newlines.
- Use operating-system secure randomness for mailbox IDs and DNS transaction IDs.
- Require `--allowed-origin` for browser access unless `--allow-all-origins` is explicitly selected.
- Require `--expose-peer-ip` to include sender IPs in API responses.

### Development and packaging

- Expose reusable DNS parsing and carrier decoding through `dnsm::server_protocol`.
- Restore integration coverage and add push/PR CI.
- Update Rust and web dependencies.
- Add npm platform metadata, license packaging, and provenance publishing.

### Upgrade notes

- Public `dnsm-ws` deployments must pass each permitted browser origin, for example `--allowed-origin https://dnsm.re`.
- Consumers that displayed `peer_ip` must opt in with `--expose-peer-ip`.
- Text piped to the client now retains its final newline; trim it explicitly if the old behavior is required.
