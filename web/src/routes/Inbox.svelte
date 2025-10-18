<script>
  import { onMount, onDestroy } from "svelte";
  import { link } from "svelte-spa-router";
  import { validateMailbox, randomMailbox } from "../lib/utils.js";

  let ws = null;
  let reconnectTimer = null;
  let reconnectDelay = 1000;
  const MAX_DELAY = 20000;
  let autoscroll = true;
  let autoReconnect = true;
  let messages = [];
  let status = { text: "Idle", level: "idle" };
  let host = "ws.dnsm.re";
  let mailbox = "";
  let zone = "k.dnsm.re";
  let wasmLoaded = false;
  let wasmModule = null;
  let genMessage = "";
  let genDomains = [];
  let genError = "";
  let genTimer = null;
  let generatorExpanded = false;
  let digExpanded = false;

  function toggleGenerator() {
    generatorExpanded = !generatorExpanded;
  }

  function toggleDig() {
    digExpanded = !digExpanded;
  }

  function setStatus(text, level = "idle") {
    status = { text, level };
  }

  function normalizeHttp(base, fallback) {
    const h = (base || "").trim();
    if (!h) return fallback;
    if (h.startsWith("http://") || h.startsWith("https://")) return h;
    if (h.includes("dnsm.re")) return "https://" + h;
    const scheme = location.protocol === "https:" ? "https://" : "http://";
    return scheme + h;
  }

  function toWsUrl(httpBase) {
    const u = new URL(httpBase);
    u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
    return u.toString().replace(/\/$/, "");
  }

  function toHex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      if (i && i % 16 === 0) out += "\n";
      else if (i && i % 2 === 0) out += " ";
      out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  function decodePayload(b64) {
    try {
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;

      let text = null;
      try {
        text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      } catch {}

      const printable = text && /[\x20-\x7E\s]{4,}/.test(text);
      if (text && printable) {
        const trimmed = text.trim();
        if (
          (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
          (trimmed.startsWith("[") && trimmed.endsWith("]"))
        ) {
          try {
            const parsed = JSON.parse(text);
            return {
              type: "json",
              content: JSON.stringify(parsed, null, 2),
              raw: b64,
            };
          } catch {}
        }
        return { type: "text", content: text, raw: b64 };
      }

      return { type: "binary", content: toHex(bytes), raw: b64 };
    } catch (e) {
      return { type: "invalid", content: `Invalid base64: ${e}`, raw: b64 };
    }
  }

  function createDateFormatter() {
    try {
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
        timeZoneName: "short",
      });
    } catch {
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      });
    }
  }

  const dateFormatter = createDateFormatter();

  function computeReceivedMeta(value) {
    const numeric = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(numeric)) {
      const raw =
        value === null || value === undefined ? "Unknown" : String(value);
      return { label: "Unknown time", tooltip: raw };
    }
    const date = new Date(numeric);
    if (Number.isNaN(date.getTime())) {
      const raw =
        value === null || value === undefined ? "Unknown" : String(value);
      return { label: "Unknown time", tooltip: raw };
    }
    return { label: dateFormatter.format(date), tooltip: date.toISOString() };
  }

  function formatReceivedAt(value) {
    return computeReceivedMeta(value).label;
  }

  function receivedAtTooltip(value) {
    return computeReceivedMeta(value).tooltip;
  }

  async function fetchBacklog(httpBase, mb) {
    try {
      const url = `${httpBase.replace(/\/$/, "")}/api/mailbox/${mb}/messages`;
      const res = await fetch(url, { method: "GET" });
      if (!res.ok) {
        setStatus(`HTTP ${res.status}: failed to fetch`, "warn");
        return [];
      }
      const arr = await res.json();
      return Array.isArray(arr) ? arr : [];
    } catch (e) {
      setStatus(`HTTP error: ${e}`, "warn");
      return [];
    }
  }

  function scheduleReconnect() {
    if (!autoReconnect) return;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connect, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 2, MAX_DELAY);
    setStatus(
      `Reconnecting in ${Math.round(reconnectDelay / 1000)}s...`,
      "warn"
    );
  }

  let isConnected = false;
  let isIntentionalDisconnect = false;
  let isConnecting = false;

  async function connect() {
    const mb = validateMailbox(mailbox);
    if (!mb) {
      setStatus("Mailbox must be 12 lowercase hex chars", "bad");
      return;
    }

    // Prevent concurrent connection attempts
    if (isConnecting) {
      return;
    }

    isConnecting = true;
    isIntentionalDisconnect = true; // We're intentionally switching connections
    mailbox = mb;
    setStatus("Connecting...", "warn");
    messages = [];

    if (
      ws &&
      (ws.readyState === WebSocket.OPEN ||
        ws.readyState === WebSocket.CONNECTING)
    ) {
      try {
        ws.close();
      } catch {}
    }
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    reconnectDelay = 1000;

    const fallback =
      location.hostname && location.protocol.startsWith("http")
        ? `${location.protocol}//${location.host}`
        : "http://localhost:8787";
    const httpBase = normalizeHttp(host, fallback);
    const wsBase = toWsUrl(httpBase);

    const backlog = await fetchBacklog(httpBase, mb);
    messages = backlog.map((m) => ({
      ...m,
      payload: decodePayload(m.data_b64),
    }));

    try {
      ws = new WebSocket(`${wsBase}/ws/${mb}`);
    } catch (e) {
      setStatus(`WS init failed: ${e}`, "bad");
      isConnecting = false;
      scheduleReconnect();
      return;
    }

    ws.addEventListener("open", () => {
      setStatus("Connected to WebSocket server", "good");
      isConnected = true;
      isConnecting = false;
      isIntentionalDisconnect = false; // Reset the flag on successful connection
      reconnectDelay = 1000; // Reset delay on successful connection
    });
    ws.addEventListener("close", () => {
      setStatus("Disconnected", "warn");
      isConnected = false;
      isConnecting = false;

      // Only auto-reconnect if this wasn't an intentional disconnect
      if (!isIntentionalDisconnect) {
        scheduleReconnect();
      } else {
        // Reset the flag for future disconnects
        isIntentionalDisconnect = false;
      }
    });
    ws.addEventListener("error", () => {
      setStatus("WebSocket error", "bad");
      isConnecting = false;
    });
    ws.addEventListener("message", (ev) => {
      try {
        const m = JSON.parse(ev.data);
        const msg = { ...m, payload: decodePayload(m.data_b64) };
        messages = [...messages, msg];
        if (autoscroll) {
          setTimeout(() => {
            const stream = document.getElementById("stream");
            if (stream) stream.scrollTop = stream.scrollHeight;
          }, 100);
        }
      } catch {}
    });
  }

  function clearMessages() {
    messages = [];
  }

  async function generateRandomMailbox() {
    mailbox = randomMailbox();
    // Reconnect with the new mailbox
    await connect();
  }

  async function copyText(content) {
    try {
      await navigator.clipboard.writeText(content);
    } catch (e) {
      console.error("Copy failed:", e);
    }
  }

  function applyQueryParams() {
    // Parse query params from hash (e.g., #/inbox?mailbox=abc&host=xyz)
    const hashParts = location.hash.split("?");
    const queryString = hashParts.length > 1 ? hashParts[1] : "";
    const p = new URLSearchParams(queryString);
    const hostParam = p.get("host");
    const mailboxParam = p.get("mailbox");
    const auto = p.get("auto");
    if (hostParam) host = hostParam;
    if (mailboxParam) mailbox = mailboxParam;
    if (auto === "0" || auto === "false") autoReconnect = false;
    return (hostParam && mailboxParam) || auto === "1" || auto === "true";
  }

  async function loadWasm() {
    try {
      if (!wasmModule) {
        wasmModule = await import("../lib/pkg-web/dnsm.js");
        await wasmModule.default();
      }
      wasmLoaded = true;
    } catch (e) {
      console.error("Failed to load Wasm module:", e);
    }
  }

  function ensureMailboxForGen() {
    const v = (mailbox || "").trim();
    if (v === "") return "";
    const ok = validateMailbox(v);
    if (!ok) return null;
    return ok;
  }

  async function generateDomains() {
    genError = "";
    genDomains = [];
    if (!wasmLoaded) await loadWasm();
    const mb = ensureMailboxForGen();
    if (mb === null) {
      genError = "Mailbox must be exactly 12 lowercase hex characters";
      return;
    }
    const z = (zone || "").trim();
    const msg = (genMessage || "").toString();
    if (!z || !msg) {
      return;
    }
    try {
      const arr = wasmModule.domains_for_string_with_mailbox(msg, z, mb);
      genDomains = Array.from(arr);
    } catch (e) {
      genError = String(e);
    }
  }

  // Auto-generate on changes with a small debounce
  $: (async () => {
    if (!wasmLoaded || !generatorExpanded) return;
    if (genTimer) {
      clearTimeout(genTimer);
      genTimer = null;
    }
    const msgOk = (genMessage || "").trim().length > 0;
    const zOk = (zone || "").trim().length > 0;
    const mb = ensureMailboxForGen();
    if (!msgOk || !zOk || mb === null) {
      if (!msgOk) {
        genDomains = [];
        genError = "";
      }
      return;
    }
    genTimer = setTimeout(() => {
      generateDomains();
    }, 100);
  })();

  async function copyAllGenerated() {
    try {
      await navigator.clipboard.writeText(genDomains.join("\n"));
    } catch (e) {
      genError = `Copy failed: ${e}`;
    }
  }

  onMount(() => {
    // Apply query params first to get mailbox from URL if present
    applyQueryParams();
    // If no mailbox was set from query params, generate random one
    if (!mailbox) {
      mailbox = randomMailbox();
    }
    // Preload WASM for generator
    loadWasm();
    // Auto-connect on load
    connect();
  });

  onDestroy(() => {
    // Disable auto-reconnect when component is being destroyed
    autoReconnect = false;
    isConnecting = false;
    isIntentionalDisconnect = true;

    if (ws) {
      try {
        ws.close();
      } catch {}
    }
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  });
</script>

<div class="wrap">
  <header>
    <div class="brand">
      <a href="#/" use:link class="logo"
        >dnsm <span class="muted">// inbox</span></a
      >
    </div>
    <div class="stat" title="Connection status">
      <span
        class="dot"
        class:good={status.level === "good"}
        class:warn={status.level === "warn"}
        class:bad={status.level === "bad"}
      ></span>
      <span>{status.text}</span>
    </div>
  </header>

  <section class="panel" aria-label="Connection">
    <div class="controls">
      <label for="host">Server</label>
      <input
        id="host"
        type="text"
        spellcheck="false"
        placeholder="localhost:8787 or ws.example.com"
        bind:value={host}
        on:keydown={(e) => e.key === "Enter" && connect()}
      />
      <label for="mailbox">Mailbox</label>
      <input
        id="mailbox"
        type="text"
        spellcheck="false"
        placeholder="12 hex chars, e.g. 50373ff32343"
        maxlength="12"
        bind:value={mailbox}
        on:keydown={(e) => e.key === "Enter" && connect()}
      />
    </div>

    <div
      class="collapsible-header"
      role="button"
      tabindex="0"
      on:click={toggleGenerator}
      on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && toggleGenerator()}
    >
      <span class="collapsible-title">Domain Generator</span>
      <svg
        class="chevron"
        class:expanded={generatorExpanded}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <polyline points="6 9 12 15 18 9"></polyline>
      </svg>
    </div>

    {#if generatorExpanded}
      <div class="generator-section">
        <div class="controls" style="margin-bottom: 14px;">
          <label for="gen-zone">Zone</label>
          <input
            id="gen-zone"
            type="text"
            spellcheck="false"
            placeholder="e.g. k.example.com"
            bind:value={zone}
          />
          <label for="gen-message">Message</label>
          <textarea
            id="gen-message"
            class="msg-input"
            placeholder="Type or paste your message..."
            bind:value={genMessage}
          ></textarea>
        </div>
        <div class="toolbar" style="margin-bottom: 10px;">
          <span class="muted small"
            >{wasmLoaded
              ? "Auto-generating as you type"
              : "Loading Wasm..."}</span
          >
          <div class="spacer"></div>
          <button
            class="btn small"
            on:click={copyAllGenerated}
            disabled={genDomains.length === 0}>Copy All</button
          >
        </div>
        {#if genError}
          <p class="hint" style="color: var(--danger); margin-top: 0; margin-bottom: 10px;">{genError}</p>
        {/if}
        <div class="gen-out">
          {#if genDomains.length === 0}
            <div class="empty">
              No domains yet. Enter zone and message. Mailbox: <code
                >{mailbox || "(none)"}</code
              >
            </div>
          {:else}
            <ol class="gen-list">
              {#each genDomains as d}
                <li><code>{d}</code></li>
              {/each}
            </ol>
          {/if}
        </div>
      </div>
    {/if}

    <div class="toolbar" style="margin-top: 10px;">
      <button
        on:click={generateRandomMailbox}
        class="btn btn-secondary small"
        title="Generate random mailbox">Random Mailbox</button
      >
      <div class="spacer"></div>
      <button
        on:click={() => (autoscroll = !autoscroll)}
        class="btn small"
        class:btn-secondary={!autoscroll}
        title="Toggle autoscroll"
      >
        Autoscroll: {autoscroll ? "On" : "Off"}
      </button>
      <button
        on:click={() => (autoReconnect = !autoReconnect)}
        class="btn small"
        class:btn-secondary={!autoReconnect}
        title="Toggle auto-reconnect"
      >
        Auto-Reconnect: {autoReconnect ? "On" : "Off"}
      </button>
      <button
        on:click={clearMessages}
        class="btn btn-secondary small"
        title="Clear messages"
        disabled={messages.length === 0}>Clear</button
      >
    </div>
  </section>

  <section class="stream" id="stream" aria-live="polite">
    {#if messages.length === 0}
      <div class="empty">
        No messages yet. Send some data via dnsm with mailbox.
      </div>
    {:else}
      {#each messages as msg (msg.id)}
        <div class="msg">
          <div class="row">
            <div class="meta">
              <div class="meta-line">
                {#if msg.message_hex}
                  <span class="meta-label">Message ID</span>
                  <span class="meta-value mono mono-break"
                    >{msg.message_hex}</span
                  >
                  <span class="meta-sep">•</span>
                {/if}
                <span class="meta-label">Received</span>
                <span
                  class="meta-value"
                  title={receivedAtTooltip(msg.received_at)}
                >
                  {formatReceivedAt(msg.received_at)}
                </span>
                <span class="meta-sep">•</span>
                <span class="meta-label">Type</span>
                <span class="meta-value">
                  <span class="badge">{msg.payload.type}</span>
                </span>
              </div>
            </div>
          </div>
          <div class="payload-section">
            {#if msg.payload.type === "json"}
              <pre class="payload mono">{msg.payload.content}</pre>
            {:else if msg.payload.type === "binary"}
              <pre class="payload mono">{msg.payload.content}</pre>
            {:else}
              <div class="payload">{msg.payload.content}</div>
            {/if}
            <div class="toolbar" style="margin-top: 8px;">
              <button
                on:click={() => copyText(msg.payload.content)}
                class="iconbtn small"
                title="Copy as text"
              >
                <svg
                  class="icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.7"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <rect x="9" y="9" width="13" height="13" rx="2"></rect>
                  <path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
                Copy
              </button>
            </div>
          </div>
        </div>
      {/each}
    {/if}
  </section>

  {#if mailbox && validateMailbox(mailbox)}
    <div class="dig-section">
      <div
        class="dig-header"
        role="button"
        tabindex="0"
        on:click={toggleDig}
        on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && toggleDig()}
      >
        <span class="dig-title">Retrieve via DNS</span>
        <svg
          class="chevron"
          class:expanded={digExpanded}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      {#if digExpanded}
        <div class="dig-content">
          <div class="dig-cmd">
            <code>dig @dnsm.re -p 53 {mailbox}.m.dnsm.re TXT +tcp +short</code>
            <button
              class="dig-copy-btn"
              on:click={() => copyText(`dig @dnsm.re -p 53 ${mailbox}.m.dnsm.re TXT +tcp +short`)}
              title="Copy command"
              aria-label="Copy dig command"
            >
              <svg
                class="icon"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="1.7"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <rect x="9" y="9" width="13" height="13" rx="2"></rect>
                <path d="M5 15V5a2 2 0 0 1 2-2h10" />
              </svg>
            </button>
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <p class="hint small">
    API: GET <code>/api/mailbox/&#123;mailbox&#125;/messages</code>, WS
    <code>/ws/&#123;mailbox&#125;</code>. Returns messages in newest-first
    fashion + live push on new rows.
  </p>
</div>

<style>
  .collapsible-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    margin-top: 10px;
    background: linear-gradient(135deg, #0a0e13 0%, #0d1218 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    cursor: pointer;
    user-select: none;
    transition: all 0.2s ease;
    outline: none;
  }

  .collapsible-header:hover {
    border-color: rgba(29, 242, 166, 0.3);
    background: linear-gradient(135deg, #0c1015 0%, #0f141a 100%);
    box-shadow: inset 0 0 0 1px rgba(29, 242, 166, 0.1);
  }

  .collapsible-header:focus-visible {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(29, 242, 166, 0.15);
  }

  .collapsible-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .collapsible-title::before {
    content: '⚙️';
    font-size: 14px;
  }

  .chevron {
    width: 18px;
    height: 18px;
    color: var(--accent);
    transition: all 0.2s ease;
  }

  .collapsible-header:hover .chevron {
    color: var(--accent-2);
  }

  .chevron.expanded {
    transform: rotate(180deg);
  }

  .generator-section {
    margin-top: 12px;
    padding: 16px;
    background: linear-gradient(180deg, #080c10 0%, #0a0e13 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3);
  }

  .stream {
    display: grid;
    gap: 12px;
    max-height: 60vh;
    overflow-y: auto;
    -webkit-overflow-scrolling: touch;
  }

  .msg {
    border: 1px solid rgba(35, 52, 64, 0.7);
    border-radius: var(--radius);
    background: #0b1319;
    padding: 12px 16px;
    box-shadow: inset 0 0 0 1px rgba(16, 27, 36, 0.4);
  }

  .msg .row {
    margin-bottom: 8px;
  }

  .msg .row:last-child {
    margin-bottom: 0;
  }

  .meta {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-family: var(--font-mono);
  }

  .meta-line {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: baseline;
  }

  .meta-label {
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.08em;
    color: #6e7c8d;
    white-space: nowrap;
  }

  .meta-value {
    font-size: 12px;
    color: #d6e2f1;
    white-space: nowrap;
  }

  .meta-value.mono {
    font-family: var(--font-mono);
  }

  .meta-value.mono-break {
    font-family: var(--font-mono);
    white-space: normal;
    word-break: break-all;
  }

  .meta-sep {
    color: #354250;
  }

  .meta-line .badge {
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 2px 6px;
  }

  .payload-section {
    margin-top: 8px;
  }

  .iconbtn {
    cursor: pointer;
    color: var(--muted);
    border: 1px solid var(--border);
    background: #0c1217;
    border-radius: var(--radius-sm);
    padding: 6px 8px;
    display: inline-flex;
    gap: 8px;
    align-items: center;
    font-family: var(--font-mono);
    font-size: 12px;
    transition: all 0.2s ease;
  }

  .iconbtn:hover {
    color: var(--accent);
    border-color: #204b3f;
    box-shadow: inset 0 0 0 1px rgba(29, 242, 166, 0.15);
  }

  .icon {
    width: 14px;
    height: 14px;
    display: inline-block;
    flex-shrink: 0;
  }

  .logo {
    text-decoration: none;
    color: var(--accent);
    transition: opacity 0.2s ease;
  }

  .logo:hover {
    opacity: 0.8;
  }

  .msg-input {
    min-height: 120px;
    resize: vertical;
    background: #0b1219;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 10px 12px;
    outline: none;
    transition:
      border-color 0.15s ease,
      box-shadow 0.15s ease;
    font-family: var(--font-mono);
  }

  .msg-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(29, 242, 166, 0.15);
  }

  .gen-out {
    margin-top: 10px;
    background: #0b1016;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 10px;
    max-height: 320px;
    overflow: auto;
  }

  .gen-list {
    margin: 0;
    padding-left: 20px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text);
  }

  .dig-section {
    margin-top: 16px;
    margin-bottom: 12px;
  }

  .dig-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    background: linear-gradient(135deg, #0a0e13 0%, #0d1218 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    cursor: pointer;
    user-select: none;
    transition: all 0.2s ease;
    outline: none;
  }

  .dig-header:hover {
    border-color: rgba(29, 242, 166, 0.3);
    background: linear-gradient(135deg, #0c1015 0%, #0f141a 100%);
    box-shadow: inset 0 0 0 1px rgba(29, 242, 166, 0.1);
  }

  .dig-header:focus-visible {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(29, 242, 166, 0.15);
  }

  .dig-header .chevron {
    width: 18px;
    height: 18px;
    color: var(--accent);
    transition: all 0.2s ease;
  }

  .dig-header:hover .chevron {
    color: var(--accent-2);
  }

  .dig-header .chevron.expanded {
    transform: rotate(180deg);
  }

  .dig-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
  }

  .dig-content {
    margin-top: 8px;
    padding: 10px 12px;
    background: linear-gradient(180deg, #080c10 0%, #0a0e13 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3);
  }

  .dig-cmd {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #0b1016;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 8px 10px;
  }

  .dig-cmd code {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--accent);
    word-break: break-all;
  }

  .dig-copy-btn {
    background: transparent;
    border: none;
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--muted);
    border-radius: 4px;
    transition: all 0.2s ease;
    flex-shrink: 0;
  }

  .dig-copy-btn:hover {
    color: var(--accent);
    background: rgba(29, 242, 166, 0.08);
  }

  .dig-copy-btn .icon {
    width: 14px;
    height: 14px;
    display: block;
  }
</style>
