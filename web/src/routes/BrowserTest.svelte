<script>
  import { onMount, onDestroy } from "svelte";
  import { link } from "svelte-spa-router";
  import { validateMailbox, randomMailbox } from "../lib/utils.js";

  let ws = null;
  let status = { text: "Idle", level: "idle" };
  let host = "ws.dnsm.re";
  let zone = "k.dnsm.re";
  let mailbox = "";
  let isConnected = false;
  let isRunning = false;
  let wasmLoaded = false;
  let wasmModule = null;
  let testCompleted = false;

  const SESSION = Math.random().toString(36).slice(2, 10);
  const USER_AGENT =
    typeof navigator !== "undefined" && navigator.userAgent
      ? navigator.userAgent
      : "unknown";

  const METHODS = [
    "dns-prefetch",
    "preconnect",
    "prefetch",
    "preload",
    "image",
    "stylesheet",
    "css-import",
    "script",
    "dynamic-import",
    "fetch",
    "beacon",
    "websocket",
    "eventsource",
    "iframe",
    "object",
    "svg-use",
    "font-face",
    "css-bg",
    "paint-worklet",
    "manifest",
    "icon",
    "apple-touch-icon",
    "webtransport",
    "webrtc-stun",
    "anchors",
    "speculation-prefetch",
  ];

  const FIREFOX_VISIBLE = new Set([
    "preload",
    "image",
    "stylesheet",
    "script",
    "dynamic-import",
    "fetch",
    "beacon",
    "websocket",
    "eventsource",
    "iframe",
    "svg-use",
    "font-face",
    "icon",
    "apple-touch-icon",
  ]);

  const CHROMIUM_VISIBLE = new Set([
    "prefetch",
    "preload",
    "image",
    "stylesheet",
    "script",
    "dynamic-import",
    "fetch",
    "beacon",
    "websocket",
    "eventsource",
    "iframe",
    "svg-use",
    "font-face",
    "paint-worklet",
    "manifest",
    "icon",
    "webtransport",
  ]);

  let methodState = METHODS.reduce((acc, name) => {
    acc[name] = { sent: false, recv: false, rid: null };
    return acc;
  }, {});

  function setStatus(text, level = "idle") {
    status = { text, level };
  }

  function toWsUrl(httpBase) {
    const u = new URL(httpBase);
    u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
    return u.toString().replace(/\/$/, "");
  }

  function normalizeHttp(base, fallback) {
    const h = (base || "").trim();
    if (!h) return fallback;
    if (h.startsWith("http://") || h.startsWith("https://")) return h;
    if (h.includes("dnsm.re")) return "https://" + h;
    const scheme = location.protocol === "https:" ? "https://" : "http://";
    return scheme + h;
  }

  function disconnectWs() {
    if (ws) {
      try {
        ws.close();
      } catch {}
    }
    isConnected = false;
    setStatus("Disconnected", "idle");
  }

  async function connectWs() {
    const mb = validateMailbox(mailbox);
    if (!mb) {
      setStatus("Mailbox must be 12 lowercase hex chars", "bad");
      return;
    }
    mailbox = mb;
    setStatus("Connecting...", "warn");
    isConnected = false;

    if (
      ws &&
      (ws.readyState === WebSocket.OPEN ||
        ws.readyState === WebSocket.CONNECTING)
    ) {
      try {
        ws.close();
      } catch {}
    }

    const httpBase = normalizeHttp(host, "https://ws.dnsm.re");
    const wsBase = toWsUrl(httpBase);

    return new Promise((resolve) => {
      try {
        ws = new WebSocket(`${wsBase}/ws/${mb}`);
        ws.addEventListener("open", () => {
          setStatus("Connected to WebSocket server", "good");
          isConnected = true;
          resolve(true);
        });
        ws.addEventListener("close", () => {
          setStatus("Disconnected", "warn");
          isConnected = false;
        });
        ws.addEventListener("error", () => {
          setStatus("WebSocket error", "bad");
          isConnected = false;
        });
        ws.addEventListener("message", (ev) => {
          try {
            const m = JSON.parse(ev.data);
            // Decode and parse message to update method state
            const text = atob(m.data_b64);
            const kv = Object.fromEntries(
              text
                .split(";")
                .map((segment) => segment.trim())
                .filter(Boolean)
                .map((segment) => {
                  const [key, value = ""] = segment.split("=");
                  return [key, value];
                })
            );
            if (kv.sid === SESSION && kv.m && methodState[kv.m]) {
              methodState[kv.m].recv = true;
              methodState[kv.m] = { ...methodState[kv.m] }; // Trigger reactivity
            }
          } catch {}
        });
      } catch (e) {
        setStatus(`WS init failed: ${e}`, "bad");
        resolve(false);
      }
    });
  }

  // DNS resolution technique implementations
  const MAX_INFLIGHT = 2;
  const METHOD_DELAY_MS = 150;
  const LOADER_TIMEOUT_MS = 6000;

  function viaImage(domain) {
    return new Promise((res) => {
      const img = new Image();
      img.decoding = "async";
      img.referrerPolicy = "no-referrer";
      img.onload =
        img.onerror =
        img.onabort =
          () => {
            img.remove();
            res();
          };
      img.src = `https://${domain}/p.png?${Date.now()}_${Math.random().toString(36).slice(2)}`;
      document.body.appendChild(img);
    });
  }

  function viaDnsPrefetch(domain) {
    const l = document.createElement("link");
    l.rel = "dns-prefetch";
    l.href = "//" + domain;
    document.head.appendChild(l);
    return Promise.resolve();
  }

  function viaPreconnect(domain) {
    const l = document.createElement("link");
    l.rel = "preconnect";
    l.href = "https://" + domain;
    document.head.appendChild(l);
    return Promise.resolve();
  }

  function viaLinkPrefetch(domain) {
    const l = document.createElement("link");
    l.rel = "prefetch";
    l.as = "fetch";
    l.href = "https://" + domain + "/x?t=" + Date.now();
    document.head.appendChild(l);
    return Promise.resolve();
  }

  function viaPreload(domain) {
    const l = document.createElement("link");
    l.rel = "preload";
    l.as = "image";
    l.href = "https://" + domain + "/i.png?t=" + Date.now();
    document.head.appendChild(l);
    return Promise.resolve();
  }

  function viaStylesheet(domain) {
    return new Promise((res) => {
      const l = document.createElement("link");
      l.rel = "stylesheet";
      l.href = "https://" + domain + "/x.css?t=" + Date.now();
      l.onload = l.onerror = () => {
        l.remove();
        res();
      };
      document.head.appendChild(l);
    });
  }

  function viaCssImport(domain) {
    const st = document.createElement("style");
    st.textContent = `@import url("https://${domain}/x.css?t=${Date.now()}");`;
    document.head.appendChild(st);
    return Promise.resolve();
  }

  function viaScript(domain) {
    return new Promise((res) => {
      const s = document.createElement("script");
      s.src = "https://" + domain + "/x.js?t=" + Date.now();
      s.async = true;
      s.onload = s.onerror = () => {
        s.remove();
        res();
      };
      document.head.appendChild(s);
    });
  }

  async function viaDynamicImport(domain) {
    try {
      await import("https://" + domain + "/m.js?t=" + Date.now());
    } catch {}
  }

  async function viaFetch(domain) {
    try {
      await fetch("https://" + domain + "/x?t=" + Date.now(), {
        mode: "no-cors",
        cache: "no-store",
      });
    } catch {}
  }

  function viaBeacon(domain) {
    try {
      navigator.sendBeacon(
        "https://" + domain + "/b?t=" + Date.now(),
        new Blob(["x"])
      );
    } catch {}
    return Promise.resolve();
  }

  function viaWebSocket(domain) {
    try {
      const s = new WebSocket("wss://" + domain + "/ws?t=" + Date.now());
      setTimeout(() => {
        try {
          s.close();
        } catch {}
      }, 1500);
    } catch {}
    return Promise.resolve();
  }

  function viaEventSource(domain) {
    try {
      const es = new EventSource("https://" + domain + "/sse?t=" + Date.now());
      setTimeout(() => {
        try {
          es.close();
        } catch {}
      }, 1500);
    } catch {}
    return Promise.resolve();
  }

  function viaIframe(domain) {
    const fr = document.createElement("iframe");
    fr.style.display = "none";
    fr.src = "https://" + domain + "/frame?t=" + Date.now();
    document.body.appendChild(fr);
    setTimeout(() => fr.remove(), 2000);
    return Promise.resolve();
  }

  function viaObject(domain) {
    const o = document.createElement("object");
    o.style.display = "none";
    o.data = "https://" + domain + "/obj?t=" + Date.now();
    document.body.appendChild(o);
    setTimeout(() => o.remove(), 2000);
    return Promise.resolve();
  }

  function viaSvgUse(domain) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttributeNS(
      "http://www.w3.org/1999/xlink",
      "href",
      "https://" + domain + "/s.svg#x?t=" + Date.now()
    );
    svg.appendChild(use);
    svg.style.display = "none";
    document.body.appendChild(svg);
    setTimeout(() => svg.remove(), 2000);
    return Promise.resolve();
  }

  async function viaFontFace(domain) {
    try {
      const ff = new FontFace(
        "T",
        `url(https://${domain}/f.woff2?t=${Date.now()})`
      );
      document.fonts.add(ff);
      await ff.load();
    } catch {}
  }

  function viaCssBg(domain) {
    const d = document.createElement("div");
    d.style.width = "1px";
    d.style.height = "1px";
    d.style.backgroundImage = `url(https://${domain}/bg.png?t=${Date.now()})`;
    d.style.display = "none";
    document.body.appendChild(d);
    setTimeout(() => d.remove(), 1500);
    return Promise.resolve();
  }

  async function viaPaintWorklet(domain) {
    try {
      if ("paintWorklet" in CSS)
        await CSS.paintWorklet.addModule(
          "https://" + domain + "/worklet.js?t=" + Date.now()
        );
    } catch {}
  }

  function viaManifest(domain) {
    const l = document.createElement("link");
    l.rel = "manifest";
    l.href = "https://" + domain + "/manifest.json?t=" + Date.now();
    document.head.appendChild(l);
    return Promise.resolve();
  }

  function viaIcon(domain) {
    const l = document.createElement("link");
    l.rel = "icon";
    l.href = "https://" + domain + "/favicon.ico?t=" + Date.now();
    document.head.appendChild(l);
    return Promise.resolve();
  }

  function viaAppleIcon(domain) {
    const l = document.createElement("link");
    l.rel = "apple-touch-icon";
    l.href = "https://" + domain + "/apple-touch-icon.png?t=" + Date.now();
    document.head.appendChild(l);
    return Promise.resolve();
  }

  async function viaWebTransport(domain) {
    try {
      if ("WebTransport" in window) {
        const wt = new WebTransport(
          "https://" + domain + "/wt?t=" + Date.now()
        );
        await Promise.race([wt.ready, new Promise((r) => setTimeout(r, 800))]);
        try {
          wt.close();
        } catch {}
      }
    } catch {}
  }

  async function viaWebRTC(domain) {
    try {
      const pc = new RTCPeerConnection({
        iceServers: [{ urls: ["stun:" + domain + ":3478"] }],
      });
      pc.createDataChannel("x");
      await pc.setLocalDescription(await pc.createOffer());
      setTimeout(() => pc.close(), 1500);
    } catch {}
  }

  function viaAnchors(domain) {
    const a = document.createElement("a");
    a.href = "https://" + domain + "/a?t=" + Date.now();
    a.rel = "noreferrer";
    a.ping = "https://" + domain + "/p";
    a.style.position = "absolute";
    a.style.left = "-9999px";
    document.body.appendChild(a);
    return Promise.resolve();
  }

  function viaSpeculationPrefetch(domain) {
    try {
      const s = document.createElement("script");
      s.type = "speculationrules";
      s.textContent = JSON.stringify({
        prefetch: [
          {
            source: "list",
            urls: ["https://" + domain + "/sp?t=" + Date.now()],
            eagerness: "moderate",
          },
        ],
      });
      document.body.appendChild(s);
      setTimeout(() => s.remove(), 1200);
    } catch {}
    return Promise.resolve();
  }

  const methodLoaders = {
    "dns-prefetch": viaDnsPrefetch,
    preconnect: viaPreconnect,
    prefetch: viaLinkPrefetch,
    preload: viaPreload,
    image: viaImage,
    stylesheet: viaStylesheet,
    "css-import": viaCssImport,
    script: viaScript,
    "dynamic-import": viaDynamicImport,
    fetch: viaFetch,
    beacon: viaBeacon,
    websocket: viaWebSocket,
    eventsource: viaEventSource,
    iframe: viaIframe,
    object: viaObject,
    "svg-use": viaSvgUse,
    "font-face": viaFontFace,
    "css-bg": viaCssBg,
    "paint-worklet": viaPaintWorklet,
    manifest: viaManifest,
    icon: viaIcon,
    "apple-touch-icon": viaAppleIcon,
    webtransport: viaWebTransport,
    "webrtc-stun": viaWebRTC,
    anchors: viaAnchors,
    "speculation-prefetch": viaSpeculationPrefetch,
  };

  function runDomains(domains, loader) {
    let inflight = 0,
      idx = 0;
    return new Promise((resolve) => {
      function step() {
        if (idx >= domains.length && inflight === 0) {
          resolve();
          return;
        }
        while (inflight < MAX_INFLIGHT && idx < domains.length) {
          const d = domains[idx++];
          inflight++;
          Promise.race([
            loader(d),
            new Promise((r) => setTimeout(r, LOADER_TIMEOUT_MS)),
          ]).finally(() => {
            inflight--;
            step();
          });
        }
      }
      step();
    });
  }

  async function startTest() {
    if (!wasmLoaded || !wasmModule) {
      setStatus("Wasm module not loaded", "bad");
      return;
    }

    // Clear previous results
    clearResults();

    setStatus("Running tests...", "warn");
    isRunning = true;

    try {
      for (const method of METHODS) {
        const rid = Math.random().toString(36).slice(2, 10);
        const parts = [
          `sid=${SESSION}`,
          `m=${method}`,
          `t=${Date.now().toString(36)}`,
          `r=${rid}`,
          `ua=${USER_AGENT}`,
        ];
        const testMessage = parts.map((p) => `${p};\n`).join("");
        const domains = Array.from(
          wasmModule.domains_for_string_with_mailbox(testMessage, zone, mailbox)
        );

        methodState[method].sent = true;
        methodState[method].rid = rid;
        methodState = { ...methodState };

        const loader = methodLoaders[method];
        if (loader) {
          await runDomains(domains, loader);
        }

        await new Promise((r) => setTimeout(r, METHOD_DELAY_MS));
      }

      setStatus("Sent all - waiting for receipts", "warn");
      testCompleted = true;
    } catch (e) {
      setStatus(`Test error: ${e}`, "bad");
      console.error("Test error:", e);
    } finally {
      isRunning = false;
    }
  }

  function clearResults() {
    methodState = METHODS.reduce((acc, name) => {
      acc[name] = { sent: false, recv: false, rid: null };
      return acc;
    }, {});
    testCompleted = false;
    setStatus("Idle", "idle");
  }

  async function copyText(content) {
    try {
      await navigator.clipboard.writeText(content);
    } catch (e) {
      console.error("Copy failed:", e);
    }
  }

  function goToInbox() {
    window.location.hash = `/inbox?mailbox=${mailbox}&host=${host}&auto=true`;
  }

  async function loadWasm() {
    try {
      wasmModule = await import("../lib/pkg-web/dnsm.js");
      await wasmModule.default();
      wasmLoaded = true;
    } catch (e) {
      console.error("Failed to load Wasm module:", e);
      setStatus("Failed to load Wasm module", "bad");
    }
  }

  onMount(() => {
    mailbox = randomMailbox();
    loadWasm();
    // Auto-connect on load
    connectWs();
  });

  onDestroy(() => {
    if (ws) {
      try {
        ws.close();
      } catch {}
    }
  });
</script>

<div class="wrap">
  <header>
    <div class="brand">
      <a href="#/" use:link class="logo"
        >dnsm <span class="muted">// browser test</span></a
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

  <section class="panel" aria-label="Connection + Controls">
    <div class="controls">
      <label for="host">WebSocket server</label>
      <input
        id="host"
        type="text"
        spellcheck="false"
        bind:value={host}
        placeholder="ws.dnsm.re"
        readonly
      />
      <label for="zone">Zone</label>
      <input
        id="zone"
        type="text"
        spellcheck="false"
        bind:value={zone}
        placeholder="e.g. k.example.com"
        readonly
      />
      <label for="mailbox">Mailbox</label>
      <div class="input-with-icon">
        <input
          id="mailbox"
          type="text"
          spellcheck="false"
          bind:value={mailbox}
          placeholder="12 hex chars"
          maxlength="12"
          readonly
        />
        <button
          on:click={() => copyText(mailbox)}
          class="input-icon-btn"
          title="Copy mailbox"
          aria-label="Copy mailbox"
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
    <div class="toolbar" style="margin-top: 10px; justify-content: center;">
      <button
        on:click={startTest}
        class="btn btn-test"
        disabled={!isConnected || isRunning}>Start Test</button
      >
      {#if testCompleted}
        <button on:click={goToInbox} class="btn btn-primary"
          >View Messages in Inbox →</button
        >
      {/if}
    </div>
  </section>

  <section class="panel methods-panel" aria-label="Methods">
    <div class="grid">
      {#each METHODS as method}
        <div class="tile">
          <div class="tile-content">
            <div class="name">
              {method}
            </div>
            <div class="badges">
              <span
                class="badge"
                data-kind="sent"
                class:on={methodState[method].sent}
              >
                <span class="dot"></span>sent
              </span>
              <span
                class="badge"
                data-kind="recv"
                class:on={methodState[method].recv}
              >
                <span class="dot"></span>received
              </span>
              {#if FIREFOX_VISIBLE.has(method)}
                <img src="/firefox.svg" alt="Firefox" class="browser-icon" title="Visible in Firefox Network tab" />
              {/if}
              {#if CHROMIUM_VISIBLE.has(method)}
                <img src="/chromium.svg" alt="Chromium" class="browser-icon" title="Visible in Chromium Network tab" />
              {/if}
            </div>
          </div>
        </div>
      {/each}
    </div>
    <p class="hint">
      This runs a battery of techniques to nudge the browser into resolving dnsm
      chunk domains (generated via Wasm) - images, preconnect/prefetch,
      stylesheet/script, fetch/beacon, WebSocket/EventSource, iframe/object,
      font, CSS background, and more.
    </p>
  </section>
</div>

<style>
  .logo {
    text-decoration: none;
    color: var(--accent);
    transition: opacity 0.2s ease;
  }

  .logo:hover {
    opacity: 0.8;
  }

  .btn-test {
    min-width: 180px;
  }

  .input-with-icon {
    position: relative;
    display: flex;
    align-items: center;
  }

  .input-with-icon input {
    flex: 1;
    padding-right: 40px;
  }

  .input-icon-btn {
    position: absolute;
    right: 6px;
    background: transparent;
    border: none;
    cursor: pointer;
    padding: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--muted);
    border-radius: 4px;
    transition: all 0.2s ease;
  }

  .input-icon-btn:hover {
    color: var(--accent);
    background: rgba(29, 242, 166, 0.08);
  }

  .input-icon-btn .icon {
    width: 16px;
    height: 16px;
    display: block;
  }

  .methods-panel {
    margin-top: 12px;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 10px;
    margin-bottom: 16px;
  }

  .tile {
    background: linear-gradient(135deg, #0a0e13 0%, #0d1218 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 12px;
    transition: all 0.2s ease;
  }

  .tile:hover {
    border-color: rgba(29, 242, 166, 0.3);
    box-shadow: inset 0 0 0 1px rgba(29, 242, 166, 0.1);
  }

  .tile-content {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .name {
    font-size: 15px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: 0.2px;
  }

  .browser-icon {
    width: 16px;
    height: 16px;
    opacity: 0.7;
    transition: opacity 0.2s ease;
    cursor: help;
    filter: brightness(0) invert(1);
    align-self: center;
  }

  .browser-icon:hover {
    opacity: 1;
  }

  .badges {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    align-items: center;
  }

  .badges .browser-icon:first-of-type {
    margin-left: auto;
  }

  .badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
    padding: 3px 7px;
    border: 1px solid var(--border);
    border-radius: 999px;
    color: var(--muted-2);
    background: rgba(0, 0, 0, 0.3);
    transition: all 0.2s ease;
  }

  .badge .dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: #3a4450;
    transition: all 0.3s ease;
  }

  .badge[data-kind="sent"].on {
    border-color: rgba(255, 184, 107, 0.4);
    background: rgba(255, 184, 107, 0.08);
    color: var(--warn);
  }

  .badge[data-kind="sent"].on .dot {
    background: var(--warn);
    box-shadow: 0 0 6px rgba(255, 184, 107, 0.4);
  }

  .badge[data-kind="recv"].on {
    border-color: rgba(46, 229, 123, 0.4);
    background: rgba(46, 229, 123, 0.08);
    color: var(--good);
  }

  .badge[data-kind="recv"].on .dot {
    background: var(--good);
    box-shadow: 0 0 6px rgba(46, 229, 123, 0.4);
  }

  @media (max-width: 820px) {
    .grid {
      grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
      gap: 8px;
    }

    .tile {
      padding: 10px;
    }

    .name {
      font-size: 12px;
    }

    .badge {
      font-size: 9px;
      padding: 2px 6px;
    }
  }
</style>
