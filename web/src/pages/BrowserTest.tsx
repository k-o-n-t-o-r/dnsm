import { useState, useEffect, useRef, useCallback } from "react"
import { Link } from "react-router-dom"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Copy } from "lucide-react"
import { validateMailbox, randomMailbox } from "@/lib/utils"

type StatusLevel = "idle" | "good" | "warn" | "bad"

interface WasmModule {
  default: () => Promise<void>
  domains_for_string_with_mailbox: (input: string, zone: string, mailbox: string) => string[]
}

const METHODS = [
  "dns-prefetch", "preconnect", "prefetch", "preload", "image",
  "stylesheet", "css-import", "script", "dynamic-import", "fetch",
  "fetch-keepalive", "beacon", "websocket", "eventsource", "iframe", "object",
  "svg-use", "svg-image", "font-face", "css-bg", "paint-worklet", "manifest",
  "icon", "apple-touch-icon", "webtransport", "webrtc-stun",
  "anchors", "speculation-prefetch",
] as const

const FIREFOX_VISIBLE = new Set([
  "preload", "image", "stylesheet", "script", "dynamic-import",
  "fetch", "fetch-keepalive", "beacon", "websocket", "eventsource", "iframe",
  "svg-use", "svg-image", "font-face", "icon", "apple-touch-icon",
])

const CHROMIUM_VISIBLE = new Set([
  "prefetch", "preload", "image", "stylesheet", "script",
  "dynamic-import", "fetch", "fetch-keepalive", "beacon", "websocket", "eventsource",
  "iframe", "svg-use", "svg-image", "font-face", "paint-worklet", "manifest",
  "icon", "webtransport",
])

interface MethodState {
  sent: boolean
  recv: boolean
  rid: string | null
  unsupported: string | null
}

const MAX_INFLIGHT = 2
const METHOD_DELAY_MS = 150
const LOADER_TIMEOUT_MS = 6000
const RECEIPT_WAIT_MS = 8000

function unsupportedReason(method: typeof METHODS[number]): string | null {
  if (method === "beacon" && !("sendBeacon" in navigator)) return "sendBeacon unavailable"
  if (method === "eventsource" && !("EventSource" in window)) return "EventSource unavailable"
  if (method === "paint-worklet" && !("paintWorklet" in CSS)) return "Paint Worklet unavailable"
  if (method === "webtransport" && !("WebTransport" in window)) return "WebTransport unavailable"
  if (method === "webrtc-stun" && !("RTCPeerConnection" in window)) return "WebRTC unavailable"
  if (method === "speculation-prefetch") {
    const supports = (HTMLScriptElement as unknown as { supports?: (type: string) => boolean }).supports
    if (!supports?.("speculationrules")) return "Speculation Rules unavailable"
  }
  return null
}

function initialMethodState(): Record<string, MethodState> {
  return Object.fromEntries(METHODS.map((method) => [method, {
    sent: false,
    recv: false,
    rid: null,
    unsupported: unsupportedReason(method),
  }]))
}

function viaImage(domain: string) {
  return new Promise<void>((res) => {
    const img = new Image()
    img.decoding = "async"
    img.referrerPolicy = "no-referrer"
    img.onload = img.onerror = img.onabort = () => { img.remove(); res() }
    img.src = `https://${domain}/p.png?${Date.now()}_${Math.random().toString(36).slice(2)}`
    document.body.appendChild(img)
  })
}

function removeLater(element: Element, delay = 3000) {
  setTimeout(() => element.remove(), delay)
}

function viaDnsPrefetch(domain: string) {
  const l = document.createElement("link"); l.rel = "dns-prefetch"; l.href = "//" + domain
  document.head.appendChild(l); removeLater(l); return Promise.resolve()
}

function viaPreconnect(domain: string) {
  const l = document.createElement("link"); l.rel = "preconnect"; l.href = "https://" + domain
  document.head.appendChild(l); removeLater(l); return Promise.resolve()
}

function viaLinkPrefetch(domain: string) {
  const l = document.createElement("link"); l.rel = "prefetch"; l.as = "fetch"
  l.href = "https://" + domain + "/x?t=" + Date.now()
  document.head.appendChild(l); removeLater(l); return Promise.resolve()
}

function viaPreload(domain: string) {
  return new Promise<void>((resolve) => {
    const href = "https://" + domain + "/i.png?t=" + Date.now()
    const l = document.createElement("link"); l.rel = "preload"; l.as = "image"; l.href = href
    const img = new Image(); img.referrerPolicy = "no-referrer"
    img.onload = img.onerror = img.onabort = () => { l.remove(); img.remove(); resolve() }
    document.head.appendChild(l)
    img.src = href
    document.body.appendChild(img)
  })
}

function viaStylesheet(domain: string) {
  return new Promise<void>((res) => {
    const l = document.createElement("link"); l.rel = "stylesheet"
    l.href = "https://" + domain + "/x.css?t=" + Date.now()
    l.onload = l.onerror = () => { l.remove(); res() }
    document.head.appendChild(l)
  })
}

function viaCssImport(domain: string) {
  const st = document.createElement("style")
  st.textContent = `@import url("https://${domain}/x.css?t=${Date.now()}");`
  document.head.appendChild(st); removeLater(st); return Promise.resolve()
}

function viaScript(domain: string) {
  return new Promise<void>((res) => {
    const s = document.createElement("script"); s.src = "https://" + domain + "/x.js?t=" + Date.now()
    s.async = true; s.onload = s.onerror = () => { s.remove(); res() }
    document.head.appendChild(s)
  })
}

async function viaDynamicImport(domain: string) {
  try { await import(/* @vite-ignore */ "https://" + domain + "/m.js?t=" + Date.now()) } catch { /* expected */ }
}

async function viaFetch(domain: string) {
  try { await fetch("https://" + domain + "/x?t=" + Date.now(), { mode: "no-cors", cache: "no-store" }) } catch { /* expected */ }
}

async function viaFetchKeepalive(domain: string) {
  try {
    await fetch("https://" + domain + "/keepalive?t=" + Date.now(), {
      method: "POST", mode: "no-cors", cache: "no-store", keepalive: true, body: "x",
    })
  } catch { /* expected */ }
}

function viaBeacon(domain: string) {
  try { navigator.sendBeacon("https://" + domain + "/b?t=" + Date.now(), new Blob(["x"])) } catch { /* expected */ }
  return Promise.resolve()
}

function viaWebSocket(domain: string) {
  try {
    const s = new WebSocket("wss://" + domain + "/ws?t=" + Date.now())
    setTimeout(() => { try { s.close() } catch { /* */ } }, 1500)
  } catch { /* expected */ }
  return Promise.resolve()
}

function viaEventSource(domain: string) {
  try {
    const es = new EventSource("https://" + domain + "/sse?t=" + Date.now())
    setTimeout(() => { try { es.close() } catch { /* */ } }, 1500)
  } catch { /* expected */ }
  return Promise.resolve()
}

function viaIframe(domain: string) {
  const fr = document.createElement("iframe"); fr.style.display = "none"
  fr.src = "https://" + domain + "/frame?t=" + Date.now()
  document.body.appendChild(fr); setTimeout(() => fr.remove(), 2000)
  return Promise.resolve()
}

function viaObject(domain: string) {
  const o = document.createElement("object"); o.style.display = "none"
  o.data = "https://" + domain + "/obj?t=" + Date.now()
  document.body.appendChild(o); setTimeout(() => o.remove(), 2000)
  return Promise.resolve()
}

function viaSvgUse(domain: string) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg")
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use")
  use.setAttributeNS("http://www.w3.org/1999/xlink", "href", "https://" + domain + "/s.svg#x?t=" + Date.now())
  svg.appendChild(use); svg.style.position = "fixed"; svg.style.left = "-9999px"
  document.body.appendChild(svg); removeLater(svg, 2000)
  return Promise.resolve()
}

function viaSvgImage(domain: string) {
  return new Promise<void>((resolve) => {
    const img = new Image(); img.referrerPolicy = "no-referrer"
    img.onload = img.onerror = img.onabort = () => { img.remove(); resolve() }
    img.src = "https://" + domain + "/s.svg?t=" + Date.now()
    document.body.appendChild(img)
  })
}

async function viaFontFace(domain: string) {
  try {
    const ff = new FontFace("T", `url(https://${domain}/f.woff2?t=${Date.now()})`)
    document.fonts.add(ff); await ff.load()
  } catch { /* expected */ }
}

function viaCssBg(domain: string) {
  const d = document.createElement("div")
  d.style.position = "fixed"; d.style.left = "-9999px"
  d.style.width = "1px"; d.style.height = "1px"
  d.style.backgroundImage = `url(https://${domain}/bg.png?t=${Date.now()})`
  document.body.appendChild(d); removeLater(d, 2000); return Promise.resolve()
}

async function viaPaintWorklet(domain: string) {
  try {
    if ("paintWorklet" in CSS) await (CSS as unknown as { paintWorklet: { addModule: (url: string) => Promise<void> } }).paintWorklet.addModule("https://" + domain + "/worklet.js?t=" + Date.now())
  } catch { /* expected */ }
}

function viaManifest(domain: string) {
  const l = document.createElement("link"); l.rel = "manifest"
  l.href = "https://" + domain + "/manifest.json?t=" + Date.now()
  document.head.appendChild(l); removeLater(l); return Promise.resolve()
}

function viaIcon(domain: string) {
  const l = document.createElement("link"); l.rel = "icon"
  l.href = "https://" + domain + "/favicon.ico?t=" + Date.now()
  document.head.appendChild(l); removeLater(l); return Promise.resolve()
}

function viaAppleIcon(domain: string) {
  const l = document.createElement("link"); l.rel = "apple-touch-icon"
  l.href = "https://" + domain + "/apple-touch-icon.png?t=" + Date.now()
  document.head.appendChild(l); removeLater(l); return Promise.resolve()
}

async function viaWebTransport(domain: string) {
  try {
    if ("WebTransport" in window) {
      const wt = new (window as unknown as { WebTransport: new (url: string) => { ready: Promise<void>; close: () => void } }).WebTransport("https://" + domain + "/wt?t=" + Date.now())
      const ready = wt.ready.catch(() => undefined)
      await Promise.race([ready, new Promise((resolve) => setTimeout(resolve, 800))])
      try { wt.close() } catch { /* */ }
    }
  } catch { /* expected */ }
}

async function viaWebRTC(domain: string) {
  try {
    const pc = new RTCPeerConnection({ iceServers: [{ urls: ["stun:" + domain + ":3478"] }] })
    pc.createDataChannel("x")
    await pc.setLocalDescription(await pc.createOffer())
    setTimeout(() => pc.close(), 1500)
  } catch { /* expected */ }
}

function viaAnchors(domain: string) {
  const iframe = document.createElement("iframe")
  iframe.style.display = "none"
  document.body.appendChild(iframe)
  const doc = iframe.contentDocument
  if (!doc) { iframe.remove(); return Promise.resolve() }
  const a = doc.createElement("a")
  a.href = "https://" + domain + "/a?t=" + Date.now()
  a.rel = "noreferrer"; a.ping = "https://" + domain + "/p"
  doc.body.appendChild(a); a.click()
  setTimeout(() => iframe.remove(), 2000)
  return Promise.resolve()
}

function viaSpeculationPrefetch(domain: string) {
  try {
    const s = document.createElement("script"); s.type = "speculationrules"
    s.textContent = JSON.stringify({ prefetch: [{ source: "list", urls: ["https://" + domain + "/sp?t=" + Date.now()], eagerness: "moderate" }] })
    document.body.appendChild(s); setTimeout(() => s.remove(), 1200)
  } catch { /* expected */ }
  return Promise.resolve()
}

const methodLoaders: Record<string, (domain: string) => Promise<void>> = {
  "dns-prefetch": viaDnsPrefetch, preconnect: viaPreconnect,
  prefetch: viaLinkPrefetch, preload: viaPreload, image: viaImage,
  stylesheet: viaStylesheet, "css-import": viaCssImport, script: viaScript,
  "dynamic-import": viaDynamicImport, fetch: viaFetch, "fetch-keepalive": viaFetchKeepalive, beacon: viaBeacon,
  websocket: viaWebSocket, eventsource: viaEventSource, iframe: viaIframe,
  object: viaObject, "svg-use": viaSvgUse, "svg-image": viaSvgImage, "font-face": viaFontFace,
  "css-bg": viaCssBg, "paint-worklet": viaPaintWorklet, manifest: viaManifest,
  icon: viaIcon, "apple-touch-icon": viaAppleIcon, webtransport: viaWebTransport,
  "webrtc-stun": viaWebRTC, anchors: viaAnchors,
  "speculation-prefetch": viaSpeculationPrefetch,
}

function waitFor(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) { resolve(); return }
    const timer = setTimeout(resolve, ms)
    signal.addEventListener("abort", () => { clearTimeout(timer); resolve() }, { once: true })
  })
}

function runDomains(
  domains: string[],
  loader: (d: string) => Promise<void>,
  signal: AbortSignal,
): Promise<void> {
  let inflight = 0, idx = 0, settled = false
  return new Promise((resolve) => {
    const finish = () => {
      if (settled) return
      settled = true
      resolve()
    }
    signal.addEventListener("abort", finish, { once: true })
    function step() {
      if (signal.aborted) { finish(); return }
      if (idx >= domains.length && inflight === 0) { finish(); return }
      while (inflight < MAX_INFLIGHT && idx < domains.length && !signal.aborted) {
        const d = domains[idx++]; inflight++
        Promise.race([loader(d), waitFor(LOADER_TIMEOUT_MS, signal)])
          .finally(() => { inflight--; step() })
      }
    }
    step()
  })
}

export function BrowserTest() {
  const [host] = useState("ws.dnsm.re")
  const [zone] = useState("k.dnsm.re")
  const [mailbox, setMailbox] = useState("")
  const [status, setStatus] = useState<{ text: string; level: StatusLevel }>({ text: "Idle", level: "idle" })
  const [isConnected, setIsConnected] = useState(false)
  const [isRunning, setIsRunning] = useState(false)
  const [testCompleted, setTestCompleted] = useState(false)
  const [wasmModule, setWasmModule] = useState<WasmModule | null>(null)
  const [methodState, setMethodState] = useState<Record<string, MethodState>>(initialMethodState)

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectDelayRef = useRef(1000)
  const wsGenerationRef = useRef(0)
  const connectWsRef = useRef<(mb: string) => Promise<void>>(null!)
  const runAbortRef = useRef<AbortController | null>(null)
  const unmountedRef = useRef(false)
  const sessionRef = useRef(Math.random().toString(36).slice(2, 10))

  const scheduleReconnect = useCallback((mb: string) => {
    if (unmountedRef.current) return
    if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
    const delay = reconnectDelayRef.current
    setStatus({ text: `Reconnecting in ${Math.round(delay / 1000)}s...`, level: "warn" })
    reconnectTimerRef.current = setTimeout(() => connectWsRef.current(mb), delay)
    reconnectDelayRef.current = Math.min(delay * 2, 20000)
  }, [])

  const connectWs = useCallback(async (mb: string) => {
    const validated = validateMailbox(mb)
    if (!validated) { setStatus({ text: "Mailbox must be 12 lowercase hex chars", level: "bad" }); return }
    const generation = ++wsGenerationRef.current
    setStatus({ text: "Connecting...", level: "warn" })
    setIsConnected(false)
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }

    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      try { wsRef.current.close() } catch { /* */ }
    }

    const httpBase = host.includes("dnsm.re") ? "https://" + host : "http://" + host
    const u = new URL(httpBase); u.protocol = u.protocol === "https:" ? "wss:" : "ws:"
    const wsBase = u.toString().replace(/\/$/, "")

    try {
      const ws = new WebSocket(`${wsBase}/ws/${validated}`)
      wsRef.current = ws
      ws.addEventListener("open", () => {
        if (generation !== wsGenerationRef.current) { ws.close(); return }
        reconnectDelayRef.current = 1000
        setStatus({ text: "Connected to WebSocket server", level: "good" })
        setIsConnected(true)
      })
      ws.addEventListener("close", () => {
        if (generation !== wsGenerationRef.current || unmountedRef.current) return
        setStatus({ text: "Disconnected", level: "warn" })
        setIsConnected(false)
        scheduleReconnect(validated)
      })
      ws.addEventListener("error", () => {
        if (generation !== wsGenerationRef.current) return
        setStatus({ text: "WebSocket error", level: "bad" })
        setIsConnected(false)
      })
      ws.addEventListener("message", (ev) => {
        if (generation !== wsGenerationRef.current) return
        try {
          const m = JSON.parse(ev.data)
          const text = atob(m.data_b64)
          const kv = Object.fromEntries(
            text.split(";").map((s: string) => s.trim()).filter(Boolean)
              .map((s: string) => { const [key, value = ""] = s.split("="); return [key, value] })
          )
          if (kv.sid === sessionRef.current && kv.m) {
            setMethodState((prev) => {
              const entry = prev[kv.m]
              if (!entry || entry.rid !== kv.r) return prev
              return { ...prev, [kv.m]: { ...entry, recv: true } }
            })
          }
        } catch { /* ignore */ }
      })
    } catch (e) {
      if (generation !== wsGenerationRef.current) return
      setStatus({ text: `WS init failed: ${e}`, level: "bad" })
      scheduleReconnect(validated)
    }
  }, [host, scheduleReconnect])

  connectWsRef.current = connectWs

  useEffect(() => {
    unmountedRef.current = false
    const mb = randomMailbox()
    setMailbox(mb)

    import("@/lib/pkg-web/dnsm.js").then(async (mod) => {
      await mod.default()
      setWasmModule(mod as unknown as WasmModule)
    }).catch(() => setStatus({ text: "Failed to load Wasm module", level: "bad" }))

    connectWs(mb)

    return () => {
      unmountedRef.current = true
      wsGenerationRef.current++
      runAbortRef.current?.abort()
      runAbortRef.current = null
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
      if (wsRef.current) try { wsRef.current.close() } catch { /* */ }
    }

  }, [])

  async function startTest() {
    if (!wasmModule) { setStatus({ text: "Wasm module not loaded", level: "bad" }); return }

    runAbortRef.current?.abort()
    const controller = new AbortController()
    runAbortRef.current = controller
    sessionRef.current = Math.random().toString(36).slice(2, 10)
    setMethodState(initialMethodState())
    setTestCompleted(false)
    setStatus({ text: "Running tests...", level: "warn" })
    setIsRunning(true)

    const userAgent = typeof navigator !== "undefined" && navigator.userAgent ? navigator.userAgent : "unknown"

    try {
      for (const method of METHODS) {
        if (controller.signal.aborted) break
        const unsupported = unsupportedReason(method)
        if (unsupported) continue
        const rid = Math.random().toString(36).slice(2, 10)
        const parts = [`sid=${sessionRef.current}`, `m=${method}`, `t=${Date.now().toString(36)}`, `r=${rid}`, `ua=${userAgent}`]
        const testMessage = parts.map((p) => `${p};\n`).join("")
        const domains = Array.from(wasmModule.domains_for_string_with_mailbox(testMessage, zone, mailbox))

        setMethodState((prev) => ({
          ...prev,
          [method]: { sent: true, recv: prev[method]?.recv || false, rid, unsupported: null },
        }))

        const loader = methodLoaders[method]
        if (loader) await runDomains(domains, loader, controller.signal)
        await waitFor(METHOD_DELAY_MS, controller.signal)
      }
      if (!controller.signal.aborted) {
        setStatus({ text: "Sent all - waiting for receipts", level: "warn" })
        await waitFor(RECEIPT_WAIT_MS, controller.signal)
      }
      if (!controller.signal.aborted) {
        setStatus({ text: "Test complete", level: "good" })
        setTestCompleted(true)
      }
    } catch (e) {
      if (!controller.signal.aborted) setStatus({ text: `Test error: ${e}`, level: "bad" })
    } finally {
      if (runAbortRef.current === controller) {
        runAbortRef.current = null
        setIsRunning(false)
      }
    }
  }

  function cancelTest() {
    runAbortRef.current?.abort()
    runAbortRef.current = null
    setIsRunning(false)
    setStatus({ text: "Test cancelled", level: "idle" })
  }

  async function copyText(content: string) {
    try { await navigator.clipboard.writeText(content) } catch { /* */ }
  }

  const statusDot = status.level === "good" ? "bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"
    : status.level === "warn" ? "bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.5)]"
    : status.level === "bad" ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"
    : "bg-muted-foreground"
  const states = Object.values(methodState)
  const attemptedCount = states.filter((entry) => entry.sent).length
  const receivedCount = states.filter((entry) => entry.recv).length
  const unsupportedCount = states.filter((entry) => entry.unsupported).length

  return (
    <div className="max-w-[1100px] mx-auto p-5 md:p-7">
      <header className="flex items-center justify-between gap-4 mb-5 flex-wrap">
        <Link to="/" className="text-lg font-bold hover:opacity-80 transition-opacity">
          <span className="text-seagrass">dnsm</span> <span className="text-muted-foreground font-normal">// browser test</span>
        </Link>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <span className={`w-2 h-2 rounded-full ${statusDot}`} />
          <span>{status.text}</span>
        </div>
      </header>

      <Card className="p-4 mb-4">
        <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-3 items-center">
          <label className="text-sm text-muted-foreground">WebSocket server</label>
          <Input value={host} readOnly spellCheck={false} />
          <label className="text-sm text-muted-foreground">Zone</label>
          <Input value={zone} readOnly spellCheck={false} />
          <label className="text-sm text-muted-foreground">Mailbox</label>
          <div className="flex items-center gap-2">
            <Input value={mailbox} readOnly spellCheck={false} className="flex-1" />
            <Button variant="ghost" size="icon" onClick={() => copyText(mailbox)} className="shrink-0">
              <Copy className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <div className="flex items-center justify-center gap-3 mt-4">
          <Button onClick={startTest} disabled={!isConnected || isRunning} className="min-w-[180px]">
            Start Test
          </Button>
          {isRunning && (
            <Button variant="outline" onClick={cancelTest}>Cancel</Button>
          )}
          {testCompleted && (
            <Link to={`/inbox?mailbox=${mailbox}&host=${host}&auto=true`}>
              <Button variant="outline">View Messages in Inbox &rarr;</Button>
            </Link>
          )}
        </div>
      </Card>

      <Card className="p-4">
        <div className="flex flex-wrap gap-4 text-xs text-muted-foreground mb-4">
          <span>attempted <strong className="text-foreground">{attemptedCount}</strong></span>
          <span>received <strong className="text-green-400">{receivedCount}</strong></span>
          <span>unsupported <strong className="text-foreground">{unsupportedCount}</strong></span>
        </div>
        <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2.5 mb-4">
          {METHODS.map((method) => (
            <div key={method} className="rounded-md border p-3 hover:border-primary/30 transition-colors">
              <div className="font-semibold text-sm mb-2">{method}</div>
              <div className="flex flex-wrap items-center gap-1.5">
                {methodState[method]?.unsupported ? (
                  <Badge
                    variant="outline"
                    className="text-[10px] text-muted-foreground"
                    title={methodState[method].unsupported ?? undefined}
                  >
                    unsupported
                  </Badge>
                ) : (
                  <>
                    <Badge
                      variant="outline"
                      className={`text-[10px] gap-1 ${methodState[method]?.sent
                        ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                        : "text-muted-foreground"}`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${methodState[method]?.sent ? "bg-yellow-400" : "bg-muted"}`} />
                      sent
                    </Badge>
                    <Badge
                      variant="outline"
                      className={`text-[10px] gap-1 ${methodState[method]?.recv
                        ? "border-green-500/40 bg-green-500/10 text-green-400"
                        : "text-muted-foreground"}`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${methodState[method]?.recv ? "bg-green-400" : "bg-muted"}`} />
                      received
                    </Badge>
                  </>
                )}
                {FIREFOX_VISIBLE.has(method) && (
                  <img src="/firefox.svg" alt="Firefox" title="Visible in Firefox Network tab" className="w-4 h-4 opacity-70 hover:opacity-100 transition-opacity invert ml-auto" />
                )}
                {CHROMIUM_VISIBLE.has(method) && (
                  <img src="/chromium.svg" alt="Chromium" title="Visible in Chromium Network tab" className="w-4 h-4 opacity-70 hover:opacity-100 transition-opacity invert" />
                )}
              </div>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          This runs a battery of techniques to nudge the browser into resolving dnsm
          chunk domains (generated via Wasm) - images, preconnect/prefetch,
          stylesheet/script, fetch/beacon, WebSocket/EventSource, iframe/object,
          font, CSS background, and more. Unsupported means the browser lacks the API;
          attempted but not received can also mean a privacy setting suppressed the lookup.
        </p>
      </Card>
    </div>
  )
}
