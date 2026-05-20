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
  "beacon", "websocket", "eventsource", "iframe", "object",
  "svg-use", "font-face", "css-bg", "paint-worklet", "manifest",
  "icon", "apple-touch-icon", "webtransport", "webrtc-stun",
  "anchors", "speculation-prefetch",
] as const

const FIREFOX_VISIBLE = new Set([
  "preload", "image", "stylesheet", "script", "dynamic-import",
  "fetch", "beacon", "websocket", "eventsource", "iframe",
  "svg-use", "font-face", "icon", "apple-touch-icon",
])

const CHROMIUM_VISIBLE = new Set([
  "prefetch", "preload", "image", "stylesheet", "script",
  "dynamic-import", "fetch", "beacon", "websocket", "eventsource",
  "iframe", "svg-use", "font-face", "paint-worklet", "manifest",
  "icon", "webtransport",
])

interface MethodState {
  sent: boolean
  recv: boolean
  rid: string | null
}

const MAX_INFLIGHT = 2
const METHOD_DELAY_MS = 150
const LOADER_TIMEOUT_MS = 6000

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

function viaDnsPrefetch(domain: string) {
  const l = document.createElement("link"); l.rel = "dns-prefetch"; l.href = "//" + domain
  document.head.appendChild(l); return Promise.resolve()
}

function viaPreconnect(domain: string) {
  const l = document.createElement("link"); l.rel = "preconnect"; l.href = "https://" + domain
  document.head.appendChild(l); return Promise.resolve()
}

function viaLinkPrefetch(domain: string) {
  const l = document.createElement("link"); l.rel = "prefetch"; l.as = "fetch"
  l.href = "https://" + domain + "/x?t=" + Date.now()
  document.head.appendChild(l); return Promise.resolve()
}

function viaPreload(domain: string) {
  const l = document.createElement("link"); l.rel = "preload"; l.as = "image"
  l.href = "https://" + domain + "/i.png?t=" + Date.now()
  document.head.appendChild(l); return Promise.resolve()
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
  document.head.appendChild(st); return Promise.resolve()
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
  svg.appendChild(use); svg.style.display = "none"
  document.body.appendChild(svg); setTimeout(() => svg.remove(), 2000)
  return Promise.resolve()
}

async function viaFontFace(domain: string) {
  try {
    const ff = new FontFace("T", `url(https://${domain}/f.woff2?t=${Date.now()})`)
    document.fonts.add(ff); await ff.load()
  } catch { /* expected */ }
}

function viaCssBg(domain: string) {
  const d = document.createElement("div")
  d.style.width = "1px"; d.style.height = "1px"
  d.style.backgroundImage = `url(https://${domain}/bg.png?t=${Date.now()})`
  d.style.display = "none"; document.body.appendChild(d)
  setTimeout(() => d.remove(), 1500); return Promise.resolve()
}

async function viaPaintWorklet(domain: string) {
  try {
    if ("paintWorklet" in CSS) await (CSS as unknown as { paintWorklet: { addModule: (url: string) => Promise<void> } }).paintWorklet.addModule("https://" + domain + "/worklet.js?t=" + Date.now())
  } catch { /* expected */ }
}

function viaManifest(domain: string) {
  const l = document.createElement("link"); l.rel = "manifest"
  l.href = "https://" + domain + "/manifest.json?t=" + Date.now()
  document.head.appendChild(l); return Promise.resolve()
}

function viaIcon(domain: string) {
  const l = document.createElement("link"); l.rel = "icon"
  l.href = "https://" + domain + "/favicon.ico?t=" + Date.now()
  document.head.appendChild(l); return Promise.resolve()
}

function viaAppleIcon(domain: string) {
  const l = document.createElement("link"); l.rel = "apple-touch-icon"
  l.href = "https://" + domain + "/apple-touch-icon.png?t=" + Date.now()
  document.head.appendChild(l); return Promise.resolve()
}

async function viaWebTransport(domain: string) {
  try {
    if ("WebTransport" in window) {
      const wt = new (window as unknown as { WebTransport: new (url: string) => { ready: Promise<void>; close: () => void } }).WebTransport("https://" + domain + "/wt?t=" + Date.now())
      await Promise.race([wt.ready, new Promise((r) => setTimeout(r, 800))])
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
  const a = document.createElement("a")
  a.href = "https://" + domain + "/a?t=" + Date.now()
  a.rel = "noreferrer"; a.ping = "https://" + domain + "/p"
  a.style.position = "absolute"; a.style.left = "-9999px"
  document.body.appendChild(a); return Promise.resolve()
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
  "dynamic-import": viaDynamicImport, fetch: viaFetch, beacon: viaBeacon,
  websocket: viaWebSocket, eventsource: viaEventSource, iframe: viaIframe,
  object: viaObject, "svg-use": viaSvgUse, "font-face": viaFontFace,
  "css-bg": viaCssBg, "paint-worklet": viaPaintWorklet, manifest: viaManifest,
  icon: viaIcon, "apple-touch-icon": viaAppleIcon, webtransport: viaWebTransport,
  "webrtc-stun": viaWebRTC, anchors: viaAnchors,
  "speculation-prefetch": viaSpeculationPrefetch,
}

function runDomains(domains: string[], loader: (d: string) => Promise<void>): Promise<void> {
  let inflight = 0, idx = 0
  return new Promise((resolve) => {
    function step() {
      if (idx >= domains.length && inflight === 0) { resolve(); return }
      while (inflight < MAX_INFLIGHT && idx < domains.length) {
        const d = domains[idx++]; inflight++
        Promise.race([loader(d), new Promise<void>((r) => setTimeout(r, LOADER_TIMEOUT_MS))])
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
  const [methodState, setMethodState] = useState<Record<string, MethodState>>(() =>
    Object.fromEntries(METHODS.map((m) => [m, { sent: false, recv: false, rid: null }]))
  )

  const wsRef = useRef<WebSocket | null>(null)
  const sessionRef = useRef(Math.random().toString(36).slice(2, 10))

  const connectWs = useCallback(async (mb: string) => {
    const validated = validateMailbox(mb)
    if (!validated) { setStatus({ text: "Mailbox must be 12 lowercase hex chars", level: "bad" }); return }
    setStatus({ text: "Connecting...", level: "warn" })
    setIsConnected(false)

    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      try { wsRef.current.close() } catch { /* */ }
    }

    const httpBase = host.includes("dnsm.re") ? "https://" + host : "http://" + host
    const u = new URL(httpBase); u.protocol = u.protocol === "https:" ? "wss:" : "ws:"
    const wsBase = u.toString().replace(/\/$/, "")

    try {
      const ws = new WebSocket(`${wsBase}/ws/${validated}`)
      wsRef.current = ws
      ws.addEventListener("open", () => { setStatus({ text: "Connected to WebSocket server", level: "good" }); setIsConnected(true) })
      ws.addEventListener("close", () => { setStatus({ text: "Disconnected", level: "warn" }); setIsConnected(false) })
      ws.addEventListener("error", () => { setStatus({ text: "WebSocket error", level: "bad" }); setIsConnected(false) })
      ws.addEventListener("message", (ev) => {
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
      setStatus({ text: `WS init failed: ${e}`, level: "bad" })
    }
  }, [host])

  useEffect(() => {
    const mb = randomMailbox()
    setMailbox(mb)

    import("@/lib/pkg-web/dnsm.js").then(async (mod) => {
      await mod.default()
      setWasmModule(mod as unknown as WasmModule)
    }).catch(() => setStatus({ text: "Failed to load Wasm module", level: "bad" }))

    connectWs(mb)

    return () => {
      if (wsRef.current) try { wsRef.current.close() } catch { /* */ }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function startTest() {
    if (!wasmModule) { setStatus({ text: "Wasm module not loaded", level: "bad" }); return }

    sessionRef.current = Math.random().toString(36).slice(2, 10)
    setMethodState(Object.fromEntries(METHODS.map((m) => [m, { sent: false, recv: false, rid: null }])))
    setTestCompleted(false)
    setStatus({ text: "Running tests...", level: "warn" })
    setIsRunning(true)

    const userAgent = typeof navigator !== "undefined" && navigator.userAgent ? navigator.userAgent : "unknown"

    try {
      for (const method of METHODS) {
        const rid = Math.random().toString(36).slice(2, 10)
        const parts = [`sid=${sessionRef.current}`, `m=${method}`, `t=${Date.now().toString(36)}`, `r=${rid}`, `ua=${userAgent}`]
        const testMessage = parts.map((p) => `${p};\n`).join("")
        const domains = Array.from(wasmModule.domains_for_string_with_mailbox(testMessage, zone, mailbox))

        setMethodState((prev) => ({ ...prev, [method]: { sent: true, recv: prev[method]?.recv || false, rid } }))

        const loader = methodLoaders[method]
        if (loader) await runDomains(domains, loader)
        await new Promise((r) => setTimeout(r, METHOD_DELAY_MS))
      }
      setStatus({ text: "Sent all - waiting for receipts", level: "warn" })
      setTestCompleted(true)
    } catch (e) {
      setStatus({ text: `Test error: ${e}`, level: "bad" })
    } finally {
      setIsRunning(false)
    }
  }

  async function copyText(content: string) {
    try { await navigator.clipboard.writeText(content) } catch { /* */ }
  }

  const statusDot = status.level === "good" ? "bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"
    : status.level === "warn" ? "bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.5)]"
    : status.level === "bad" ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"
    : "bg-muted-foreground"

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
          {testCompleted && (
            <Link to={`/inbox?mailbox=${mailbox}&host=${host}&auto=true`}>
              <Button variant="outline">View Messages in Inbox &rarr;</Button>
            </Link>
          )}
        </div>
      </Card>

      <Card className="p-4">
        <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2.5 mb-4">
          {METHODS.map((method) => (
            <div key={method} className="rounded-md border p-3 hover:border-primary/30 transition-colors">
              <div className="font-semibold text-sm mb-2">{method}</div>
              <div className="flex flex-wrap items-center gap-1.5">
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
          font, CSS background, and more.
        </p>
      </Card>
    </div>
  )
}
