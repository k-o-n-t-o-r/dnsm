import { useState, useEffect, useRef, useCallback } from "react"
import { Link, useParams, useLocation, useNavigate } from "react-router-dom"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Collapsible } from "@/components/ui/collapsible"
import { Copy, ChevronDown, Shuffle, Trash2 } from "lucide-react"
import { validateMailbox, randomMailbox } from "@/lib/utils"

interface DecodedPayload {
  type: "text" | "json" | "binary" | "invalid" | "ping"
  content: string
  raw: string
}

interface Message {
  id: string
  message_hex?: string
  received_at?: number
  message_type?: string
  data_b64: string
  peer_ip?: string
  payload: DecodedPayload
}

type StatusLevel = "idle" | "good" | "warn" | "bad"

function toHex(bytes: Uint8Array): string {
  let out = ""
  for (let i = 0; i < bytes.length; i++) {
    if (i && i % 16 === 0) out += "\n"
    else if (i && i % 2 === 0) out += " "
    out += bytes[i].toString(16).padStart(2, "0")
  }
  return out
}

function decodePayload(b64: string, messageType?: string): DecodedPayload {
  if (messageType === "ping") {
    return { type: "ping", content: "", raw: "" }
  }
  try {
    const bin = atob(b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff

    let text: string | null = null
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
    } catch { /* not utf8 */ }

    const printable = text && text.length > 0 && !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)
    if (text && printable) {
      const trimmed = text.trim()
      if (
        (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
        (trimmed.startsWith("[") && trimmed.endsWith("]"))
      ) {
        try {
          const parsed = JSON.parse(text)
          return { type: "json", content: JSON.stringify(parsed, null, 2), raw: b64 }
        } catch { /* not valid json */ }
      }
      return { type: "text", content: text, raw: b64 }
    }
    return { type: "binary", content: toHex(bytes), raw: b64 }
  } catch (e) {
    return { type: "invalid", content: `Invalid base64: ${e}`, raw: b64 }
  }
}

function formatDate(date: Date): string {
  const d = String(date.getDate()).padStart(2, "0")
  const m = String(date.getMonth() + 1).padStart(2, "0")
  const y = date.getFullYear()
  const H = String(date.getHours()).padStart(2, "0")
  const M = String(date.getMinutes()).padStart(2, "0")
  const S = String(date.getSeconds()).padStart(2, "0")
  return `${d}.${m}.${y}, ${H}:${M}:${S}`
}

function formatReceivedAt(value: unknown): string {
  const numeric = typeof value === "number" ? value : Number(value)
  if (!Number.isFinite(numeric)) return "Unknown time"
  const date = new Date(numeric)
  if (Number.isNaN(date.getTime())) return "Unknown time"
  return formatDate(date)
}

function normalizeHttp(base: string, fallback: string): string {
  const h = (base || "").trim()
  if (!h) return fallback
  if (h.startsWith("http://") || h.startsWith("https://")) return h
  if (h.includes("dnsm.re")) return "https://" + h
  const scheme = location.protocol === "https:" ? "https://" : "http://"
  return scheme + h
}

function toWsUrl(httpBase: string): string {
  const u = new URL(httpBase)
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:"
  return u.toString().replace(/\/$/, "")
}

const COLLAPSE_LINE_THRESHOLD = 12
const COLLAPSE_CHAR_THRESHOLD = 1000

function isLongContent(content: string): boolean {
  return content.length > COLLAPSE_CHAR_THRESHOLD ||
    content.split("\n").length > COLLAPSE_LINE_THRESHOLD
}

interface WasmModule {
  default: () => Promise<void>
  domains_for_string_with_mailbox: (input: string, zone: string, mailbox: string) => string[]
}

export function Inbox() {
  const { id } = useParams()
  const location = useLocation()
  const navigate = useNavigate()

  const defaultHost = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? "127.0.0.1:8787" : "ws.dnsm.re"

  const [host, setHost] = useState(defaultHost)
  const [mailbox, setMailbox] = useState("")
  const [zone, setZone] = useState("k.dnsm.re")
  const [messages, setMessages] = useState<Message[]>([])
  const [status, setStatus] = useState<{ text: string; level: StatusLevel }>({ text: "Idle", level: "idle" })
  const [expandedMessages, setExpandedMessages] = useState<Set<string>>(new Set())
  const [wasmModule, setWasmModule] = useState<WasmModule | null>(null)
  const [genMessage, setGenMessage] = useState("")
  const [genDomains, setGenDomains] = useState<string[]>([])
  const [genError, setGenError] = useState("")

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectDelayRef = useRef(1000)
  const generationRef = useRef(0)
  const abortRef = useRef<AbortController | null>(null)
  const activeMailboxRef = useRef("")
  const activeHostRef = useRef("")

  const parentZone = zone.split(".").slice(1).join(".") || zone
  const mailboxZone = `m.${parentZone}`

  const scheduleReconnect = useCallback(() => {
    if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
    reconnectTimerRef.current = setTimeout(
      () => connect({ mailbox: activeMailboxRef.current, host: activeHostRef.current }),
      reconnectDelayRef.current,
    )
    reconnectDelayRef.current = Math.min(reconnectDelayRef.current * 2, 20000)
    setStatus({ text: `Reconnecting in ${Math.round(reconnectDelayRef.current / 1000)}s...`, level: "warn" })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const connect = useCallback(async (opts?: { mailbox?: string; host?: string; replace?: boolean }) => {
    const target = opts?.mailbox || mailbox
    const effectiveHost = opts?.host || host
    const validated = validateMailbox(target)
    if (!validated) {
      setStatus({ text: "Mailbox must be 12 lowercase hex chars", level: "bad" })
      return
    }

    const gen = ++generationRef.current
    if (abortRef.current) abortRef.current.abort()
    const abort = new AbortController()
    abortRef.current = abort

    activeMailboxRef.current = validated
    activeHostRef.current = effectiveHost
    setMailbox(validated)

    const isNonDefaultHost = effectiveHost !== defaultHost
    const search = isNonDefaultHost ? `?host=${encodeURIComponent(effectiveHost)}` : ""
    const targetUrl = `/inbox/${validated}${search}`
    if (targetUrl !== location.pathname + location.search) {
      navigate(targetUrl, { replace: opts?.replace ?? false })
    }

    setStatus({ text: "Connecting...", level: "warn" })
    setMessages([])

    const prevWs = wsRef.current
    wsRef.current = null
    if (prevWs && (prevWs.readyState === WebSocket.OPEN || prevWs.readyState === WebSocket.CONNECTING)) {
      try { prevWs.close() } catch { /* ignore */ }
    }
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    reconnectDelayRef.current = 1000

    let wsBase: string
    let backlogOk = false
    let timedOut = false
    try {
      const fallback = `${window.location.protocol}//${window.location.host}`
      const httpBase = normalizeHttp(effectiveHost, fallback)
      wsBase = toWsUrl(httpBase)

      const timeout = setTimeout(() => { timedOut = true; abort.abort() }, 10000)
      try {
        const url = `${httpBase.replace(/\/$/, "")}/api/mailbox/${validated}/messages`
        const res = await fetch(url, { signal: abort.signal })
        if (gen !== generationRef.current) return
        if (res.ok) {
          const arr = await res.json()
          if (gen !== generationRef.current) return
          if (Array.isArray(arr)) {
            backlogOk = true
            setMessages(arr.reverse().map((m: { data_b64: string; message_type?: string }) => ({
              ...m,
              payload: decodePayload(m.data_b64, m.message_type),
            } as Message)))
          }
        } else {
          setStatus({ text: `Backlog fetch failed: HTTP ${res.status}`, level: "warn" })
        }
      } catch (e) {
        if (gen !== generationRef.current) return
        if (timedOut) {
          setStatus({ text: "History fetch timed out — showing live messages only", level: "warn" })
        } else if (!abort.signal.aborted) {
          setStatus({ text: `Backlog fetch error: ${e}`, level: "warn" })
        }
      } finally {
        clearTimeout(timeout)
      }
    } catch (e) {
      if (gen !== generationRef.current) return
      setStatus({ text: `Invalid host: ${e}`, level: "bad" })
      return
    }

    if (gen !== generationRef.current) return

    try {
      const ws = new WebSocket(`${wsBase}/ws/${validated}`)
      wsRef.current = ws

      ws.addEventListener("open", () => {
        if (gen !== generationRef.current) { ws.close(); return }
        setStatus(backlogOk
          ? { text: "Connected", level: "good" }
          : { text: "Connected — history unavailable", level: "warn" })
        reconnectDelayRef.current = 1000
      })
      ws.addEventListener("close", () => {
        if (gen !== generationRef.current) return
        setStatus({ text: "Disconnected", level: "warn" })
        scheduleReconnect()
      })
      ws.addEventListener("error", () => {
        if (gen !== generationRef.current) return
        setStatus({ text: "WebSocket error", level: "bad" })
      })
      ws.addEventListener("message", (ev) => {
        if (gen !== generationRef.current) return
        try {
          const m = JSON.parse(ev.data)
          const msg: Message = { ...m, payload: decodePayload(m.data_b64, m.message_type) }
          setMessages((prev) => [...prev, msg])
        } catch { /* ignore */ }
      })
    } catch (e) {
      if (gen !== generationRef.current) return
      setStatus({ text: `WS init failed: ${e}`, level: "bad" })
      scheduleReconnect()
    }
  }, [host, mailbox, defaultHost, navigate, scheduleReconnect, location.pathname, location.search])

  useEffect(() => {
    window.scrollTo({ top: document.documentElement.scrollHeight })
  }, [messages])

  useEffect(() => {
    import("@/lib/pkg-web/dnsm.js").then(async (mod) => {
      await mod.default()
      setWasmModule(mod as unknown as WasmModule)
    }).catch(() => { /* wasm load failed */ })

    return () => {
      generationRef.current++
      if (abortRef.current) abortRef.current.abort()
      const ws = wsRef.current
      wsRef.current = null
      if (ws) try { ws.close() } catch { /* ignore */ }
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const routeSearch = location.search
  useEffect(() => {
    const params = new URLSearchParams(routeSearch)
    const hostParam = params.get("host")

    let mb = ""
    if (id && validateMailbox(id)) {
      mb = id
    }
    if (!mb) {
      const mailboxParam = params.get("mailbox")
      if (mailboxParam) mb = mailboxParam
    }
    if (!mb) {
      mb = import.meta.env.DEV ? "d00d00d00d00" : randomMailbox()
    }

    const effectiveHost = hostParam || defaultHost

    if (mb === activeMailboxRef.current && effectiveHost === activeHostRef.current) return

    setMailbox(mb)
    setHost(effectiveHost)
    setTimeout(() => connect({ mailbox: mb, host: effectiveHost, replace: true }), 0)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, routeSearch])

  useEffect(() => {
    if (!wasmModule || !genMessage.trim() || !zone.trim()) {
      if (!genMessage.trim()) {
        setGenDomains([])
        setGenError("")
      }
      return
    }
    const mb = validateMailbox(mailbox)
    if (!mb) {
      setGenError("Mailbox must be exactly 12 lowercase hex characters")
      return
    }
    setGenError("")
    const timer = setTimeout(() => {
      try {
        const arr = wasmModule.domains_for_string_with_mailbox(genMessage, zone, mb)
        setGenDomains(Array.from(arr))
      } catch (e) {
        setGenError(String(e))
      }
    }, 100)
    return () => clearTimeout(timer)
  }, [wasmModule, genMessage, zone, mailbox])

  function toggleExpand(msgId: string) {
    setExpandedMessages((prev) => {
      const next = new Set(prev)
      if (next.has(msgId)) next.delete(msgId)
      else next.add(msgId)
      return next
    })
  }

  async function copyText(content: string) {
    try { await navigator.clipboard.writeText(content) } catch { /* ignore */ }
  }

  async function generateRandomMailbox() {
    const mb = randomMailbox()
    setMailbox(mb)
    await connect({ mailbox: mb })
  }

  const digCmd = `dig @${parentZone} -p 53 ${mailbox}.${mailboxZone} TXT +tcp +short`

  const statusDot = status.level === "good" ? "bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"
    : status.level === "warn" ? "bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.5)]"
    : status.level === "bad" ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"
    : "bg-muted-foreground"

  return (
    <div className="max-w-[1100px] mx-auto p-5 md:p-7">
      <header className="flex items-center justify-between gap-4 mb-5 flex-wrap">
        <Link to="/" className="text-lg font-bold hover:opacity-80 transition-opacity">
          <span className="text-seagrass">dnsm</span> <span className="text-muted-foreground font-normal">// inbox</span>
        </Link>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <span className={`w-2 h-2 rounded-full ${statusDot}`} />
          <span>{status.text}</span>
        </div>
      </header>

      <Card className="p-4 mb-4">
        <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-3 items-center">
          <label className="text-sm text-muted-foreground">WebSocket Server</label>
          <Input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && connect()}
            placeholder="localhost:8787 or ws.example.com"
            spellCheck={false}
          />
          <label className="text-sm text-muted-foreground">Mailbox</label>
          <div className="flex items-center gap-2 min-w-0">
            <Input
              value={mailbox}
              onChange={(e) => setMailbox(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && connect()}
              placeholder="12 hex chars, e.g. 50373ff32343"
              maxLength={12}
              spellCheck={false}
              className="flex-1 min-w-0"
            />
            <Button variant="outline" size="sm" onClick={generateRandomMailbox} className="shrink-0">
              <Shuffle className="h-3 w-3" /> Random
            </Button>
          </div>
        </div>

      </Card>

      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-muted-foreground">
          {messages.length} message{messages.length === 1 ? "" : "s"}
        </span>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setMessages([])}
          disabled={messages.length === 0}
        >
          <Trash2 className="h-3 w-3" /> Clear
        </Button>
      </div>

      <div className="space-y-3">
        {messages.length === 0 ? (
          <div className="border border-dashed rounded-xl p-6 text-center text-muted-foreground">
            No messages yet. Send some data via dnsm with mailbox.
          </div>
        ) : (
          messages.map((msg) => (
            <MessageCard
              key={msg.id}
              msg={msg}
              expanded={expandedMessages.has(msg.id)}
              onToggle={() => toggleExpand(msg.id)}
              onCopy={copyText}
            />
          ))
        )}
      </div>

      <Collapsible title="Domain Generator" className="mt-4">
        <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-3 items-center mb-3">
          <label className="text-sm text-muted-foreground">Zone</label>
          <Input
            value={zone}
            onChange={(e) => setZone(e.target.value)}
            placeholder="e.g. k.example.com"
            spellCheck={false}
          />
          <label className="text-sm text-muted-foreground">Message</label>
          <textarea
            value={genMessage}
            onChange={(e) => setGenMessage(e.target.value)}
            placeholder="Type or paste your message..."
            className="min-h-[100px] resize-y w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring font-mono"
          />
        </div>
        <div className="flex items-center gap-2 mb-2">
          <span className="text-xs text-muted-foreground">
            {wasmModule ? "Auto-generating as you type" : "Loading Wasm..."}
          </span>
          <span className="flex-1" />
          <Button
            variant="outline"
            size="sm"
            onClick={() => copyText(genDomains.join("\n"))}
            disabled={genDomains.length === 0}
          >
            <Copy className="h-3 w-3" /> Copy All
          </Button>
        </div>
        {genError && (
          <p className="text-xs text-destructive-foreground mb-2">{genError}</p>
        )}
        <div className="rounded-md border p-3 max-h-[300px] overflow-auto bg-background">
          {genDomains.length === 0 ? (
            <div className="text-center text-sm text-muted-foreground py-4 border border-dashed rounded-md">
              No domains yet. Enter zone and message. Mailbox: <code className="text-xs bg-secondary px-1 py-0.5 rounded">{mailbox || "(none)"}</code>
            </div>
          ) : (
            <ol className="list-decimal list-inside font-mono text-xs space-y-0.5">
              {genDomains.map((d, i) => <li key={i}>{d}</li>)}
            </ol>
          )}
        </div>
      </Collapsible>

      {mailbox && validateMailbox(mailbox) && (
        <Collapsible title="Retrieve via DNS" className="mt-4">
          <div className="flex items-center gap-2 py-2">
            <code className="flex-1 text-sm font-mono text-primary break-all">{digCmd}</code>
            <Button variant="ghost" size="icon" onClick={() => copyText(digCmd)} className="shrink-0">
              <Copy className="h-4 w-4" />
            </Button>
          </div>
        </Collapsible>
      )}

      <p className="mt-3 text-xs text-muted-foreground">
        API: GET <code className="text-xs bg-secondary px-1 py-0.5 rounded">/api/mailbox/{"{mailbox}"}/messages</code>, WS{" "}
        <code className="text-xs bg-secondary px-1 py-0.5 rounded">/ws/{"{mailbox}"}</code>. Returns messages in newest-first fashion + live push on new rows.
      </p>
    </div>
  )
}

function MessageCard({
  msg,
  expanded,
  onToggle,
  onCopy,
}: {
  msg: Message
  expanded: boolean
  onToggle: () => void
  onCopy: (text: string) => void
}) {
  const isPing = msg.payload.type === "ping"
  const long = !isPing && isLongContent(msg.payload.content)
  const isExpanded = !long || expanded

  return (
    <Card className={`px-3 pt-2 pb-5 ${isPing ? "border-atomic-tangerine/30" : ""}`}>
      <div className="flex flex-wrap items-baseline gap-2 text-xs font-mono pb-2 border-b border-border">
        {msg.message_hex && (
          <>
            <span className="text-muted-foreground uppercase tracking-wider text-[10px]">ID</span>
            <span className="break-all text-cerulean">{msg.message_hex}</span>
            <span className="text-border">•</span>
          </>
        )}
        <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Received</span>
        <span className="text-willow-green">{formatReceivedAt(msg.received_at)}</span>
        <span className="text-border">•</span>
        <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Type</span>
        <span className={isPing ? "text-atomic-tangerine" : "text-tuscan-sun"}>
          {isPing ? "ping" : msg.payload.type}
        </span>
        {msg.peer_ip && (
          <>
            <span className="text-border">•</span>
            <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Peer</span>
            <span className="font-mono text-seagrass">{msg.peer_ip}</span>
          </>
        )}
        {!isPing && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onCopy(msg.payload.content)}
            className="ml-auto h-6 w-6 p-0 [&_svg]:size-3"
            aria-label="Copy"
          >
            <Copy />
          </Button>
        )}
      </div>

      {!isPing && (
        <div className="mt-4">
          <div className={`relative ${!isExpanded ? "max-h-[200px] overflow-hidden" : ""}`}>
            <pre className="whitespace-pre-wrap break-words text-xs font-mono">{msg.payload.content}</pre>
            {!isExpanded && (
              <div className="absolute bottom-0 left-0 right-0 h-14 bg-gradient-to-t from-card to-transparent pointer-events-none" />
            )}
          </div>
          {long && (
            <div className="mt-2">
              <Button variant="ghost" size="sm" onClick={onToggle} className="h-6 px-2 text-[11px] gap-1 [&_svg]:size-3">
                <ChevronDown className={`transition-transform ${isExpanded ? "rotate-180" : ""}`} />
                {isExpanded ? "Show less" : "Show more"}
              </Button>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
