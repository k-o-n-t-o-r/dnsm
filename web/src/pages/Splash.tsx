import { Link } from "react-router-dom"
import { Card } from "@/components/ui/card"
import { Inbox, FlaskConical } from "lucide-react"

function GithubIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" className={className}>
      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
    </svg>
  )
}

const asciiLogo = `\
██████╗ ███╗   ██╗███████╗███╗   ███╗
██╔══██╗████╗  ██║██╔════╝████╗ ████║
██║  ██║██╔██╗ ██║███████╗██╔████╔██║
██║  ██║██║╚██╗██║╚════██║██║╚██╔╝██║
██████╔╝██║ ╚████║███████║██║ ╚═╝ ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝`

export function Splash() {
  return (
    <div className="min-h-svh grid place-items-center p-5">
      <div className="max-w-[900px] w-full flex flex-col items-center gap-8">
        <div className="inline-block p-5 px-6">
          <pre
            className="text-[8px] sm:text-[11px] leading-[1] select-all font-mono"
            style={{
              color: "var(--color-seagrass)",
              fontVariantLigatures: "none",
              fontFeatureSettings: '"liga" 0, "calt" 0',
              textShadow: "0.06em 0 currentColor, 0 0 4px color-mix(in srgb, var(--color-seagrass) 10%, transparent)",
            }}
          >
            {asciiLogo}
          </pre>
        </div>

        <p className="text-muted-foreground text-center text-sm">
          A small but comprehensive toolkit for covert data exfiltration using DNS.
        </p>

        <nav className="grid grid-cols-1 sm:grid-cols-3 gap-4 w-full max-w-[900px]">
          <Link to="/inbox">
            <Card className="flex items-center gap-3 p-3 hover:border-primary/50 hover:-translate-y-0.5 transition-all cursor-pointer h-full">
              <Inbox className="h-8 w-8 shrink-0 text-muted-foreground" />
              <h3 className="font-semibold">Inbox</h3>
            </Card>
          </Link>

          <Link to="/browser-test">
            <Card className="flex items-center gap-3 p-3 hover:border-primary/50 hover:-translate-y-0.5 transition-all cursor-pointer h-full">
              <FlaskConical className="h-8 w-8 shrink-0 text-muted-foreground" />
              <h3 className="font-semibold">Browser Test</h3>
            </Card>
          </Link>

          <a href="https://github.com/k-o-n-t-o-r/dnsm" target="_blank" rel="noopener noreferrer">
            <Card className="flex items-center gap-3 p-3 hover:border-primary/50 hover:-translate-y-0.5 transition-all cursor-pointer h-full">
              <GithubIcon className="h-8 w-8 shrink-0 text-muted-foreground" />
              <h3 className="font-semibold">GitHub</h3>
            </Card>
          </a>
        </nav>

        <footer className="mt-4 flex flex-wrap items-center justify-center gap-2">
          <a href="https://crates.io/crates/dnsm" target="_blank" rel="noopener noreferrer" className="opacity-80 hover:opacity-100 transition-opacity">
            <img src="https://img.shields.io/crates/v/dnsm.svg" alt="crates.io" />
          </a>
          <a href="https://pypi.org/project/dnsm/" target="_blank" rel="noopener noreferrer" className="opacity-80 hover:opacity-100 transition-opacity">
            <img src="https://img.shields.io/pypi/v/dnsm" alt="pypi" />
          </a>
        </footer>
      </div>
    </div>
  )
}
