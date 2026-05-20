import * as React from "react"
import { cn } from "@/lib/utils"
import { ChevronDown } from "lucide-react"

interface CollapsibleProps {
  title: string
  children: React.ReactNode
  defaultOpen?: boolean
  className?: string
}

export function Collapsible({
  title,
  children,
  defaultOpen = false,
  className,
}: CollapsibleProps) {
  const [open, setOpen] = React.useState(defaultOpen)

  return (
    <div className={cn("rounded-md border", className)}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-4 py-3 text-sm font-semibold hover:bg-accent/50 transition-colors cursor-pointer"
      >
        <span>{title}</span>
        <ChevronDown
          className={cn(
            "h-4 w-4 transition-transform",
            open && "rotate-180"
          )}
        />
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  )
}
