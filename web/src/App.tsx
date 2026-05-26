import { Routes, Route } from "react-router-dom"
import { Splash } from "@/pages/Splash"
import { Inbox } from "@/pages/Inbox"
import { BrowserTest } from "@/pages/BrowserTest"

declare const __COMMIT_HASH__: string

export default function App() {
  return (
    <>
      <Routes>
        <Route path="/" element={<Splash />} />
        <Route path="/inbox" element={<Inbox />} />
        <Route path="/inbox/:id" element={<Inbox />} />
        <Route path="/browser-test" element={<BrowserTest />} />
      </Routes>
      <footer className="fixed bottom-2 inset-x-0 text-center text-[10px] text-muted-foreground/50 select-all font-mono">
        {__COMMIT_HASH__}
      </footer>
    </>
  )
}
