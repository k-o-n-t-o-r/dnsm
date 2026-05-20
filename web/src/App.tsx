import { Routes, Route } from "react-router-dom"
import { Splash } from "@/pages/Splash"
import { Inbox } from "@/pages/Inbox"
import { BrowserTest } from "@/pages/BrowserTest"

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Splash />} />
      <Route path="/inbox" element={<Inbox />} />
      <Route path="/inbox/:id" element={<Inbox />} />
      <Route path="/browser-test" element={<BrowserTest />} />
    </Routes>
  )
}
