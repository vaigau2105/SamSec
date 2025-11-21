"use client"

import { useState } from "react"
import Hero from "@/components/home/Hero"
import Features from "@/components/home/Features"
import HowToUse from "@/components/home/HowToUse"
import About from "@/components/home/About";

export default function Page() {
  const [view, setView] = useState<"home" | "reports">("home")

  return (
    <main className="bg-slate-900 text-white min-h-screen">

      {/* SIMPLE SWITCH BUTTON */}
      <div className="flex justify-center gap-6 py-6 border-b border-gray-800">
        <button 
          onClick={() => setView("home")}
          className={`px-5 py-2 rounded ${view === "home" ? "bg-blue-500" : "bg-gray-700"}`}>
          Home
        </button>

        <button 
          onClick={() => setView("reports")}
          className={`px-5 py-2 rounded ${view === "reports" ? "bg-blue-500" : "bg-gray-700"}`}>
          Reports
        </button>
      </div>

      {view === "home" ? <HomePage /> : <ReportsPage />}

    </main>
  )
}

/* ---------------- HOME ---------------- */
function HomePage() {
  return (
    <>
      <Hero />
      <Features />
      <HowToUse />
      <About />
    </>
  )
}

/* ---------------- REPORTS ---------------- */
function ReportsPage() {
  const [scanId, setScanId] = useState("")
  const [html, setHtml] = useState("")
  const [loading, setLoading] = useState(false)

  const fetchReport = async () => {
    if (!scanId) {
      alert("Please enter Scan ID")
      return
    }

    setLoading(true)

    try {
      const res = await fetch(`http://127.0.0.1:8000/api/report/${scanId}`)
      const data = await res.json()

      if (res.status === 202) {
        alert("Scan still running ⏳")
      }
      else if (res.status === 404) {
        alert("No report found ❌")
      }
      else {
        setHtml(data.html)
      }

    } catch (err) {
      console.error(err)
      alert("Backend error ❌")
    }

    setLoading(false)
  }

  return (
    <div className="p-10">

      <h1 className="text-3xl font-bold mb-6">🔎 SamSec – View Report</h1>

      <div className="flex gap-4 mb-10">
        <input
          value={scanId}
          onChange={e => setScanId(e.target.value)}
          placeholder="Enter Scan ID"
          className="p-3 w-[350px] rounded bg-gray-900 border border-gray-700"
        />

        <button
          onClick={fetchReport}
          className="px-6 py-3 bg-blue-500 rounded font-semibold"
        >
          {loading ? "Loading..." : "Get Report"}
        </button>
      </div>

      {html && (
        <div
          className="bg-gray-900 p-6 rounded-xl"
          dangerouslySetInnerHTML={{ __html: html }}
        />
      )}

    </div>
  )
}
