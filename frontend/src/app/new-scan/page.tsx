"use client";

import { useState } from "react";

export default function NewScanPage() {
    const [tab, setTab] = useState<"single" | "bulk">("single");

    return (
        <main className="min-h-screen bg-[var(--surface-1-gradient)] text-[var(--text-1)]">


            {/* HEADER */}
            <div className="
    bg-[rgba(255,255,255,0.03)]
    backdrop-blur-xl
    border-b border-[var(--border-1)]
    px-6 py-6
    shadow-[0_4px_20px_rgba(0,0,0,0.3)]
">
                <h1 className="text-3xl font-extrabold text-[var(--samsec-aqua)] drop-shadow-[0_0_10px_var(--samsec-glow)]">
                    New Scan
                </h1>
                <p className="text-slate-400 text-sm">Start scanning your targets for vulnerabilities</p>
            </div>

            {/* TABS */}
            <div className="max-w-5xl mx-auto mt-10 px-4">
                <div className="flex gap-10 border-b border-[rgba(255,255,255,0.08)] pb-3">

                    <button
                        className={`
                            pb-3 font-semibold transition
                            ${tab === "single"
                                ? "text-[var(--samsec-blue)] border-b-2 border-[var(--samsec-blue)] drop-shadow-[0_0_8px_var(--samsec-glow)]"
                                : "text-slate-400 hover:text-white"
                            }
                        `}
                        onClick={() => setTab("single")}
                    >
                        Single Target Scan
                    </button>

                    <button
                        className={`
                            pb-3 font-semibold transition
                            ${tab === "bulk"
                                ? "text-[var(--samsec-blue)] border-b-2 border-[var(--samsec-blue)] drop-shadow-[0_0_8px_var(--samsec-glow)]"
                                : "text-slate-400 hover:text-white"
                            }
                        `}
                        onClick={() => setTab("bulk")}
                    >
                        Bulk Scan
                    </button>
                </div>
            </div>

            {/* CONTENT CARD */}
            <div className="max-w-5xl mx-auto mt-8 px-4">
                <div className="
                    bg-[var(--surface-2)]
                    border border-[rgba(255,255,255,0.06)]
                    rounded-xl p-8
                    shadow-[0_0_25px_rgba(0,0,0,0.45)]
                ">
                    {tab === "single" ? <SingleScanForm /> : <BulkScanForm />}
                </div>
            </div>
        </main>
    );
}


/* ----------------------------------------------------
   SINGLE TARGET SCAN FORM
----------------------------------------------------*/
function SingleScanForm() {

  const [targetName, setTargetName] = useState("")
  const [targetUrl, setTargetUrl] = useState("")
  const [groupName, setgroupName] = useState("")

  const startSingleScan = async () => {
  if (!targetUrl) {
    alert("Please enter a target URL")
    return
  }

  try {
    const res = await fetch("http://127.0.0.1:8000/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        target_name: targetName,
        target_url: targetUrl,
        grouo_name: groupName
      })
    })

    const data = await res.json()

    console.log("Response from backend:", data)

    alert("Scan started successfully ✅\nJob ID: " + data.scan_id)

  } catch (err) {
    console.error(err)
    alert("Something went wrong ❌ Check backend")
  }
}

  return (
    <>
      <h2 className="text-2xl font-bold text-[var(--samsec-blue)] drop-shadow-[0_0_6px_var(--samsec-glow)] mb-6">
        Single Target Scan
      </h2>

      {/* INPUT GRID */}
      <div className="grid md:grid-cols-2 gap-6">

        {/* TARGET NAME */}
        <div>
          <label className="block text-sm text-slate-300 mb-2">Target Name</label>
          <input
            placeholder="e.g., Production Website"
            value={targetName}
            onChange={(e) => setTargetName(e.target.value)}
            className="w-full bg-[var(--surface-3)] border rounded-lg px-3 py-2"
          />
        </div>

        {/* TARGET URL */}
        <div>
          <label className="block text-sm text-slate-300 mb-2">Target URL</label>
          <input
            placeholder="https://example.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full bg-[var(--surface-3)] border rounded-lg px-3 py-2"
          />
        </div>

        {/* GROUP */}
        <div>
          <label className="block text-sm text-slate-300 mb-2">Group</label>
          <input
            placeholder="e.g., Production, Staging"
            value={groupName}
            onChange={(e) => setgroupName(e.target.value)}
            className="w-full bg-[var(--surface-3)] border rounded-lg px-3 py-2"
          />
        </div>

      </div>

      {/* BUTTONS */}
      <div className="mt-10 flex gap-4">
        <button
          onClick={startSingleScan}
          className="
              bg-gradient-to-r from-[var(--samsec-blue)] to-[var(--samsec-aqua)]
              hover:opacity-90 transition
              px-6 py-3 rounded-lg font-semibold text-black
          "
        >
          🚀 Start Scan
        </button>

        <button className="
            bg-[#1b2738] hover:bg-[#223042]
            px-6 py-3 rounded-lg font-semibold text-slate-300
        ">
          Cancel
        </button>
      </div>
    </>
  )
}


/* ----------------------------------------------------
   BULK SCAN FORM
----------------------------------------------------*/
function BulkScanForm() {
    return (
        <>
            <h2 className="text-2xl font-bold text-[var(--samsec-blue)] drop-shadow-[0_0_6px_var(--samsec-glow)] mb-2">
                Bulk Scan
            </h2>

            <p className="text-slate-400 mb-6 max-w-2xl">
                Scan multiple targets simultaneously. SamSec can handle up to 1,000 targets in parallel.
            </p>

            <div className="grid md:grid-cols-2 gap-6">

                {/* URL TEXTAREA */}
                <div>
                    <label className="text-sm font-semibold text-slate-300">Paste URL List</label>
                    <textarea
                        rows={10}
                        placeholder={`https://example1.com\nhttps://example2.com\nhttps://example3.com`}
                        className="w-full mt-2 bg-[var(--surface-3)] border border-[rgba(255,255,255,0.06)] rounded-lg px-3 py-2 focus:outline-none focus:border-[var(--samsec-blue)] focus:ring-2 focus:ring-[var(--samsec-blue)]/40"
                    />
                    <p className="text-xs text-slate-500 mt-2">Enter one URL per line (max 1,000)</p>
                </div>

                {/* FILE UPLOAD */}
                <div>
                    <label className="text-sm font-semibold text-slate-300">Upload File</label>
                    <div className="
                        mt-2 p-10 rounded-lg text-center border-2 border-dashed border-[rgba(255,255,255,0.12)]
                        bg-[var(--surface-3)] hover:border-[var(--samsec-blue)] transition
                    ">
                        <p className="text-5xl mb-3">📁</p>
                        <p className="text-slate-300">Click to upload file</p>
                        <p className="text-xs text-slate-500">Supports .txt & .csv</p>
                    </div>

                    <input
                        placeholder="e.g., Bulk Scan 2024"
                        className="w-full bg-[var(--surface-3)] border border-[rgba(255,255,255,0.06)] rounded-lg px-3 py-2 mt-4 focus:outline-none focus:border-[var(--samsec-blue)] focus:ring-2 focus:ring-[var(--samsec-blue)]/40"
                    />
                </div>
            </div>

            {/* BULK OPTIONS */}
            <div className="grid md:grid-cols-3 gap-6 mt-10">
                {[
                    ["Parallel Scans", ["50 (Recommended)", "100", "250", "500", "1000 (Maximum)"]],
                    ["Schedule", ["One-time scan", "Weekly", "Monthly"]],
                    ["Scan Depth", ["Quick Scan", "Standard", "Deep Scan"]],
                ].map(([label, options]) => (
                    <div key={Array.isArray(label) ? label.join("-") : label}>
                        <label className="block text-sm mb-2 text-slate-300">{label}</label>
                        <select className="
                            w-full bg-[var(--surface-3)] border border-[rgba(255,255,255,0.06)]
                            rounded-lg px-3 py-2 focus:outline-none
                            focus:border-[var(--samsec-blue)]
                            focus:ring-2 focus:ring-[var(--samsec-blue)]/40
                        ">
                            {(options as string[]).map((opt) => (
                                <option key={opt}>{opt}</option>
                            ))}
                        </select>
                    </div>
                ))}
            </div>

            {/* BUTTONS */}
            <div className="mt-10 flex gap-4">
                <button className="
                    bg-gradient-to-r from-[var(--samsec-blue)] to-[var(--samsec-aqua)]
                    hover:opacity-90 transition
                    px-6 py-3 rounded-lg font-semibold text-black shadow-[0_0_20px_var(--samsec-glow)]
                ">
                    🚀 Start Bulk Scan
                </button>

                <button className="
                    bg-[#1b2738] hover:bg-[#223042]
                    px-6 py-3 rounded-lg font-semibold text-slate-300
                    border border-[rgba(255,255,255,0.08)]
                ">
                    Cancel
                </button>
            </div>
        </>
    );
}
