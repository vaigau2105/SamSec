"use client"
interface ScanItem {
  scan_id: string
  target_name: string
  target_url: string
  status: string
  scan_date?: string
}

interface Vulnerability {
  name?: string
  severity?: "Critical" | "High" | "Medium" | "Low" | "Info" | string
}

interface ReportData {
  scan_id: string
  target_url: string
  status: string
  subdomains: string[]
  open_ports: any[]
  vulnerabilities: Vulnerability[]
}

import { useEffect, useState } from "react"

export default function ReportsPage() {
  const [scanId, setScanId] = useState("")
  const [reportData, setReportData] = useState<ReportData | null>(null)
  const [allScans, setAllScans] = useState<ScanItem[]>([])

  const [loading, setLoading] = useState(false)

  // ✅ Load all previous scans automatically
  useEffect(() => {
    const loadAllScans = async () => {
      try {
        const res = await fetch("http://127.0.0.1:8000/api/scans")
        const data = await res.json()

        if (data.scans) {
          setAllScans(data.scans)
        }
      } catch (err) {
        console.error("Error fetching scan list:", err)
      }
    }

    loadAllScans()
  }, [])

  // ✅ Fetch report of a scan
const fetchReport = async () => {
  if (!scanId) {
    alert("Please enter Scan ID")
    return
  }

  setLoading(true)

  try {
    const res = await fetch(`http://127.0.0.1:8000/api/report/${scanId}`)
    const data = await res.json()

    if (res.status === 202 || data.status === "running") {
      alert("Scan still running ⏳ Try again after some time")
      setLoading(false)
      return
    }

    if (res.status === 404) {
      alert("No report found ❌")
      setLoading(false)
      return
    }

    // ✅ Safely count severities (since only subfinder works now)
    const vulnerabilities = data.vulnerabilities || []

    const counts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    }

    vulnerabilities.forEach((v: Vulnerability) => {
      if (v?.severity && counts[v.severity] !== undefined) {
        counts[v.severity]++
      }
    })

    {/*setHtml(`
      <h2>Scan ID: ${data.scan_id}</h2>
      <p><b>Target:</b> ${data.target_url}</p>
      <p><b>Status:</b> ${data.status}</p>
      
      <p><b>Subdomains found:</b> ${data.subdomains?.length || 0}</p>

      <p><b>Critical:</b> ${counts.Critical}</p>
      <p><b>High:</b> ${counts.High}</p>
      <p><b>Medium:</b> ${counts.Medium}</p>
      <p><b>Low:</b> ${counts.Low}</p>

      <h3 style="margin-top:20px;">Subdomains</h3>
      <pre>${JSON.stringify(data.subdomains || [], null, 2)}</pre>

      <h3>Open Ports:</h3>
      <pre>${JSON.stringify(data.open_ports || [], null, 2)}</pre>

      <h3>Vulnerabilities:</h3>
      <pre>${JSON.stringify(data.vulnerabilities || [], null, 2)}</pre>
    `)*/}

  } catch (err) {
    console.error(err)
    alert("Backend error ❌")
  }

  setLoading(false)
}


  return (
    <div className="min-h-screen bg-[var(--surface-1-gradient)] text-white p-10">

      <h1 className="text-3xl font-bold mb-6">🔎Report</h1>

      {/* INPUT BAR */}
      <div className="flex gap-4 mb-10">
        <input
          value={scanId}
          onChange={e => setScanId(e.target.value)}
          placeholder="Enter Scan ID here"
          className="p-3 w-[350px] rounded bg-[var(--surface-3)] border border-[rgba(255,255,255,0.08)]"
        />

        <button
          onClick={fetchReport}
          className="px-6 py-3 bg-[var(--samsec-blue)] rounded font-semibold"
        >
          {loading ? "Loading..." : "Get Report"}
        </button>
      </div>

      {/* ✅ CARDS (STYLE B) - AUTO SCANS LIST */}
      {allScans.length > 0 && (
        <>
          <h2 className="text-xl font-semibold mb-4 text-slate-300">
            Previous Scans
          </h2>

          <div className="grid md:grid-cols-2 gap-6">

            {allScans.map((scan) => (
              <div
                key={scan.scan_id}
                className="
                  bg-[var(--surface-2)]
                  p-5
                  rounded-xl
                  border border-[rgba(255,255,255,0.06)]
                  shadow-[0_0_20px_rgba(0,0,0,0.3)]
                  flex
                  justify-between
                  items-start
                "
              >
                <div>
                  <h3 className="font-semibold text-lg mb-1">
                    {scan.target_name}
                  </h3>

                  <p className="text-sm text-slate-400">
                    {scan.target_url}
                  </p>

                  <p className="text-xs text-slate-500 mt-1">
                    Scan ID: {scan.scan_id}
                  </p>

                  <p className="mt-2">
                    Status:{" "}
                    <span
                      className={
                        scan.status === "Completed"
                          ? "text-green-400"
                          : "text-yellow-400"
                      }
                    >
                      {scan.status}
                    </span>
                  </p>
                </div>

                <button
                  onClick={() => {
                    setScanId(scan.scan_id)
                    window.scrollTo({ top: 0, behavior: "smooth" })
                  }}
                  className="
                    bg-[var(--samsec-aqua)]
                    text-black
                    px-4
                    py-2
                    rounded-lg
                    font-semibold
                  "
                >
                  Use ID
                </button>

              </div>
            ))}

          </div>
        </>
      )}

      {/* REPORT OUTPUT */}
      {reportData && (
  <div className="bg-[var(--surface-2)] p-6 rounded-xl mt-12 space-y-4">

    <h2 className="text-xl font-bold">Scan ID: {reportData.scan_id}</h2>
    <p><b>Target:</b> {reportData.target_url}</p>
    <p><b>Status:</b> {reportData.status}</p>

    <p>
      <b>Subdomains found:</b> {reportData.subdomains?.length || 0}
    </p>

    <div>
      <h3 className="font-semibold mt-4 mb-2">Subdomains</h3>
      <ul className="text-sm space-y-1 max-h-40 overflow-y-auto">
        {reportData.subdomains?.map((sub: string, i: number) => (
          <li key={i} className="text-blue-400">{sub}</li>
        ))}
      </ul>
    </div>

    <div>
      <h3 className="font-semibold mt-4 mb-2">Open Ports</h3>
      <pre className="text-xs">
        {JSON.stringify(reportData.open_ports, null, 2)}
      </pre>
    </div>

    <div>
      <h3 className="font-semibold mt-4 mb-2">Vulnerabilities</h3>

      {reportData.vulnerabilities?.length === 0 && (
        <p className="text-green-400">✅ None found</p>
      )}

      {reportData.vulnerabilities?.map((v: any, i: number) => (
        <div
          key={i}
          className="border border-[rgba(255,255,255,0.06)] rounded p-3 mt-2"
        >
          <p><b>Name:</b> {v.name || "Unknown"}</p>
          <p><b>Severity:</b> {v.severity || "Info"}</p>
        </div>
      ))}
    </div>

  </div>
)}
    </div>
  )
}
