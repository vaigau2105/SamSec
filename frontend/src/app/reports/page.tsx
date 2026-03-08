"use client"

import { useEffect, useRef, useState, useCallback } from "react"

// ─────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────

interface ScanItem {
  scan_id: string
  target_name: string
  target_url: string
  status: string
  scan_date?: string
  progress?: number
}

interface Vulnerability {
  name: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info" | string
  description?: string
  cve_ids?: string[]
  remediation?: string
  target?: string
  template_id?: string
  tags?: string[]
  references?: string[]
  cvss_score?: number | null
}

interface ReportData {
  scan_id: string
  target_url: string
  status: string
  scan_date?: string
  subdomains: string[]
  open_ports: any[]
  dns_data?: any
  alive_hosts?: string[]
  vulnerabilities: Vulnerability[]
  summary?: Record<string, number>
  critical_count?: number
  high_count?: number
  medium_count?: number
  low_count?: number
  info_count?: number
}

interface LiveStatus {
  status: string
  progress: number
  stage?: string
  summary?: Record<string, number>
  error?: string
}

// ─────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────

const SEV_META: Record<string, { color: string; bg: string; border: string; glow: string; dot: string }> = {
  Critical: {
    color:  "text-red-400",
    bg:     "bg-red-500/10",
    border: "border-red-500/30",
    glow:   "shadow-red-500/20",
    dot:    "bg-red-400",
  },
  High: {
    color:  "text-orange-400",
    bg:     "bg-orange-500/10",
    border: "border-orange-500/30",
    glow:   "shadow-orange-500/20",
    dot:    "bg-orange-400",
  },
  Medium: {
    color:  "text-yellow-400",
    bg:     "bg-yellow-500/10",
    border: "border-yellow-500/30",
    glow:   "shadow-yellow-500/20",
    dot:    "bg-yellow-400",
  },
  Low: {
    color:  "text-blue-400",
    bg:     "bg-blue-500/10",
    border: "border-blue-500/30",
    glow:   "shadow-blue-500/20",
    dot:    "bg-blue-400",
  },
  Info: {
    color:  "text-slate-400",
    bg:     "bg-slate-500/10",
    border: "border-slate-500/30",
    glow:   "shadow-slate-500/10",
    dot:    "bg-slate-400",
  },
}

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
const API = "http://127.0.0.1:8000"

// ─────────────────────────────────────────────────────────
//  Mini SVG Pie Chart (no external library needed)
// ─────────────────────────────────────────────────────────

function PieChart({ data }: { data: { label: string; value: number; color: string }[] }) {
  const total = data.reduce((s, d) => s + d.value, 0)
  if (total === 0) return (
    <div className="w-40 h-40 mx-auto flex items-center justify-center rounded-full border-2 border-dashed border-slate-600">
      <span className="text-slate-500 text-sm">No data</span>
    </div>
  )

  let cumulative = 0
  const slices = data.map(d => {
    const pct  = d.value / total
    const startAngle = cumulative * 2 * Math.PI - Math.PI / 2
    cumulative += pct
    const endAngle = cumulative * 2 * Math.PI - Math.PI / 2

    const r = 80
    const cx = 90
    const cy = 90
    const x1 = cx + r * Math.cos(startAngle)
    const y1 = cy + r * Math.sin(startAngle)
    const x2 = cx + r * Math.cos(endAngle)
    const y2 = cy + r * Math.sin(endAngle)
    const largeArc = pct > 0.5 ? 1 : 0

    const pathD = pct === 1
      ? `M ${cx},${cy} m -${r},0 a ${r},${r} 0 1,0 ${r * 2},0 a ${r},${r} 0 1,0 -${r * 2},0`
      : `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2} Z`

    return { ...d, pathD, pct }
  })

  return (
    <div className="flex flex-col items-center gap-4">
      <svg width="180" height="180" viewBox="0 0 180 180">
        {slices.filter(s => s.value > 0).map(s => (
          <path key={s.label} d={s.pathD} fill={s.color} stroke="#1c2432" strokeWidth="2">
            <title>{s.label}: {s.value}</title>
          </path>
        ))}
        {/* center hole */}
        <circle cx="90" cy="90" r="42" fill="#1c2432" />
        <text x="90" y="86" textAnchor="middle" fill="#f3f6fb" fontSize="22" fontWeight="700">{total}</text>
        <text x="90" y="103" textAnchor="middle" fill="#9ba8b9" fontSize="11">total</text>
      </svg>
      <div className="flex flex-wrap justify-center gap-3">
        {slices.filter(s => s.value > 0).map(s => (
          <div key={s.label} className="flex items-center gap-1.5 text-xs text-slate-300">
            <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: s.color }} />
            {s.label} ({s.value})
          </div>
        ))}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
//  Bar Chart
// ─────────────────────────────────────────────────────────

function BarChart({ counts }: { counts: Record<string, number> }) {
  const maxVal = Math.max(...SEV_ORDER.map(s => counts[s] || 0), 1)
  const COLORS: Record<string, string> = {
    Critical: "#f87171",
    High:     "#fb923c",
    Medium:   "#facc15",
    Low:      "#60a5fa",
    Info:     "#94a3b8",
  }

  return (
    <div className="flex items-end gap-3 h-32 px-2">
      {SEV_ORDER.map(sev => {
        const val  = counts[sev] || 0
        const pct  = (val / maxVal) * 100
        return (
          <div key={sev} className="flex flex-col items-center gap-1 flex-1">
            <span className="text-xs font-bold" style={{ color: COLORS[sev] }}>{val}</span>
            <div
              className="w-full rounded-t-md transition-all duration-700"
              style={{
                height:     `${Math.max(pct, val > 0 ? 8 : 0)}%`,
                background: COLORS[sev],
                boxShadow:  `0 0 12px ${COLORS[sev]}55`,
              }}
            />
            <span className="text-[10px] text-slate-500">{sev.slice(0, 4)}</span>
          </div>
        )
      })}
    </div>
  )
}

// ─────────────────────────────────────────────────────────
//  Progress Bar
// ─────────────────────────────────────────────────────────

function ProgressBar({ pct, stage }: { pct: number; stage?: string }) {
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between text-xs text-slate-400">
        <span>{stage || "Scanning…"}</span>
        <span>{pct}%</span>
      </div>
      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{
            width:      `${pct}%`,
            background: "linear-gradient(90deg, #3b82f6, #38bdf8)",
            boxShadow:  "0 0 10px rgba(56,189,248,0.5)",
          }}
        />
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
//  Vulnerability Card
// ─────────────────────────────────────────────────────────

function VulnCard({ vuln, idx }: { vuln: Vulnerability; idx: number }) {
  const [open, setOpen] = useState(false)
  const meta = SEV_META[vuln.severity] || SEV_META.Info

  return (
    <div
      className={`
        rounded-xl border transition-all duration-200 overflow-hidden
        ${meta.border} ${meta.bg}
        ${open ? `shadow-lg ${meta.glow}` : ""}
      `}
    >
      {/* Header row — always visible */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={() => setOpen(o => !o)}
      >
        {/* Severity dot */}
        <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${meta.dot}`} />

        {/* Name */}
        <span className="flex-1 font-semibold text-sm text-slate-100 truncate">
          {vuln.name}
        </span>

        {/* CVE badges */}
        {vuln.cve_ids && vuln.cve_ids.length > 0 && (
          <div className="flex gap-1 flex-shrink-0">
            {vuln.cve_ids.slice(0, 2).map(cve => (
              <a
                key={cve}
                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-sky-300 hover:text-sky-200 font-mono border border-sky-500/20"
              >
                {cve}
              </a>
            ))}
            {vuln.cve_ids.length > 2 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-400">
                +{vuln.cve_ids.length - 2}
              </span>
            )}
          </div>
        )}

        {/* Severity badge */}
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${meta.color} ${meta.bg} border ${meta.border} flex-shrink-0`}>
          {vuln.severity}
        </span>

        {/* CVSS */}
        {vuln.cvss_score != null && (
          <span className="text-xs text-slate-400 flex-shrink-0">
            CVSS {vuln.cvss_score}
          </span>
        )}

        {/* Expand arrow */}
        <svg
          className={`w-4 h-4 text-slate-500 flex-shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded body */}
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-white/5 pt-3">

          {/* Target */}
          {vuln.target && (
            <div>
              <p className="text-[11px] text-slate-500 uppercase tracking-wider mb-0.5">Affected target</p>
              <p className="text-xs font-mono text-sky-300 break-all">{vuln.target}</p>
            </div>
          )}

          {/* Description */}
          {vuln.description && (
            <div>
              <p className="text-[11px] text-slate-500 uppercase tracking-wider mb-0.5">Description</p>
              <p className="text-xs text-slate-300 leading-relaxed">{vuln.description}</p>
            </div>
          )}

          {/* CVE list with NVD links */}
          {vuln.cve_ids && vuln.cve_ids.length > 0 && (
            <div>
              <p className="text-[11px] text-slate-500 uppercase tracking-wider mb-1">CVE IDs</p>
              <div className="flex flex-wrap gap-2">
                {vuln.cve_ids.map(cve => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono px-2 py-1 rounded-md bg-slate-800 text-sky-300 border border-sky-500/25 hover:border-sky-400/50 transition-colors"
                  >
                    🔗 {cve}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          {vuln.remediation && (
            <div className="rounded-lg bg-emerald-500/8 border border-emerald-500/20 p-3">
              <p className="text-[11px] text-emerald-400 uppercase tracking-wider mb-1 font-semibold">
                ✅ Remediation
              </p>
              <p className="text-xs text-slate-300 leading-relaxed">{vuln.remediation}</p>
            </div>
          )}

          {/* Tags */}
          {vuln.tags && vuln.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {vuln.tags.map(tag => (
                <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">
                  {tag}
                </span>
              ))}
            </div>
          )}

          {/* References */}
          {vuln.references && vuln.references.length > 0 && (
            <div>
              <p className="text-[11px] text-slate-500 uppercase tracking-wider mb-1">References</p>
              <div className="space-y-0.5">
                {vuln.references.slice(0, 3).map(ref => (
                  <a
                    key={ref}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block text-xs text-sky-400 hover:text-sky-300 truncate"
                  >
                    {ref}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Template ID */}
          {vuln.template_id && (
            <p className="text-[10px] text-slate-600 font-mono">template: {vuln.template_id}</p>
          )}
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────
//  Main Page
// ─────────────────────────────────────────────────────────

export default function ReportsPage() {
  const [scanId,      setScanId]      = useState("")
  const [reportData,  setReportData]  = useState<ReportData | null>(null)
  const [allScans,    setAllScans]    = useState<ScanItem[]>([])
  const [liveStatus,  setLiveStatus]  = useState<LiveStatus | null>(null)
  const [loading,     setLoading]     = useState(false)
  const [sevFilter,   setSevFilter]   = useState<string>("All")
  const [search,      setSearch]      = useState("")
  const [activeTab,   setActiveTab]   = useState<"vulns" | "subdomains" | "ports" | "dns">("vulns")

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // ── Load all scans on mount
  useEffect(() => {
    fetchAllScans()
    const refresh = setInterval(fetchAllScans, 8000)
    return () => clearInterval(refresh)
  }, [])

  const fetchAllScans = async () => {
    try {
      const res  = await fetch(`${API}/api/scans`)
      const data = await res.json()
      if (data.scans) setAllScans(data.scans)
    } catch {}
  }

  // ── Poll live status while scan is running
  const startPolling = useCallback((id: string) => {
    if (pollRef.current) clearInterval(pollRef.current)

    pollRef.current = setInterval(async () => {
      try {
        const res  = await fetch(`${API}/api/scan/${id}/status`)
        const data: LiveStatus = await res.json()
        setLiveStatus(data)

        if (data.status === "Completed" || data.status === "Failed") {
          clearInterval(pollRef.current!)
          pollRef.current = null
          if (data.status === "Completed") {
            // Fetch the full report now
            const rr  = await fetch(`${API}/api/report/${id}`)
            const rd  = await rr.json()
            setReportData(rd)
          }
        }
      } catch {}
    }, 2000)
  }, [])

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  // ── Fetch report
  const fetchReport = async () => {
    if (!scanId.trim()) return
    setLoading(true)
    setReportData(null)
    setLiveStatus(null)

    try {
      // First check live status
      const statusRes  = await fetch(`${API}/api/scan/${scanId}/status`)
      const statusData: LiveStatus = await statusRes.json()
      setLiveStatus(statusData)

      if (statusData.status === "Running" || statusData.status === "Queued") {
        // Start polling — will auto-load report when done
        startPolling(scanId)
        setLoading(false)
        return
      }

      if (statusData.status === "Completed") {
        const res  = await fetch(`${API}/api/report/${scanId}`)
        const data = await res.json()

        if (data.status === "running") {
          startPolling(scanId)
          setLoading(false)
          return
        }

        setReportData(data)
      }

      if (statusData.status === "Failed") {
        // show error state
      }

    } catch {
      // Fallback: direct report fetch
      try {
        const res  = await fetch(`${API}/api/report/${scanId}`)
        if (res.status === 404) { setLoading(false); return }
        const data = await res.json()
        if (data.status === "running") { startPolling(scanId); setLoading(false); return }
        setReportData(data)
      } catch {}
    }

    setLoading(false)
  }

  // ── Derived values
  const counts: Record<string, number> = {
    Critical: reportData?.critical_count ?? reportData?.summary?.Critical ?? 0,
    High:     reportData?.high_count     ?? reportData?.summary?.High     ?? 0,
    Medium:   reportData?.medium_count   ?? reportData?.summary?.Medium   ?? 0,
    Low:      reportData?.low_count      ?? reportData?.summary?.Low      ?? 0,
    Info:     reportData?.info_count     ?? reportData?.summary?.Info     ?? 0,
  }

  const pieData = SEV_ORDER
    .filter(s => counts[s] > 0)
    .map(s => ({
      label: s,
      value: counts[s],
      color: { Critical: "#f87171", High: "#fb923c", Medium: "#facc15", Low: "#60a5fa", Info: "#94a3b8" }[s]!,
    }))

  const filteredVulns = (reportData?.vulnerabilities ?? []).filter(v => {
    const matchSev    = sevFilter === "All" || v.severity === sevFilter
    const matchSearch = !search || [v.name, v.description, ...(v.cve_ids ?? [])].join(" ").toLowerCase().includes(search.toLowerCase())
    return matchSev && matchSearch
  })

  const isScanning = liveStatus?.status === "Running" || liveStatus?.status === "Queued"

  // ────────────────────────────────────────────
  //  Render
  // ────────────────────────────────────────────
  return (
    <div className="min-h-screen text-white" style={{ background: "var(--surface-1-gradient)" }}>

      <div className="max-w-7xl mx-auto px-4 py-10 space-y-8">

        {/* ── PAGE HEADER ── */}
        <div>
          <h1 className="text-3xl font-bold text-white">Scan Reports</h1>
          <p className="text-slate-400 mt-1 text-sm">View interactive vulnerability reports with live scan tracking</p>
        </div>

        {/* ── SEARCH BAR ── */}
        <div className="flex gap-3">
          <input
            value={scanId}
            onChange={e => setScanId(e.target.value)}
            onKeyDown={e => e.key === "Enter" && fetchReport()}
            placeholder="Enter Scan ID…"
            className="flex-1 max-w-sm px-4 py-2.5 rounded-lg text-sm bg-[#293448] border border-white/8 text-white placeholder-slate-500 focus:outline-none focus:border-sky-500/50"
          />
          <button
            onClick={fetchReport}
            disabled={loading || !scanId.trim()}
            className="px-5 py-2.5 rounded-lg text-sm font-semibold bg-gradient-to-r from-blue-600 to-sky-500 text-white hover:opacity-90 disabled:opacity-40 transition-opacity"
          >
            {loading ? "Loading…" : "Load Report"}
          </button>
        </div>

        {/* ── LIVE SCAN STATUS ── */}
        {isScanning && liveStatus && (
          <div className="rounded-xl border border-sky-500/25 bg-sky-500/5 p-5 space-y-3">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-sky-400 animate-pulse" />
              <span className="text-sm font-semibold text-sky-300">Scan in progress — {liveStatus.status}</span>
            </div>
            <ProgressBar pct={liveStatus.progress} stage={liveStatus.stage} />
          </div>
        )}

        {/* ── FAILED STATE ── */}
        {liveStatus?.status === "Failed" && (
          <div className="rounded-xl border border-red-500/25 bg-red-500/5 p-5 text-sm text-red-400">
            ❌ Scan failed: {liveStatus.error || "Unknown error"}
          </div>
        )}

        {/* ── REPORT BODY ── */}
        {reportData && (
          <div className="space-y-6">

            {/* Meta row */}
            <div className="rounded-xl bg-[#232d3f] border border-white/6 p-5 flex flex-wrap gap-6 items-start">
              <div>
                <p className="text-[11px] text-slate-500 uppercase tracking-wider">Target</p>
                <a href={reportData.target_url} target="_blank" rel="noopener noreferrer"
                   className="text-sky-400 hover:text-sky-300 font-mono text-sm break-all">
                  {reportData.target_url}
                </a>
              </div>
              <div>
                <p className="text-[11px] text-slate-500 uppercase tracking-wider">Scan ID</p>
                <p className="text-white font-mono text-sm">{reportData.scan_id}</p>
              </div>
              <div>
                <p className="text-[11px] text-slate-500 uppercase tracking-wider">Date</p>
                <p className="text-slate-300 text-sm">{reportData.scan_date ? new Date(reportData.scan_date).toLocaleString() : "—"}</p>
              </div>
              <div>
                <p className="text-[11px] text-slate-500 uppercase tracking-wider">Status</p>
                <span className={`text-sm font-semibold ${reportData.status === "Completed" ? "text-emerald-400" : "text-yellow-400"}`}>
                  {reportData.status}
                </span>
              </div>
            </div>

            {/* ── SEVERITY SUMMARY CARDS ── */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {SEV_ORDER.map(sev => {
                const meta = SEV_META[sev]
                const val  = counts[sev]
                return (
                  <button
                    key={sev}
                    onClick={() => setSevFilter(sevFilter === sev ? "All" : sev)}
                    className={`
                      rounded-xl border p-4 text-center transition-all duration-200
                      ${meta.bg} ${meta.border}
                      ${sevFilter === sev ? `shadow-lg ${meta.glow} scale-[1.03]` : "hover:scale-[1.02]"}
                    `}
                  >
                    <p className={`text-2xl font-bold ${meta.color}`}>{val}</p>
                    <p className="text-xs text-slate-400 mt-0.5">{sev}</p>
                  </button>
                )
              })}
            </div>

            {/* ── CHARTS ROW ── */}
            <div className="grid md:grid-cols-2 gap-6">
              <div className="rounded-xl bg-[#232d3f] border border-white/6 p-6">
                <h3 className="text-sm font-semibold text-slate-300 mb-4">Severity Distribution</h3>
                <PieChart data={pieData} />
              </div>
              <div className="rounded-xl bg-[#232d3f] border border-white/6 p-6">
                <h3 className="text-sm font-semibold text-slate-300 mb-4">Findings by Severity</h3>
                <BarChart counts={counts} />
              </div>
            </div>

            {/* ── TABS ── */}
            <div className="border-b border-white/8 flex gap-6">
              {([
                ["vulns",      `Vulnerabilities (${reportData.vulnerabilities.length})`],
                ["subdomains", `Subdomains (${reportData.subdomains?.length ?? 0})`],
                ["ports",      `Open Ports (${reportData.open_ports?.length ?? 0})`],
                ["dns",        "DNS Data"],
              ] as const).map(([tab, label]) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`pb-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                    activeTab === tab
                      ? "border-sky-400 text-sky-300"
                      : "border-transparent text-slate-500 hover:text-slate-300"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* ── TAB: VULNERABILITIES ── */}
            {activeTab === "vulns" && (
              <div className="space-y-4">

                {/* Filter + search bar */}
                <div className="flex flex-wrap gap-2 items-center">
                  {["All", ...SEV_ORDER].map(sev => (
                    <button
                      key={sev}
                      onClick={() => setSevFilter(sev)}
                      className={`px-3 py-1 rounded-full text-xs font-semibold border transition-all ${
                        sevFilter === sev
                          ? sev === "All"
                            ? "bg-slate-600 border-slate-500 text-white"
                            : `${SEV_META[sev]?.bg} ${SEV_META[sev]?.border} ${SEV_META[sev]?.color}`
                          : "bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500"
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                  <input
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    placeholder="Search vulnerabilities, CVE…"
                    className="ml-auto px-3 py-1.5 rounded-lg text-xs bg-[#293448] border border-white/8 text-white placeholder-slate-500 focus:outline-none focus:border-sky-500/50 min-w-[220px]"
                  />
                </div>

                {/* Vuln count */}
                <p className="text-xs text-slate-500">
                  Showing {filteredVulns.length} of {reportData.vulnerabilities.length} findings
                </p>

                {/* Cards */}
                {filteredVulns.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-600 p-10 text-center">
                    <p className="text-slate-500">
                      {reportData.vulnerabilities.length === 0
                        ? "✅ No vulnerabilities found"
                        : "No results match current filters"}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {filteredVulns.map((v, i) => (
                      <VulnCard key={i} vuln={v} idx={i} />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB: SUBDOMAINS ── */}
            {activeTab === "subdomains" && (
              <div className="rounded-xl bg-[#232d3f] border border-white/6 p-5">
                {(!reportData.subdomains || reportData.subdomains.length === 0) ? (
                  <p className="text-slate-500 text-sm">No subdomains discovered</p>
                ) : (
                  <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-96 overflow-y-auto">
                    {reportData.subdomains.map((sub, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm font-mono text-sky-300 bg-sky-500/5 border border-sky-500/15 rounded-lg px-3 py-1.5">
                        <span className="text-sky-500/60">•</span>
                        <a href={`https://${sub}`} target="_blank" rel="noopener noreferrer" className="hover:text-sky-200 truncate">
                          {sub}
                        </a>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB: OPEN PORTS ── */}
            {activeTab === "ports" && (
              <div className="rounded-xl bg-[#232d3f] border border-white/6 p-5">
                {(!reportData.open_ports || reportData.open_ports.length === 0) ? (
                  <p className="text-slate-500 text-sm">No open ports found</p>
                ) : (
                  <div className="space-y-2">
                    {reportData.open_ports.map((port: any, i: number) => (
                      <div key={i} className="flex items-center gap-3 text-sm bg-[#293448] rounded-lg px-4 py-2 border border-white/5">
                        <span className="font-mono text-sky-400 font-bold w-16">:{port.port ?? port}</span>
                        {port.host && <span className="text-slate-400">{port.host}</span>}
                        {port.service && <span className="text-slate-500 text-xs">{port.service}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── TAB: DNS ── */}
            {activeTab === "dns" && (
              <div className="rounded-xl bg-[#232d3f] border border-white/6 p-5">
                {!reportData.dns_data || Object.keys(reportData.dns_data).length === 0 ? (
                  <p className="text-slate-500 text-sm">No DNS data available</p>
                ) : (
                  <pre className="text-xs text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-96">
                    {JSON.stringify(reportData.dns_data, null, 2)}
                  </pre>
                )}
              </div>
            )}

          </div>
        )}

        {/* ── PREVIOUS SCANS LIST ── */}
        {allScans.length > 0 && (
          <div className="space-y-3">
            <h2 className="text-lg font-semibold text-slate-200">All Scans</h2>
            <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-3">
              {allScans.map(scan => {
                const isRunning = scan.status === "Running" || scan.status === "Queued"
                return (
                  <div
                    key={scan.scan_id}
                    className="rounded-xl bg-[#232d3f] border border-white/6 p-4 flex flex-col gap-3 hover:border-sky-500/25 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="font-semibold text-sm text-slate-100 truncate">{scan.target_name}</p>
                        <p className="text-xs text-slate-500 font-mono truncate">{scan.target_url}</p>
                      </div>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full flex-shrink-0 ${
                        scan.status === "Completed" ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/25" :
                        scan.status === "Failed"    ? "bg-red-500/15 text-red-400 border border-red-500/25" :
                                                      "bg-sky-500/15 text-sky-400 border border-sky-500/25"
                      }`}>
                        {scan.status}
                      </span>
                    </div>

                    {isRunning && (
                      <ProgressBar pct={scan.progress ?? 0} stage="Scanning…" />
                    )}

                    <div className="flex items-center justify-between">
                      <p className="text-[11px] text-slate-600 font-mono">{scan.scan_id}</p>
                      <button
                        onClick={() => {
                          setScanId(scan.scan_id)
                          window.scrollTo({ top: 0, behavior: "smooth" })
                          setTimeout(() => {
                            setScanId(scan.scan_id)
                            fetchReport()
                          }, 100)
                        }}
                        className="text-xs px-3 py-1 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20 hover:bg-sky-500/20 transition-colors"
                      >
                        View →
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
