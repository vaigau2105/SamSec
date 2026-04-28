"use client"

import { useEffect, useRef, useState, useCallback } from "react"

// ─────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────

interface Technique {
  technique_id:   string
  technique_name: string
  tactic:         string
  confidence:     "high" | "medium" | "low"
  match_reason:   string
}

interface Finding {
  name:             string
  severity:         string
  mitre_techniques: Technique[]
}

interface TacticSummary {
  tactic:          string
  technique_count: number
  technique_ids:   string[]
}

interface TechniqueHit {
  technique_id:   string
  technique_name: string
  tactic:         string
  count:          number
  max_score:      number
  max_severity:   string
  findings:       string[]
  confidence:     string
}

interface Coverage {
  total_techniques_covered: number
  total_tactics_covered:    number
  total_tactics:            number
  coverage_pct:             number
  tactic_summary:           TacticSummary[]
  technique_hits:           TechniqueHit[]
}

interface MitreReport {
  scan_id:         string
  target_url:      string
  scan_date:       string
  mitre:           { coverage: Coverage; has_mitre: boolean }
  vulnerabilities: Finding[]
}

interface ScanItem {
  scan_id:     string
  target_name: string
  target_url:  string
  status:      string
}

// ─────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────

const API = "http://127.0.0.1:8000"

const TACTIC_ORDER = [
  "reconnaissance", "resource-development", "initial-access",
  "execution", "persistence", "privilege-escalation",
  "defense-evasion", "credential-access", "discovery",
  "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact",
]

const TACTIC_META: Record<string, { label: string; icon: string; color: string; bg: string; border: string }> = {
  "reconnaissance":       { label: "Reconnaissance",        icon: "🔍", color: "text-violet-400",  bg: "bg-violet-500/10",  border: "border-violet-500/30" },
  "resource-development": { label: "Resource Dev",          icon: "🏗️", color: "text-purple-400",  bg: "bg-purple-500/10",  border: "border-purple-500/30" },
  "initial-access":       { label: "Initial Access",        icon: "🚪", color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/30" },
  "execution":            { label: "Execution",             icon: "⚡", color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/30" },
  "persistence":          { label: "Persistence",           icon: "📌", color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/30" },
  "privilege-escalation": { label: "Privilege Escalation",  icon: "⬆️", color: "text-amber-400",   bg: "bg-amber-500/10",   border: "border-amber-500/30" },
  "defense-evasion":      { label: "Defense Evasion",       icon: "🥷", color: "text-lime-400",    bg: "bg-lime-500/10",    border: "border-lime-500/30" },
  "credential-access":    { label: "Credential Access",     icon: "🔑", color: "text-green-400",   bg: "bg-green-500/10",   border: "border-green-500/30" },
  "discovery":            { label: "Discovery",             icon: "🗺️", color: "text-teal-400",    bg: "bg-teal-500/10",    border: "border-teal-500/30" },
  "lateral-movement":     { label: "Lateral Movement",      icon: "↔️", color: "text-cyan-400",    bg: "bg-cyan-500/10",    border: "border-cyan-500/30" },
  "collection":           { label: "Collection",            icon: "📦", color: "text-sky-400",     bg: "bg-sky-500/10",     border: "border-sky-500/30" },
  "command-and-control":  { label: "C2",                    icon: "📡", color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/30" },
  "exfiltration":         { label: "Exfiltration",          icon: "📤", color: "text-indigo-400",  bg: "bg-indigo-500/10",  border: "border-indigo-500/30" },
  "impact":               { label: "Impact",                icon: "💥", color: "text-rose-400",    bg: "bg-rose-500/10",    border: "border-rose-500/30" },
}

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-blue-400",
  info:     "text-slate-400",
}

const CONF_BADGE: Record<string, string> = {
  high:   "bg-emerald-500/15 text-emerald-400 border-emerald-500/25",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25",
  low:    "bg-slate-500/15 text-slate-400 border-slate-500/25",
}

// ─────────────────────────────────────────────────────────────
//  Stat Card
// ─────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color = "text-sky-400" }: {
  label: string; value: string | number; sub?: string; color?: string
}) {
  return (
    <div className="rounded-xl bg-[#232d3f] border border-white/6 p-5 flex flex-col gap-1">
      <p className="text-[11px] text-slate-500 uppercase tracking-widest">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-slate-500">{sub}</p>}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Tactic Kill-Chain Strip
// ─────────────────────────────────────────────────────────────

function KillChainStrip({ tacticSummary, onSelect, selected }: {
  tacticSummary: TacticSummary[]
  onSelect: (t: string | null) => void
  selected: string | null
}) {
  const byTactic = Object.fromEntries(tacticSummary.map(t => [t.tactic, t]))

  return (
    <div className="rounded-xl bg-[#1a2236] border border-white/6 p-4 overflow-x-auto">
      <p className="text-xs text-slate-500 uppercase tracking-widest mb-3 px-1">ATT&CK Kill Chain</p>
      <div className="flex gap-2 min-w-max">
        {TACTIC_ORDER.map((tactic, i) => {
          const meta    = TACTIC_META[tactic] || { label: tactic, icon: "•", color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/30" }
          const summary = byTactic[tactic]
          const count   = summary?.technique_count ?? 0
          const active  = count > 0
          const sel     = selected === tactic

          return (
            <div key={tactic} className="flex items-center gap-0">
              <button
                onClick={() => onSelect(sel ? null : tactic)}
                className={`
                  flex flex-col items-center gap-1.5 px-3 py-3 rounded-lg border transition-all duration-200 min-w-[90px]
                  ${active
                    ? `${meta.bg} ${meta.border} cursor-pointer hover:scale-105 ${sel ? "scale-105 ring-2 ring-offset-1 ring-offset-[#1a2236] ring-current" : ""}`
                    : "bg-slate-800/30 border-slate-700/30 opacity-40 cursor-default"
                  }
                `}
              >
                <span className="text-lg">{meta.icon}</span>
                <span className={`text-[10px] font-semibold text-center leading-tight ${active ? meta.color : "text-slate-600"}`}>
                  {meta.label}
                </span>
                {active && (
                  <span className={`text-lg font-bold ${meta.color}`}>{count}</span>
                )}
              </button>
              {i < TACTIC_ORDER.length - 1 && (
                <span className="text-slate-700 text-sm px-0.5">›</span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Technique Hit Card
// ─────────────────────────────────────────────────────────────

function TechniqueCard({ hit }: { hit: TechniqueHit }) {
  const [open, setOpen] = useState(false)
  const tactic = hit.tactic
  const meta   = TACTIC_META[tactic] || { label: tactic, icon: "•", color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/30" }
  const sevColor = SEV_COLOR[hit.max_severity] || "text-slate-400"

  return (
    <div className={`rounded-xl border transition-all duration-200 ${meta.border} ${meta.bg} ${open ? "shadow-lg" : ""}`}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={() => setOpen(o => !o)}
      >
        <span className="text-sm font-mono font-bold text-slate-300 bg-slate-800/60 px-2 py-0.5 rounded flex-shrink-0">
          {hit.technique_id}
        </span>
        <span className="flex-1 font-semibold text-sm text-slate-100 truncate">
          {hit.technique_name}
        </span>
        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${meta.bg} ${meta.color} border ${meta.border} flex-shrink-0`}>
          {meta.label}
        </span>
        <span className={`text-xs font-bold flex-shrink-0 ${sevColor}`}>
          {hit.max_severity.toUpperCase()}
        </span>
        <span className="text-xs text-slate-500 flex-shrink-0">{hit.count} finding{hit.count !== 1 ? "s" : ""}</span>
        <svg className={`w-4 h-4 text-slate-500 flex-shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-white/5 pt-3">
          <div>
            <p className="text-[11px] text-slate-500 uppercase tracking-wider mb-1">Related Findings</p>
            <div className="flex flex-wrap gap-1.5">
              {[...new Set(hit.findings)].map((f, i) => (
                <span key={i} className="text-xs px-2 py-0.5 rounded bg-slate-800/70 text-slate-300 border border-slate-700/40">
                  {f}
                </span>
              ))}
            </div>
          </div>
          <div className="flex gap-4">
            <a
              href={`https://attack.mitre.org/techniques/${hit.technique_id.replace(".", "/")}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-sky-400 hover:text-sky-300 underline"
            >
              View on MITRE ATT&CK →
            </a>
          </div>
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Finding Row with ATT&CK badges
// ─────────────────────────────────────────────────────────────

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  const sevColor = SEV_COLOR[finding.severity?.toLowerCase()] || "text-slate-400"

  return (
    <div className="rounded-lg bg-[#232d3f] border border-white/5 overflow-hidden">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/2 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <span className={`text-xs font-bold w-16 flex-shrink-0 ${sevColor}`}>
          {finding.severity}
        </span>
        <span className="flex-1 text-sm text-slate-200 truncate">{finding.name}</span>
        <div className="flex gap-1 flex-shrink-0 flex-wrap max-w-[300px]">
          {finding.mitre_techniques.slice(0, 3).map(t => {
            const meta = TACTIC_META[t.tactic]
            return (
              <span key={t.technique_id}
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${meta?.border || "border-slate-700"} ${meta?.color || "text-slate-400"} bg-transparent`}>
                {t.technique_id}
              </span>
            )
          })}
          {finding.mitre_techniques.length > 3 && (
            <span className="text-[10px] text-slate-500">+{finding.mitre_techniques.length - 3}</span>
          )}
        </div>
        <svg className={`w-4 h-4 text-slate-600 flex-shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && finding.mitre_techniques.length > 0 && (
        <div className="px-4 pb-3 pt-1 border-t border-white/5 space-y-2">
          {finding.mitre_techniques.map((t, i) => {
            const meta = TACTIC_META[t.tactic]
            return (
              <div key={i} className={`flex items-center gap-3 rounded-lg px-3 py-2 ${meta?.bg || "bg-slate-800/30"} border ${meta?.border || "border-slate-700/30"}`}>
                <span className="font-mono text-xs font-bold text-slate-200">{t.technique_id}</span>
                <span className={`text-xs ${meta?.color || "text-slate-400"} flex-1`}>{t.technique_name}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded border ${CONF_BADGE[t.confidence] || CONF_BADGE.low}`}>
                  {t.confidence}
                </span>
                <span className="text-[10px] text-slate-500">{t.match_reason}</span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Main Page
// ─────────────────────────────────────────────────────────────

export default function MitrePage() {
  const [scanId,      setScanId]      = useState("")
  const [report,      setReport]      = useState<MitreReport | null>(null)
  const [allScans,    setAllScans]    = useState<ScanItem[]>([])
  const [loading,     setLoading]     = useState(false)
  const [error,       setError]       = useState("")
  const [activeTab,   setActiveTab]   = useState<"overview" | "techniques" | "findings">("overview")
  const [tacticFilter,setTacticFilter]= useState<string | null>(null)
  const [searchQ,     setSearchQ]     = useState("")
  const [refreshing,  setRefreshing]  = useState(false)

  // Load scans list
  useEffect(() => {
    fetch(`${API}/api/scans`)
      .then(r => r.json())
      .then(d => { if (d.scans) setAllScans(d.scans.filter((s: ScanItem) => s.status === "Completed")) })
      .catch(() => {})
  }, [])

  const fetchReport = useCallback(async (id?: string) => {
    const sid = id || scanId.trim()
    if (!sid) return
    setLoading(true)
    setError("")
    setReport(null)
    try {
      const res  = await fetch(`${API}/api/mitre/report/${sid}`)
      if (!res.ok) {
        const msg = await res.text()
        setError(res.status === 404 ? "No MITRE data found. Run a scan first." : `Error: ${msg}`)
        return
      }
      const data = await res.json()
      setReport(data)
      setScanId(sid)
    } catch {
      setError("Could not connect to backend.")
    } finally {
      setLoading(false)
    }
  }, [scanId])

  const downloadLayer = async () => {
    if (!report) return
    const res  = await fetch(`${API}/api/mitre/navigator/${report.scan_id}`)
    const blob = await res.blob()
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement("a")
    a.href     = url
    a.download = `samsec_${report.scan_id}_mitre.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const refreshCache = async () => {
    setRefreshing(true)
    try {
      await fetch(`${API}/api/mitre/refresh-cache`, { method: "POST" })
    } finally {
      setRefreshing(false)
    }
  }

  // ── Derived data ──
  const coverage       = report?.mitre?.coverage
  const tacticSummary  = coverage?.tactic_summary || []
  const techniqueHits  = coverage?.technique_hits || []
  const findings       = report?.vulnerabilities  || []

  const filteredHits = techniqueHits
    .filter(h => !tacticFilter || h.tactic === tacticFilter)
    .filter(h => !searchQ || `${h.technique_id} ${h.technique_name}`.toLowerCase().includes(searchQ.toLowerCase()))
    .sort((a, b) => b.max_score - a.max_score)

  const filteredFindings = findings
    .filter(f => !tacticFilter || f.mitre_techniques.some(t => t.tactic === tacticFilter))
    .filter(f => !searchQ || f.name.toLowerCase().includes(searchQ.toLowerCase()))

  // ─────────────────────────────────────────────────────────
  //  Render
  // ─────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen text-white" style={{ background: "var(--surface-1-gradient)" }}>
      <div className="max-w-7xl mx-auto px-4 py-10 space-y-8">

        {/* ── PAGE HEADER ── */}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <span className="text-2xl">🛡️</span> MITRE ATT&CK Analysis
            </h1>
            <p className="text-slate-400 mt-1 text-sm">
              Map scan findings to ATT&CK techniques, visualize kill-chain coverage, and export Navigator layers
            </p>
          </div>
          <button
            onClick={refreshCache}
            disabled={refreshing}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-700/60 text-slate-300 border border-slate-600/40 hover:bg-slate-700 disabled:opacity-50 transition-colors"
          >
            {refreshing ? "Refreshing ATT&CK data…" : "🔄 Refresh ATT&CK Cache"}
          </button>
        </div>

        {/* ── SCAN SELECTOR ── */}
        <div className="flex gap-3 flex-wrap">
          <input
            value={scanId}
            onChange={e => setScanId(e.target.value)}
            onKeyDown={e => e.key === "Enter" && fetchReport()}
            placeholder="Enter Scan ID…"
            className="flex-1 max-w-sm px-4 py-2.5 rounded-lg text-sm bg-[#293448] border border-white/8 text-white placeholder-slate-500 focus:outline-none focus:border-sky-500/50"
          />
          <button
            onClick={() => fetchReport()}
            disabled={loading || !scanId.trim()}
            className="px-5 py-2.5 rounded-lg text-sm font-semibold bg-gradient-to-r from-blue-600 to-sky-500 text-white hover:opacity-90 disabled:opacity-40 transition-opacity"
          >
            {loading ? "Loading…" : "Analyse"}
          </button>
        </div>

        {/* ── COMPLETED SCANS QUICK SELECT ── */}
        {allScans.length > 0 && !report && (
          <div className="space-y-2">
            <p className="text-xs text-slate-500 uppercase tracking-widest">Quick Select — Completed Scans</p>
            <div className="flex flex-wrap gap-2">
              {allScans.map(scan => (
                <button
                  key={scan.scan_id}
                  onClick={() => { setScanId(scan.scan_id); fetchReport(scan.scan_id) }}
                  className="px-3 py-1.5 rounded-lg text-xs bg-[#232d3f] border border-white/6 text-slate-300 hover:border-sky-500/30 hover:text-sky-300 transition-colors"
                >
                  {scan.target_name || scan.target_url}
                  <span className="ml-2 text-slate-600 font-mono">{scan.scan_id}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* ── ERROR ── */}
        {error && (
          <div className="rounded-xl border border-red-500/25 bg-red-500/5 p-4 text-sm text-red-400">
            ❌ {error}
          </div>
        )}

        {/* ── REPORT BODY ── */}
        {report && coverage && (
          <div className="space-y-6">

            {/* Meta row */}
            <div className="rounded-xl bg-[#232d3f] border border-white/6 p-4 flex flex-wrap gap-6 items-center">
              <div>
                <p className="text-[11px] text-slate-500 uppercase tracking-wider">Target</p>
                <p className="text-sky-400 font-mono text-sm">{report.target_url}</p>
              </div>
              <div>
                <p className="text-[11px] text-slate-500 uppercase tracking-wider">Scan ID</p>
                <p className="text-white font-mono text-sm">{report.scan_id}</p>
              </div>
              <div>
                <p className="text-[11px] text-slate-500 uppercase tracking-wider">Date</p>
                <p className="text-slate-300 text-sm">{report.scan_date ? new Date(report.scan_date).toLocaleString() : "—"}</p>
              </div>
              <div className="ml-auto">
                <button
                  onClick={downloadLayer}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/25 hover:bg-emerald-500/25 transition-colors"
                >
                  ⬇️ Download Navigator Layer
                </button>
              </div>
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <StatCard
                label="Techniques Detected"
                value={coverage.total_techniques_covered}
                color="text-sky-400"
              />
              <StatCard
                label="Tactics Covered"
                value={`${coverage.total_tactics_covered} / ${coverage.total_tactics}`}
                color="text-violet-400"
              />
              <StatCard
                label="Findings Mapped"
                value={findings.length}
                color="text-emerald-400"
              />
              <StatCard
                label="ATT&CK Version"
                value="v14"
                sub="Enterprise"
                color="text-orange-400"
              />
            </div>

            {/* Kill-Chain Strip */}
            <KillChainStrip
              tacticSummary={tacticSummary}
              onSelect={setTacticFilter}
              selected={tacticFilter}
            />

            {tacticFilter && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Filtered by tactic:</span>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${TACTIC_META[tacticFilter]?.border} ${TACTIC_META[tacticFilter]?.color} ${TACTIC_META[tacticFilter]?.bg}`}>
                  {TACTIC_META[tacticFilter]?.label || tacticFilter}
                </span>
                <button onClick={() => setTacticFilter(null)} className="text-xs text-slate-500 hover:text-slate-300">
                  ✕ Clear
                </button>
              </div>
            )}

            {/* ── TABS ── */}
            <div className="border-b border-white/8 flex gap-6">
              {([
                ["overview",   "Overview"],
                ["techniques", `Techniques (${techniqueHits.length})`],
                ["findings",   `Mapped Findings (${findings.length})`],
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

            {/* Search bar (techniques + findings tabs) */}
            {activeTab !== "overview" && (
              <input
                value={searchQ}
                onChange={e => setSearchQ(e.target.value)}
                placeholder="Search techniques or findings…"
                className="w-full max-w-sm px-3 py-2 rounded-lg text-sm bg-[#293448] border border-white/8 text-white placeholder-slate-500 focus:outline-none focus:border-sky-500/50"
              />
            )}

            {/* ── TAB: OVERVIEW ── */}
            {activeTab === "overview" && (
              <div className="grid md:grid-cols-2 gap-6">

                {/* Tactic breakdown table */}
                <div className="rounded-xl bg-[#232d3f] border border-white/6 p-5 space-y-2">
                  <h3 className="text-sm font-semibold text-slate-300 mb-3">Techniques per Tactic</h3>
                  {TACTIC_ORDER.map(tactic => {
                    const summary = tacticSummary.find(t => t.tactic === tactic)
                    const count   = summary?.technique_count || 0
                    const meta    = TACTIC_META[tactic]
                    const pct     = Math.round((count / Math.max(...tacticSummary.map(t => t.technique_count), 1)) * 100)
                    return (
                      <div key={tactic} className="flex items-center gap-3">
                        <span className="text-sm w-5">{meta?.icon}</span>
                        <span className="text-xs text-slate-400 w-36 truncate">{meta?.label || tactic}</span>
                        <div className="flex-1 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all duration-700"
                            style={{
                              width:      `${pct}%`,
                              background: count > 0 ? "linear-gradient(90deg, #3b82f6, #38bdf8)" : "transparent",
                            }}
                          />
                        </div>
                        <span className={`text-xs font-bold w-4 text-right ${count > 0 ? meta?.color : "text-slate-700"}`}>
                          {count}
                        </span>
                      </div>
                    )
                  })}
                </div>

                {/* Top techniques by severity */}
                <div className="rounded-xl bg-[#232d3f] border border-white/6 p-5 space-y-2">
                  <h3 className="text-sm font-semibold text-slate-300 mb-3">Top Techniques by Severity</h3>
                  {techniqueHits
                    .sort((a, b) => b.max_score - a.max_score)
                    .slice(0, 10)
                    .map(h => {
                      const meta    = TACTIC_META[h.tactic]
                      const sevColor = SEV_COLOR[h.max_severity] || "text-slate-400"
                      return (
                        <div key={h.technique_id} className="flex items-center gap-3">
                          <span className="font-mono text-xs text-slate-400 w-16 flex-shrink-0">{h.technique_id}</span>
                          <span className="text-xs text-slate-300 flex-1 truncate">{h.technique_name}</span>
                          <span className={`text-[10px] font-bold flex-shrink-0 ${sevColor}`}>
                            {h.max_severity.toUpperCase()}
                          </span>
                          <span className={`text-[10px] px-1.5 py-0.5 rounded ${meta?.bg || ""} ${meta?.color || "text-slate-400"}`}>
                            {meta?.label || h.tactic}
                          </span>
                        </div>
                      )
                    })}
                </div>
              </div>
            )}

            {/* ── TAB: TECHNIQUES ── */}
            {activeTab === "techniques" && (
              <div className="space-y-2">
                {filteredHits.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-700 p-10 text-center text-slate-500">
                    No techniques match current filters
                  </div>
                ) : (
                  filteredHits.map(h => <TechniqueCard key={h.technique_id} hit={h} />)
                )}
              </div>
            )}

            {/* ── TAB: FINDINGS ── */}
            {activeTab === "findings" && (
              <div className="space-y-2">
                {filteredFindings.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-700 p-10 text-center text-slate-500">
                    No mapped findings for current filter
                  </div>
                ) : (
                  filteredFindings.map((f, i) => <FindingRow key={i} finding={f} />)
                )}
              </div>
            )}

          </div>
        )}

      </div>
    </div>
  )
}
