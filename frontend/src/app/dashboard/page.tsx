"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import AddTargetModal from "@/components/modals/AddTargetModal";

// ─── API configuration ────────────────────────────────────────────────────────
const API_BASE_URL = "http://127.0.0.1:8000";

// ─── TypeScript Interfaces ────────────────────────────────────────────────────
export interface ScanSummary {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
}

export interface ScanData {
    scan_id: string;
    target_name: string;
    target_url: string;
    group_name?: string;
    status: "Queued" | "Running" | "Completed" | "Failed" | string;
    progress?: number;
    summary?: ScanSummary;
    created_at?: string;
    updated_at?: string;
}

const api = {
    fetchScans: async () => {
        const res = await fetch(`${API_BASE_URL}/api/scans`);
        if (!res.ok) throw new Error("Failed to fetch scans");
        return res.json();
    },
    fetchScanStatus: async (scanId: string) => {
        const res = await fetch(`${API_BASE_URL}/api/scan/${scanId}/status`);
        if (!res.ok) throw new Error("Failed to fetch status");
        return res.json();
    },
    deleteScan: async (scanId: string) => {
        const res = await fetch(`${API_BASE_URL}/api/scan/${scanId}`, { method: "DELETE" });
        if (!res.ok) throw new Error("Failed to delete scan");
        return res.json();
    },
};

// ─── Severity helpers ─────────────────────────────────────────────────────────
function getSeverityTotals(scans: ScanData[]) {
    let critical = 0, high = 0, medium = 0, low = 0;
    if (!Array.isArray(scans)) return { critical, high, medium, low }; 

    for (const scan of scans) {
        const s = scan.summary || {};
        // Explicitly separating Critical from High
        critical += s.critical ?? 0;
        high     += s.high ?? 0;
        medium   += s.medium ?? 0;
        low      += (s.low ?? 0) + (s.info ?? 0);
    }
    return { critical, high, medium, low };
}

function getScanSeverityLabel(scan: ScanData): string | null {
    const s = scan.summary || {};
    if ((s.critical ?? 0) > 0) return "critical";
    if ((s.high ?? 0) > 0) return "high";
    if ((s.medium ?? 0) > 0) return "medium";
    if (scan.status === "Completed") return "low";
    return null;
}

// ─── Sub-components ───────────────────────────────────────────────────
function StatusBadge({ status }: { status: string }) {
    const styles: Record<string, string> = {
        Queued:    "bg-slate-700/40 text-slate-400 border border-slate-600/30",
        Running:   "bg-blue-500/10 text-blue-400 border border-blue-500/20",
        Completed: "bg-green-500/10 text-green-400 border border-green-500/20",
        Failed:    "bg-red-500/10 text-red-400 border border-red-500/20",
    };
    const dotStyles: Record<string, string> = {
        Queued:    "bg-slate-500",
        Running:   "bg-blue-400 animate-pulse",
        Completed: "bg-green-400",
        Failed:    "bg-red-400",
    };
    const cls = styles[status] || styles.Queued;
    const dot = dotStyles[status] || dotStyles.Queued;
    return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${cls}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
            {status}
        </span>
    );
}

function SeverityBadge({ label }: { label: string | null }) {
    if (!label) return <span className="text-slate-600 text-sm">—</span>;
    const styles: Record<string, string> = {
        critical: "bg-purple-500/10 text-purple-400 border border-purple-500/20", // Added Critical Style
        high:     "bg-red-500/10 text-red-400 border border-red-500/20",
        medium:   "bg-yellow-400/10 text-yellow-300 border border-yellow-400/20",
        low:      "bg-green-500/10 text-green-400 border border-green-500/20",
    };
    return (
        <span className={`px-2.5 py-1 rounded-full text-xs font-semibold capitalize ${styles[label]}`}>
            {label}
        </span>
    );
}

function ProgressBar({ value }: { value?: number }) {
    return (
        <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-white/10 rounded-full overflow-hidden">
                <div
                    className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 rounded-full transition-all duration-500"
                    style={{ width: `${value ?? 0}%` }}
                />
            </div>
            <span className="text-xs text-slate-500 w-8 text-right">{value ?? 0}%</span>
        </div>
    );
}

function DeleteConfirmModal({ scan, onClose, onConfirm, loading }: { scan: ScanData, onClose: () => void, onConfirm: () => void, loading: boolean }) {
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-[var(--surface-2,#1a1f2e)] border border-red-500/20 rounded-2xl p-7 w-[380px] shadow-2xl">
                <h3 className="text-lg font-bold text-white mb-2">Delete Scan?</h3>
                <p className="text-slate-400 text-sm mb-6">
                    This will permanently remove{" "}
                    <span className="text-white font-semibold">{scan.target_name}</span>{" "}
                    and all associated scan data.
                </p>
                <div className="flex gap-3 justify-end">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 rounded-lg border border-white/10 text-slate-400 text-sm hover:border-white/20 transition"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={onConfirm}
                        disabled={loading}
                        className="px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white text-sm font-semibold transition disabled:opacity-50"
                    >
                        {loading ? "Deleting…" : "Delete"}
                    </button>
                </div>
            </div>
        </div>
    );
}

// ─── Main Dashboard Page ──────────────────────────────────────────────────────
export default function DashboardPage() {
    const [scans, setScans]                 = useState<ScanData[]>([]);
    const [loadingScans, setLoadingScans]   = useState(true);
    const [fetchError, setFetchError]       = useState("");
    const [addTargetOpen, setAddTargetOpen] = useState(false);
    const [deleteTarget, setDeleteTarget]   = useState<ScanData | null>(null);
    const [deletingId, setDeletingId]       = useState<string | null>(null);
    const pollRef                           = useRef<NodeJS.Timeout | null>(null);

    const loadScans = useCallback(async () => {
        try {
            const data = await api.fetchScans();
            setScans(Array.isArray(data.scans) ? data.scans : (Array.isArray(data) ? data : []));
            setFetchError("");
        } catch (err: any) {
            setFetchError(err.message || "Could not connect to server.");
        } finally {
            setLoadingScans(false);
        }
    }, []);

    useEffect(() => {
        loadScans();

        pollRef.current = setInterval(() => {
            setScans((prev) => {
                const active = prev.filter((s) => s.status === "Running" || s.status === "Queued");
                if (active.length === 0) return prev;

                Promise.all(
                    active.map((s) => api.fetchScanStatus(s.scan_id).catch(() => null))
                ).then((updates) => {
                    setScans((latest) =>
                        latest.map((scan) => {
                            const upd = updates.find((u) => u && u.scan_id === scan.scan_id);
                            return upd ? { ...scan, ...upd } : scan;
                        })
                    );
                });
                return prev;
            });
        }, 5000);

        return () => {
            if (pollRef.current) clearInterval(pollRef.current);
        };
    }, [loadScans]);

    const handleDelete = async () => {
        if (!deleteTarget) return;
        setDeletingId(deleteTarget.scan_id);
        try {
            await api.deleteScan(deleteTarget.scan_id);
            setScans((prev) => prev.filter((s) => s.scan_id !== deleteTarget.scan_id));
        } catch {
            alert("Failed to delete scan.");
        } finally {
            setDeletingId(null);
            setDeleteTarget(null);
        }
    };

    const handleViewReport = (scanId: string) => {
        window.location.href = `/reports?scanId=${scanId}`;
    };

    // Destructure all 4 severity levels
    const { critical, high, medium, low } = getSeverityTotals(scans);

    return (
        <main className="min-h-screen bg-[var(--surface-1-gradient)] text-[var(--text-1)]">
            <AddTargetModal
                open={addTargetOpen}
                onClose={() => setAddTargetOpen(false)}
                onSuccess={() => {
                    setAddTargetOpen(false);
                    loadScans();
                }}
            />

            {deleteTarget && (
                <DeleteConfirmModal
                    scan={deleteTarget}
                    loading={deletingId === deleteTarget.scan_id}
                    onClose={() => setDeleteTarget(null)}
                    onConfirm={handleDelete}
                />
            )}

            <div className="bg-[rgba(255,255,255,0.03)] backdrop-blur-xl border-b border-[var(--border-1)] px-6 py-6 shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
                <div className="page-container flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-bold text-[var(--samsec-aqua)] drop-shadow-[0_0_8px_var(--samsec-glow-1)]">
                            Security Dashboard
                        </h1>
                        <p className="text-slate-400">Prioritize vulnerabilities across your infrastructure</p>
                    </div>
                    <button className="btn btn-primary" onClick={() => setAddTargetOpen(true)}>
                        + Start New Scan
                    </button>
                </div>
            </div>

            {fetchError && (
                <div className="page-container mt-4">
                    <div className="px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                        ⚠️ {fetchError}
                    </div>
                </div>
            )}

            {/* Now uses a 4-column grid (md:grid-cols-4) to display all severities clearly */}
            <div className="page-container mt-10 grid sm:grid-cols-2 md:grid-cols-4 gap-6">
                
                {/* Critical Severity Card */}
                <div className="app-card p-6 border border-purple-500/20 shadow-[0_0_10px_rgba(168,85,247,0.1)]">
                    <h3 className="font-semibold flex items-center gap-2 text-purple-400"><span>☢️</span> Critical</h3>
                    <p className={critical > 0 ? "text-4xl font-bold text-purple-400 mt-3" : "text-slate-400 mt-3"}>
                        {critical > 0 ? critical : "Clean"}
                    </p>
                </div>

                <div className="app-card p-6 border border-red-500/20 shadow-[0_0_10px_rgba(255,0,0,0.1)]">
                    <h3 className="font-semibold flex items-center gap-2 text-red-400"><span>🚨</span> High</h3>
                    <p className={high > 0 ? "text-4xl font-bold text-red-400 mt-3" : "text-slate-400 mt-3"}>
                        {high > 0 ? high : "Clean"}
                    </p>
                </div>
                
                <div className="app-card p-6 border border-yellow-400/20 shadow-[0_0_10px_rgba(255,255,0,0.1)]">
                    <h3 className="font-semibold flex items-center gap-2 text-yellow-300"><span>⚠️</span> Medium</h3>
                    <p className={medium > 0 ? "text-4xl font-bold text-yellow-300 mt-3" : "text-slate-400 mt-3"}>
                        {medium > 0 ? medium : "Clean"}
                    </p>
                </div>
                
                <div className="app-card p-6 border border-green-400/20 shadow-[0_0_10px_rgba(0,255,0,0.1)]">
                    <h3 className="font-semibold flex items-center gap-2 text-green-400"><span>✅</span> Low Risk</h3>
                    <p className={low > 0 ? "text-4xl font-bold text-green-400 mt-3" : "text-slate-400 mt-3"}>
                        {low > 0 ? low : "No findings"}
                    </p>
                </div>
            </div>

            <div className="page-container mt-10 mb-16">
                <div className="app-card p-6 border border-[rgba(255,255,255,0.06)] shadow-[0_0_12px_rgba(0,0,0,0.4)]">
                    <h2 className="font-bold mb-6 text-[var(--samsec-teal)] text-xl">
                        All Targets {scans.length > 0 && <span className="text-sm font-normal text-slate-500 ml-2">({scans.length})</span>}
                    </h2>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="text-slate-400 text-sm border-b border-[rgba(255,255,255,0.05)]">
                                    <th className="pb-3 pr-4">Target</th>
                                    <th className="pb-3 pr-4">Status</th>
                                    <th className="pb-3 pr-4 min-w-[140px]">Progress</th>
                                    <th className="pb-3 pr-4">Severity</th>
                                    <th className="pb-3">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {loadingScans ? (
                                    <tr><td colSpan={5} className="py-10 text-center text-slate-500">Loading scans…</td></tr>
                                ) : scans.length === 0 ? (
                                    <tr><td colSpan={5} className="py-10 text-center text-slate-500">No targets added yet.</td></tr>
                                ) : (
                                    scans.map((scan) => (
                                        <tr key={scan.scan_id} className="hover:bg-[rgba(255,255,255,0.03)] transition border-b border-[rgba(255,255,255,0.03)] last:border-0">
                                            <td className="py-4 pr-4">
                                                <p className="font-semibold text-white text-sm">{scan.target_name}</p>
                                                <p className="text-xs text-slate-500 mt-0.5 truncate max-w-[200px]">{scan.target_url}</p>
                                            </td>
                                            <td className="py-4 pr-4"><StatusBadge status={scan.status} /></td>
                                            <td className="py-4 pr-4">
                                                {scan.status === "Running" || scan.status === "Queued" ? <ProgressBar value={scan.progress} /> : <span className="text-slate-600 text-sm">—</span>}
                                            </td>
                                            <td className="py-4 pr-4"><SeverityBadge label={getScanSeverityLabel(scan)} /></td>
                                            <td className="py-4">
                                                <div className="flex items-center gap-2">
                                                    <button
                                                        onClick={() => handleViewReport(scan.scan_id)}
                                                        disabled={scan.status !== "Completed"}
                                                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-[var(--samsec-aqua,#00c8c8)]/10 text-[var(--samsec-aqua,#00c8c8)] border border-[var(--samsec-aqua,#00c8c8)]/20 hover:bg-[var(--samsec-aqua,#00c8c8)]/20 transition disabled:opacity-30"
                                                    >
                                                        View
                                                    </button>
                                                    <button
                                                        onClick={() => setDeleteTarget(scan)}
                                                        className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition"
                                                    >
                                                        Delete
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </main>
    );
}