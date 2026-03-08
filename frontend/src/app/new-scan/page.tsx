"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const API = "http://127.0.0.1:8000";

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
                    {(["single", "bulk"] as const).map(t => (
                        <button
                            key={t}
                            onClick={() => setTab(t)}
                            className={`
                                pb-3 font-semibold transition
                                ${tab === t
                                    ? "text-[var(--samsec-blue)] border-b-2 border-[var(--samsec-blue)]"
                                    : "text-slate-400 hover:text-white"
                                }
                            `}
                        >
                            {t === "single" ? "Single Target Scan" : "Bulk Scan"}
                        </button>
                    ))}
                </div>
            </div>

            {/* CONTENT */}
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


/* ─────────────────────────────────────────────────────────────
   SINGLE TARGET SCAN FORM
───────────────────────────────────────────────────────────── */
function SingleScanForm() {
    const router = useRouter();
    const [targetName, setTargetName] = useState("");
    const [targetUrl,  setTargetUrl]  = useState("");
    const [groupName,  setGroupName]  = useState("");
    const [loading,    setLoading]    = useState(false);

    const startSingleScan = async () => {
        if (!targetUrl.trim()) {
            alert("Please enter a target URL");
            return;
        }

        setLoading(true);
        try {
            const res = await fetch(`${API}/api/scan`, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    target_name: targetName || targetUrl,
                    target_url:  targetUrl.trim(),
                    group_name:  groupName || "Default",
                }),
            });

            const data = await res.json();

            if (data.scan_id) {
                alert(`✅ Scan started!\nScan ID: ${data.scan_id}\n\nRedirecting to reports…`);
                router.push("/reports");
            } else {
                alert("❌ Unexpected response from server");
            }
        } catch (err) {
            console.error(err);
            alert("❌ Could not connect to backend. Is it running?");
        } finally {
            setLoading(false);
        }
    };

    return (
        <>
            <h2 className="text-2xl font-bold text-[var(--samsec-blue)] mb-6">
                Single Target Scan
            </h2>

            <div className="grid md:grid-cols-2 gap-6">
                <div>
                    <label className="block text-sm text-slate-300 mb-2">Target Name</label>
                    <input
                        placeholder="e.g., Production Website"
                        value={targetName}
                        onChange={e => setTargetName(e.target.value)}
                        className="w-full bg-[var(--surface-3)] border border-[rgba(255,255,255,0.06)] rounded-lg px-3 py-2 focus:outline-none focus:border-[var(--samsec-blue)]"
                    />
                </div>

                <div>
                    <label className="block text-sm text-slate-300 mb-2">Target URL</label>
                    <input
                        placeholder="https://example.com  or  http://localhost:3000"
                        value={targetUrl}
                        onChange={e => setTargetUrl(e.target.value)}
                        onKeyDown={e => e.key === "Enter" && startSingleScan()}
                        className="w-full bg-[var(--surface-3)] border border-[rgba(255,255,255,0.06)] rounded-lg px-3 py-2 focus:outline-none focus:border-[var(--samsec-blue)]"
                    />
                    <p className="text-xs text-slate-500 mt-1">Supports domains, IPs, and localhost with ports</p>
                </div>

                <div>
                    <label className="block text-sm text-slate-300 mb-2">Group</label>
                    <input
                        placeholder="e.g., Production, Staging"
                        value={groupName}
                        onChange={e => setGroupName(e.target.value)}
                        className="w-full bg-[var(--surface-3)] border border-[rgba(255,255,255,0.06)] rounded-lg px-3 py-2 focus:outline-none focus:border-[var(--samsec-blue)]"
                    />
                </div>
            </div>

            <div className="mt-10 flex gap-4 items-center">
                <button
                    onClick={startSingleScan}
                    disabled={loading}
                    className="
                        bg-gradient-to-r from-[var(--samsec-blue)] to-[var(--samsec-aqua)]
                        hover:opacity-90 transition disabled:opacity-50
                        px-6 py-3 rounded-lg font-semibold text-black
                    "
                >
                    {loading ? "Starting…" : "🚀 Start Scan"}
                </button>
                {loading && (
                    <span className="text-sm text-slate-400 animate-pulse">
                        Queuing scan — you will be redirected to reports…
                    </span>
                )}
            </div>
        </>
    );
}


/* ─────────────────────────────────────────────────────────────
   BULK SCAN FORM
───────────────────────────────────────────────────────────── */
function BulkScanForm() {
    const router = useRouter();
    const [urlList,    setUrlList]    = useState("");
    const [groupName,  setGroupName]  = useState("Bulk");
    const [loading,    setLoading]    = useState(false);
    const [results,    setResults]    = useState<{ scheduled: number; scan_ids: string[] } | null>(null);

    const startBulkScan = async () => {
        const urls = urlList
            .split("\n")
            .map(u => u.trim())
            .filter(u => u.length > 0);

        if (urls.length === 0) {
            alert("Please enter at least one URL");
            return;
        }

        if (urls.length > 1000) {
            alert("Maximum 1,000 URLs per bulk scan");
            return;
        }

        setLoading(true);
        setResults(null);

        try {
            const res = await fetch(`${API}/api/bulk_scan`, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    urls:       urls,
                    group_name: groupName || "Bulk",
                }),
            });

            if (!res.ok) {
                const err = await res.text();
                alert(`❌ Server error: ${err}`);
                return;
            }

            const data = await res.json();
            setResults(data);

        } catch (err) {
            console.error(err);
            alert("❌ Could not connect to backend. Is it running?");
        } finally {
            setLoading(false);
        }
    };

    const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = ev => {
            const text = ev.target?.result as string || "";
            // Handle CSV (first column) or plain txt
            const lines = text
                .split("\n")
                .map(l => l.split(",")[0].trim())
                .filter(l => l.length > 0);
            setUrlList(lines.join("\n"));
        };
        reader.readAsText(file);
    };

    const urlCount = urlList.split("\n").filter(u => u.trim()).length;

    return (
        <>
            <h2 className="text-2xl font-bold text-[var(--samsec-blue)] mb-2">
                Bulk Scan
            </h2>
            <p className="text-slate-400 mb-6 max-w-2xl">
                Scan multiple targets in parallel. Each target gets its own scan process.
            </p>

            <div className="grid md:grid-cols-2 gap-6">

                {/* URL TEXTAREA */}
                <div>
                    <label className="block text-sm font-semibold text-slate-300 mb-2">
                        Paste URL List
                        {urlCount > 0 && (
                            <span className="ml-2 text-sky-400 font-normal">{urlCount} URLs</span>
                        )}
                    </label>
                    <textarea
                        rows={10}
                        value={urlList}
                        onChange={e => setUrlList(e.target.value)}
                        placeholder={`https://example1.com\nhttp://localhost:3000\nhttps://example2.com`}
                        className="
                            w-full bg-[var(--surface-3)] border border-[rgba(255,255,255,0.06)]
                            rounded-lg px-3 py-2 font-mono text-sm
                            focus:outline-none focus:border-[var(--samsec-blue)]
                        "
                    />
                    <p className="text-xs text-slate-500 mt-1">One URL per line (max 1,000)</p>
                </div>

                {/* FILE UPLOAD + OPTIONS */}
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-semibold text-slate-300 mb-2">Upload File</label>
                        <label className="
                            block p-8 rounded-lg text-center border-2 border-dashed border-[rgba(255,255,255,0.12)]
                            bg-[var(--surface-3)] hover:border-[var(--samsec-blue)] transition cursor-pointer
                        ">
                            <p className="text-4xl mb-2">📁</p>
                            <p className="text-slate-300 text-sm">Click to upload .txt or .csv</p>
                            <input
                                type="file"
                                accept=".txt,.csv"
                                className="hidden"
                                onChange={handleFileUpload}
                            />
                        </label>
                    </div>

                    <div>
                        <label className="block text-sm font-semibold text-slate-300 mb-2">Group Name</label>
                        <input
                            value={groupName}
                            onChange={e => setGroupName(e.target.value)}
                            placeholder="e.g., Bulk Scan 2025"
                            className="
                                w-full bg-[var(--surface-3)] border border-[rgba(255,255,255,0.06)]
                                rounded-lg px-3 py-2 focus:outline-none focus:border-[var(--samsec-blue)]
                            "
                        />
                    </div>
                </div>
            </div>

            {/* ACTIONS */}
            <div className="mt-8 flex gap-4 items-center flex-wrap">
                <button
                    onClick={startBulkScan}
                    disabled={loading || urlCount === 0}
                    className="
                        bg-gradient-to-r from-[var(--samsec-blue)] to-[var(--samsec-aqua)]
                        hover:opacity-90 transition disabled:opacity-50
                        px-6 py-3 rounded-lg font-semibold text-black
                        shadow-[0_0_20px_rgba(56,189,248,0.3)]
                    "
                >
                    {loading ? `Starting ${urlCount} scans…` : `🚀 Start Bulk Scan (${urlCount})`}
                </button>

                {results && (
                    <button
                        onClick={() => router.push("/reports")}
                        className="px-5 py-3 rounded-lg text-sm font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/25 hover:bg-emerald-500/25 transition"
                    >
                        View Reports →
                    </button>
                )}
            </div>

            {/* SUCCESS MESSAGE */}
            {results && (
                <div className="mt-6 rounded-xl border border-emerald-500/25 bg-emerald-500/5 p-5">
                    <p className="text-emerald-400 font-semibold mb-2">
                        ✅ {results.scheduled} scan{results.scheduled !== 1 ? "s" : ""} queued successfully
                    </p>
                    <p className="text-slate-400 text-sm mb-3">Scan IDs (check reports page for progress):</p>
                    <div className="flex flex-wrap gap-2">
                        {results.scan_ids.map(id => (
                            <span key={id} className="text-xs font-mono px-2 py-1 rounded bg-slate-800 text-sky-300 border border-sky-500/20">
                                {id}
                            </span>
                        ))}
                    </div>
                </div>
            )}
        </>
    );
}