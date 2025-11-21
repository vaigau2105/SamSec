"use client";

import AddTargetModal from "@/components/modals/AddTargetModal";
import { useState } from "react";

export default function DashboardPage() {
    const [addTargetOpen, setAddTargetOpen] = useState(false);

    return (
        <main className="min-h-screen bg-[var(--surface-1-gradient)] text-[var(--text-1)]">

            <AddTargetModal open={addTargetOpen} onClose={() => setAddTargetOpen(false)} />

            {/* Header */}
<div className="
    bg-[rgba(255,255,255,0.03)]
    backdrop-blur-xl
    border-b border-[var(--border-1)]
    px-6 py-6
    shadow-[0_4px_20px_rgba(0,0,0,0.3)]
">                <div className="page-container flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-bold text-[var(--samsec-aqua)] drop-shadow-[0_0_8px_var(--samsec-glow-1)]">
                            Security Dashboard
                        </h1>
                        <p className="text-slate-400">
                            Prioritize vulnerabilities across your infrastructure
                        </p>
                    </div>

                    <button
                        className="btn btn-primary"
                        onClick={() => setAddTargetOpen(true)}
                    >
                        + Start New Scan
                    </button>
                </div>
            </div>

            {/* Severity Summary */}
            <div className="page-container mt-10 grid md:grid-cols-3 gap-6">

                {/* High Severity */}
                <div className="app-card p-6 border border-red-500/20 shadow-[0_0_10px_rgba(255,0,0,0.1)]">
                    <h3 className="font-semibold flex items-center gap-2 text-red-400">
                        <span>🚨</span>
                        High Severity Targets
                    </h3>
                    <p className="text-slate-400 mt-3">
                        No high severity targets found. Excellent!
                    </p>
                </div>

                {/* Medium Severity */}
                <div className="app-card p-6 border border-yellow-400/20 shadow-[0_0_10px_rgba(255,255,0,0.1)]">
                    <h3 className="font-semibold flex items-center gap-2 text-yellow-300">
                        <span>⚠️</span>
                        Medium Severity Targets
                    </h3>
                    <p className="text-slate-400 mt-3">No medium severity targets found.</p>
                </div>

                {/* Low Risk */}
                <div className="app-card p-6 border border-green-400/20 shadow-[0_0_10px_rgba(0,255,0,0.1)]">
                    <h3 className="font-semibold flex items-center gap-2 text-green-400">
                        <span>✅</span>
                        Low Risk / Clean Targets
                    </h3>
                    <p className="text-slate-400 mt-3">
                        No targets scanned yet. Start your first scan!
                    </p>
                </div>
            </div>

            {/* All Targets Table */}
            <div className="page-container mt-10">
                <div className="app-card p-6 border border-[rgba(255,255,255,0.06)] shadow-[0_0_12px_rgba(0,0,0,0.4)]">
                    <h2 className="font-bold mb-6 text-[var(--samsec-teal)] text-xl">
                        All Targets
                    </h2>

                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="text-slate-400 text-sm border-b border-[rgba(255,255,255,0.05)]">
                                    <th className="pb-3">Target</th>
                                    <th className="pb-3">Group</th>
                                    <th className="pb-3">Status</th>
                                    <th className="pb-3">Last Scan</th>
                                    <th className="pb-3">Severity</th>
                                    <th className="pb-3">Actions</th>
                                </tr>
                            </thead>

                            <tbody>
                                <tr className="hover:bg-[rgba(255,255,255,0.03)] transition">
                                    <td colSpan={6}
                                        className="py-10 text-center text-slate-500">
                                        No targets added yet.
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                </div>
            </div>

        </main>
    );
}
