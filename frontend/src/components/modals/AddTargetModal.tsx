"use client";

import ModalBase from "./ModalBase";

export default function AddTargetModal({ open, onClose }: any) {
    return (
        <ModalBase open={open} onClose={onClose}>
            <h2 className="text-xl font-semibold mb-6">Add New Target</h2>

            <div className="space-y-4">
                <div>
                    <label className="text-sm">Target Name</label>
                    <input className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2"
                        placeholder="e.g., Production Website" />
                </div>

                <div>
                    <label className="text-sm">Target URL</label>
                    <input className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2"
                        placeholder="https://example.com" />
                </div>

                <div>
                    <label className="text-sm">Group (Optional)</label>
                    <input className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2"
                        placeholder="e.g., Production, Clients" />
                </div>

                <div className="flex justify-end gap-3 mt-4">
                    <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
                    <button className="btn btn-primary">Start Scan</button>
                </div>
            </div>
        </ModalBase>
    );
}
