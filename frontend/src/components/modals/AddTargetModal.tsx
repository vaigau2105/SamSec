"use client";

import { useState } from "react";
import ModalBase from "./ModalBase";

interface AddTargetModalProps {
    open: boolean;
    onClose: () => void;
    onSuccess: () => void;
}

export default function AddTargetModal({ open, onClose, onSuccess }: AddTargetModalProps) {
    const [form, setForm] = useState({
        target_url: "",
        target_name: "",
        group_name: "",
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) =>
        setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));

    const handleSubmit = async () => {
        // Validation
        if (!form.target_url.trim() || !form.target_name.trim()) {
            return setError("Name and URL are required.");
        }

        try {
            new URL(form.target_url);
        } catch {
            return setError("Please enter a valid URL (e.g., https://example.com).");
        }

        setLoading(true);
        setError("");

        try {
            // Updated to point directly to your FastAPI backend to fix connection errors
            const res = await fetch("http://127.0.0.1:8000/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(form),
            });

            if (!res.ok) throw new Error("Failed to start scan");

            // Reset form and notify parent to refresh dashboard
            setForm({ target_url: "", target_name: "", group_name: "" });
            onSuccess();
        } catch (err: any) {
            setError(err.message || "Connection failed. Is the backend running?");
        } finally {
            setLoading(false);
        }
    };

    return (
        <ModalBase open={open} onClose={onClose}>
            <h2 className="text-xl font-semibold mb-6">Add New Target</h2>

            {error && (
                <div className="mb-4 p-2 text-xs bg-red-500/10 border border-red-500/20 text-red-400 rounded">
                    {error}
                </div>
            )}

            <div className="space-y-4">
                <div>
                    <label className="text-sm text-slate-400">Target Name</label>
                    <input
                        name="target_name"
                        value={form.target_name}
                        onChange={handleChange}
                        className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white"
                        placeholder="e.g., Production Website"
                    />
                </div>

                <div>
                    <label className="text-sm text-slate-400">Target URL</label>
                    <input
                        name="target_url"
                        value={form.target_url}
                        onChange={handleChange}
                        className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white"
                        placeholder="https://example.com"
                    />
                </div>

                <div>
                    <label className="text-sm text-slate-400">Group (Optional)</label>
                    <input
                        name="group_name"
                        value={form.group_name}
                        onChange={handleChange}
                        className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white"
                        placeholder="e.g., Production, Clients"
                    />
                </div>

                <div className="flex justify-end gap-3 mt-4">
                    <button 
                        className="btn btn-ghost" 
                        onClick={onClose}
                        disabled={loading}
                    >
                        Cancel
                    </button>
                    <button 
                        className="btn btn-primary" 
                        onClick={handleSubmit}
                        disabled={loading}
                    >
                        {loading ? "Starting..." : "Start Scan"}
                    </button>
                </div>
            </div>
        </ModalBase>
    );
}