"use client";

import { useEffect, useState } from "react";
import { Eye, EyeOff } from "lucide-react";

export default function AuthModal({ open, onClose, openForgot }) {
    const [showPass, setShowPass] = useState(false);
    const [mode, setMode] = useState<"login" | "signup">("login");
    useEffect(() => {
    const handler = (e) => setMode(e.detail);
    document.addEventListener("auth-set-mode", handler);
    return () => document.removeEventListener("auth-set-mode", handler);
}, []);

    if (!open) return null;

    return (
        <div
            className="
                fixed inset-0 z-[9999]
                flex items-center justify-center
                bg-black/50 backdrop-blur-sm
            "
        >
            <div
                className="
                    w-full max-w-sm
                    bg-[#111827]
                    border border-[rgba(255,255,255,0.08)]
                    rounded-xl p-6
                    shadow-xl animate-fade-in
                "
            >
                {/* HEADER */}
                <div className="flex justify-between items-center mb-5">
                    <h2 className="text-xl font-semibold">
                        {mode === "login" ? "Welcome Back" : "Create Account"}
                    </h2>

                    <button
                        onClick={onClose}
                        className="text-slate-400 hover:text-white"
                    >
                        ✕
                    </button>
                </div>

                {/* SWITCHER */}
                <div className="flex mb-6 border-b border-[rgba(255,255,255,0.1)]">
                    <button
                        className={`
                            flex-1 py-2 text-sm font-semibold
                            ${mode === "login"
                                ? "text-[var(--samsec-aqua)] border-b-2 border-[var(--samsec-aqua)]"
                                : "text-slate-400"}
                        `}
                        onClick={() => setMode("login")}
                    >
                        Log In
                    </button>

                    <button
                        className={`
                            flex-1 py-2 text-sm font-semibold
                            ${mode === "signup"
                                ? "text-[var(--samsec-aqua)] border-b-2 border-[var(--samsec-aqua)]"
                                : "text-slate-400"}
                        `}
                        onClick={() => setMode("signup")}
                    >
                        Sign Up
                    </button>
                </div>

                {/* ==== LOGIN FORM ==== */}
                {mode === "login" && (
                    <>
                        {/* Email */}
                        <label className="block text-sm text-slate-300 mb-1">Email</label>
                        <input
                            type="email"
                            placeholder="you@example.com"
                            className="w-full mb-4 bg-[#1e293b] border border-[rgba(255,255,255,0.08)] rounded-lg px-3 py-2"
                        />

                        {/* Password */}
                        <label className="block text-sm text-slate-300 mb-1">Password</label>

                        <div className="relative">
                            <input
                                type={showPass ? "text" : "password"}
                                className="w-full bg-[#1e293b] border border-[rgba(255,255,255,0.08)] rounded-lg px-3 py-2"
                            />

                            <button
                                onClick={() => setShowPass(!showPass)}
                                className="absolute right-3 top-2.5 text-slate-400 hover:text-white"
                            >
                                {showPass ? <EyeOff size={18} /> : <Eye size={18} />}
                            </button>
                        </div>

                        <button
                            onClick={openForgot}
                            className="mt-2 text-sm text-[var(--samsec-blue)] hover:underline"
                        >
                            Forgot password?
                        </button>

                        <button className="btn btn-primary w-full mt-6 py-2">Log In</button>
                    </>
                )}

                {/* ==== SIGNUP FORM ==== */}
                {mode === "signup" && (
                    <>
                        {/* Full Name */}
                        <label className="block text-sm text-slate-300 mb-1">Full Name</label>
                        <input
                            type="text"
                            placeholder="John Doe"
                            className="w-full mb-4 bg-[#1e293b] border border-[rgba(255,255,255,0.08)] rounded-lg px-3 py-2"
                        />

                        {/* Email */}
                        <label className="block text-sm text-slate-300 mb-1">Email</label>
                        <input
                            type="email"
                            placeholder="you@example.com"
                            className="w-full mb-4 bg-[#1e293b] border border-[rgba(255,255,255,0.08)] rounded-lg px-3 py-2"
                        />

                        {/* Password */}
                        <label className="block text-sm text-slate-300 mb-1">Password</label>

                        <div className="relative mb-6">
                            <input
                                type={showPass ? "text" : "password"}
                                className="w-full bg-[#1e293b] border border-[rgba(255,255,255,0.08)] rounded-lg px-3 py-2"
                            />

                            <button
                                onClick={() => setShowPass(!showPass)}
                                className="absolute right-3 top-2.5 text-slate-400 hover:text-white"
                            >
                                {showPass ? <EyeOff size={18} /> : <Eye size={18} />}
                            </button>
                        </div>

                        <button className="btn btn-primary w-full py-2">Create Account</button>
                    </>
                )}

                <button
                    onClick={onClose}
                    className="mt-4 text-sm text-slate-400 hover:text-white mx-auto block"
                >
                    Cancel
                </button>
            </div>
        </div>
    );
}
