"use client";

import Link from "next/link";
import { useState } from "react";
import AuthModal from "../modals/AuthModal";
import ForgotPasswordModal from "../modals/ForgotPasswordModal";
import Image from "next/image";
import { Menu } from "lucide-react";

export default function Navbar() {
    const [authOpen, setAuthOpen] = useState(false);
    const [forgotOpen, setForgotOpen] = useState(false);

    return (
        <>
            <nav
                className="
                    sticky top-0 z-50
                    bg-[#0c101b]/90 backdrop-blur-xl
                    border-b border-[rgba(255,255,255,0.05)]
                    shadow-[0_0_25px_rgba(0,0,0,0.7)]
                "
            >
                <div className="max-w-7xl mx-auto px-4 h-16 flex justify-between items-center">

                    {/* LOGO */}
                    <div className="flex items-center gap-3">
                        <div className="relative w-10 h-10 flex items-center justify-center">
                            <div className="absolute inset-0 rounded-xl bg-[var(--samsec-blue)]/25 blur-xl opacity-80"></div>

                            <Image
                                src="/samsec.png"
                                width={48}
                                height={48}
                                alt="SamSec Logo"
                                priority
                                className="relative z-10 w-10 h-10 object-contain drop-shadow-[0_0_12px_var(--samsec-glow-1)]"
                            />
                        </div>

                        <span className="text-xl font-semibold text-white drop-shadow-[0_0_10px_rgba(0,0,0,0.6)]">
                            SamSec
                        </span>
                    </div>

                    {/* Desktop Nav Links */}
                    <div className="hidden md:flex gap-8">
                        {[
                            ["Home", "/"],
                            ["Dashboard", "/dashboard"],
                            ["New Scan", "/new-scan"],
                            ["Reports", "/reports"],
                            ["Account", "/account"],
                        ].map(([label, href]) => (
                            <Link
                                key={label}
                                href={href}
                                className="
                                    text-slate-300 text-sm font-medium
                                    hover:text-[var(--samsec-aqua)]
                                    transition-colors duration-200
                                "
                            >
                                {label}
                            </Link>
                        ))}
                    </div>

                    {/* Desktop Auth */}
                    <div className="hidden md:flex gap-4">
                        <button
                            onClick={() => {
                                setAuthOpen(true);
                                setTimeout(() => {
                                    document.dispatchEvent(new CustomEvent("auth-set-mode", { detail: "login" }));
                                }, 10);
                            }}
                            className="
        text-slate-300 text-sm font-medium
        hover:text-white transition
    "
                        >
                            Log In
                        </button>

                        <button
                            onClick={() => {
                                setAuthOpen(true);
                                setTimeout(() => {
                                    document.dispatchEvent(new CustomEvent("auth-set-mode", { detail: "signup" }));
                                }, 10);
                            }}
                            className="
        px-4 py-2 text-sm font-semibold rounded-lg
        bg-gradient-to-r from-[var(--samsec-blue)] to-[var(--samsec-aqua)]
        text-black shadow-[0_0_15px_var(--samsec-glow-1)]
        hover:opacity-90 transition
    "
                        >
                            Sign Up
                        </button>

                    </div>

                    {/* Mobile Icon */}
                    <div className="md:hidden">
                        <button className="text-slate-300 hover:text-white transition">
                            <Menu className="w-7 h-7" />
                        </button>
                    </div>
                </div>
            </nav>

            {/* MODALS MUST BE OUTSIDE NAVBAR */}
            <AuthModal
                open={authOpen}
                onClose={() => setAuthOpen(false)}
                openForgot={() => setForgotOpen(true)}
            />

            <ForgotPasswordModal
                open={forgotOpen}
                onClose={() => setForgotOpen(false)}
            />
        </>
    );
}
