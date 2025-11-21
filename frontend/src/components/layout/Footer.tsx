import Link from "next/link";

export default function Footer() {
    return (
        <footer className="relative bg-[var(--surface-1-gradient)] border-t border-[rgba(255,255,255,0.05)] mt-24 pt-16">

            {/* Background Glow */}
            <div className="absolute inset-0 pointer-events-none">
                <div className="absolute w-[600px] h-[600px] -top-40 left-1/2 -translate-x-1/2
                    bg-[var(--samsec-blue)]/5 blur-[180px] opacity-70">
                </div>
            </div>

            {/* FOOTER CONTENT */}
            <div className="relative max-w-7xl mx-auto px-6 pb-12 grid md:grid-cols-3 gap-12">

                {/* BRAND */}
                <div>
                    <div className="flex items-center gap-3 mb-4">
                        <div
                            className="
                                w-10 h-10 rounded-xl flex items-center justify-center font-bold text-black
                                bg-gradient-to-br from-[var(--samsec-blue)] to-[var(--samsec-aqua)]
                                shadow-[0_0_20px_var(--samsec-glow-1)]
                            "
                        >
                            S
                        </div>

                        <span className="text-xl font-semibold text-white drop-shadow-[0_0_10px_rgba(0,0,0,0.6)]">
                            SamSec
                        </span>
                    </div>

                    <p className="text-slate-400 text-sm leading-relaxed max-w-xs">
                        Enterprise-grade vulnerability scanning engine.
                        Scan, prioritize, and remediate security issues at scale with real-time insights.
                    </p>
                </div>

                {/* PRODUCT LINKS */}
                <div>
                    <h4 className="text-white font-semibold mb-4 text-lg
                        drop-shadow-[0_0_10px_rgba(0,0,0,0.5)]">
                        Product
                    </h4>

                    <ul className="space-y-2 text-slate-400 text-sm">
                        <li><Link href="/dashboard" className="hover:text-[var(--samsec-aqua)] transition">Dashboard</Link></li>
                        <li><Link href="/new-scan" className="hover:text-[var(--samsec-aqua)] transition">New Scan</Link></li>
                        <li><Link href="/reports" className="hover:text-[var(--samsec-aqua)] transition">Reports</Link></li>
                    </ul>
                </div>

                {/* COMPANY LINKS */}
                <div>
                    <h4 className="text-white font-semibold mb-4 text-lg
                        drop-shadow-[0_0_10px_rgba(0,0,0,0.5)]">
                        Company
                    </h4>

                    <ul className="space-y-2 text-slate-400 text-sm">
                        <li><Link href="/about" className="hover:text-[var(--samsec-aqua)] transition">About</Link></li>
                        <li><Link href="/privacy" className="hover:text-[var(--samsec-aqua)] transition">Privacy</Link></li>
                        <li><Link href="/contact" className="hover:text-[var(--samsec-aqua)] transition">Contact</Link></li>
                    </ul>
                </div>
            </div>

            {/* COPYRIGHT & SMALL LINKS */}
            <div className="border-t border-[rgba(255,255,255,0.05)]">
                <div className="
                    max-w-7xl mx-auto px-6 py-6
                    flex flex-col md:flex-row justify-between items-center text-sm text-slate-400
                ">
                    <div className="text-center md:text-left">
                        © {new Date().getFullYear()} SamSec. All rights reserved.
                    </div>

                    <div className="mt-4 md:mt-0 flex gap-6">
                        <Link href="#" className="hover:text-[var(--samsec-aqua)] transition">Terms</Link>
                        <Link href="#" className="hover:text-[var(--samsec-aqua)] transition">Security</Link>
                        <Link href="#" className="hover:text-[var(--samsec-aqua)] transition">Status</Link>
                    </div>
                </div>
            </div>

        </footer>
    );
}
