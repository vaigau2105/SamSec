"use client";

import Image from "next/image";
import { HexagonBackground } from "@/components/ui/shadcn-io/hexagon-background";

export default function Hero() {
    return (
        <section className="relative overflow-hidden py-20 md:py-24 px-4 text-center bg-[var(--surface-1-gradient)]">

            {/* Hexagon BG */}
            <div className="absolute inset-0">
                <HexagonBackground className="w-full h-full opacity-[0.4] pointer-events-none" />
            </div>

            {/* Subtle top-to-bottom gradient */}
            <div className="absolute inset-0 bg-gradient-to-b from-black/40 via-transparent to-[#0b0f19]"></div>

            {/* Content */}
            <div className="relative z-10 max-w-4xl mx-auto">

                {/* Logo (Smaller, clean) */}
                <div className="flex justify-center mb-6">
                    <Image
                        src="/samsec.png"
                        width={165}
                        height={165}
                        alt="SamSec Logo"
                        priority
                        className="w-[155px] h-[155px] object-contain opacity-95"
                    />
                </div>

                {/* Title */}
                <h1 className="text-4xl md:text-5xl font-extrabold text-white leading-tight">
                    High-Speed Multi-Target Web Vulnerability Scanner
                </h1>

                {/* Subtitle */}
                <p className="text-lg md:text-xl text-slate-300 max-w-2xl mx-auto mt-4">
                    Scan up to <span className="text-[var(--samsec-blue)] font-semibold">1,000 assets</span>{" "}
                    in parallel with intelligent prioritization and automated remediation workflow tracking.
                </p>

                {/* CTA */}
                <button className="btn btn-primary mt-8 px-10 py-3 text-lg">
                    Go to Dashboard
                </button>
            </div>
        </section>
    );
}
