"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";

export default function About() {
    return (
        <section className="bg-[var(--surface-1-gradient)] py-24 border-t border-[var(--border-1)]">

            {/* Heading */}
            <h2 className="
                text-4xl md:text-5xl font-extrabold text-center mb-12
                text-[var(--samsec-aqua)]
                drop-shadow-[0_0_15px_var(--samsec-glow-1)]
            ">
                About the SamSec Platform
            </h2>

            {/* Description */}
            <div className="max-w-4xl mx-auto text-[var(--text-2)] text-lg leading-relaxed space-y-6 px-4">
                <p>
                    SamSec is an enterprise-grade vulnerability scanning platform engineered for
                    security teams, developers, DevOps engineers, and organizations that require
                    high-speed, high-accuracy automated security testing across modern
                    applications and cloud infrastructure.
                </p>
                <p>
                    Our engine can scan up to{" "}
                    <span className="text-[var(--samsec-blue)] font-semibold">
                        1,000+ assets simultaneously
                    </span>,
                    delivering enriched vulnerability insights, severity prioritization, and
                    actionable remediation workflows — all in minutes.
                </p>
                <p>
                    SamSec integrates with CI/CD, offers automated scheduling, team collaboration
                    tools, API access, reporting dashboards, and parallel scanning systems to help
                    your team maintain a continuous and proactive security posture.
                </p>
            </div>

            {/* Feature Cards */}
            <div className="max-w-6xl mx-auto mt-16 grid md:grid-cols-3 gap-8 px-4">
                {[
                    ["⚡", "High-Speed Engine", "Parallel scanning powered by a highly optimized vulnerability detection engine."],
                    ["📡", "Cloud-Ready", "Easily scan cloud apps, APIs, and infrastructure with seamless workflow integration."],
                    ["🛡️", "Enterprise Security", "Robust protections, encryption, and role-based team access control included."]
                ].map(([icon, title, desc]) => (
                    <div
                        key={title}
                        className="
                            relative p-[2px] rounded-2xl
                            bg-gradient-to-br
                            from-[var(--samsec-aqua)]
                            via-[var(--samsec-blue)]
                            to-[var(--samsec-teal)]
                            shadow-[0_0_25px_var(--samsec-glow-1)]
                        "
                    >
                        <div className="
                            bg-[var(--surface-2)] rounded-2xl p-6 h-full
                            text-center shadow-[0_0_20px_rgba(0,0,0,0.3)]
                        ">
                            <div className="text-5xl mb-4">{icon}</div>
                            <h3 className="text-xl font-bold mb-2 text-[var(--text-1)]">
                                {title}
                            </h3>
                            <p className="text-[var(--text-3)] text-sm">{desc}</p>
                        </div>
                    </div>
                ))}
            </div>

            {/* Accordion */}
            <AboutAccordion />

        </section>
    );
}

/* ----------------------------------------------------
   Accordion Component — Fixed Theme Colors
---------------------------------------------------- */
function AboutAccordion() {
    const items = [
        {
            title: "How does SamSec detect vulnerabilities?",
            content:
                "SamSec uses a hybrid detection engine combining signature-based scanning, behavioral analysis, heuristic detection, and machine-assisted rule sets. This ensures accurate identification of OWASP Top 10, misconfigurations, outdated dependencies, SSL/TLS issues, and more."
        },
        {
            title: "Who is SamSec designed for?",
            content:
                "From individual developers to enterprise SOC teams, SamSec is built for anyone needing fast, automated, and scalable security scanning. It fits seamlessly into CI/CD pipelines, cloud workflows, and DevSecOps programs."
        },
        {
            title: "What makes SamSec different?",
            content:
                "Unlike traditional scanners, SamSec prioritizes speed and scalability — supporting over 1,000 parallel scans, real-time prioritization analytics, automated rescanning, and advanced reporting dashboards."
        }
    ];

    const [open, setOpen] = useState<number | null>(0);

    return (
        <div className="max-w-4xl mx-auto mt-20 px-4 space-y-4">

            {items.map((item, index) => {
                const isOpen = open === index;

                return (
                    <div
                        key={index}
                        className="
                            rounded-xl overflow-hidden
                            border border-[var(--border-2)]
                            bg-[var(--surface-2)]
                            shadow-[0_0_20px_rgba(0,0,0,0.3)]
                        "
                    >
                        <button
                            className="
                                w-full flex justify-between items-center
                                px-5 py-4 text-left
                                text-lg font-semibold
                                text-[var(--samsec-blue)]
                                hover:bg-[var(--surface-3)]
                                transition
                            "
                            onClick={() => setOpen(isOpen ? null : index)}
                        >
                            {item.title}

                            <ChevronDown
                                className={`
                                    w-5 h-5 transition-transform
                                    text-[var(--text-3)]
                                    ${isOpen ? "rotate-180" : ""}
                                `}
                            />
                        </button>

                        <div
                            className={`
                                transition-all duration-300 overflow-hidden
                                ${isOpen ? "max-h-[300px] p-5" : "max-h-0 p-0"}
                            `}
                        >
                            <p className="text-[var(--text-3)] text-sm leading-relaxed">
                                {item.content}
                            </p>
                        </div>
                    </div>
                );
            })}
        </div>
    );
}
