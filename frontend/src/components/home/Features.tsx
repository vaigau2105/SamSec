export default function Features() {
    const features = [
        ["📊", "Detailed Reporting", "Comprehensive vulnerability reports with remediation guidance."],
        ["🎯", "Severity Prioritization", "Focus on the most critical vulnerabilities first."],
        ["🌐", "Multi-Target Scanning", "Scan multiple hosts and apps in a unified dashboard."],
        ["📈", "Progress Tracking", "Monitor security improvements with analytics."],
        ["🔄", "Automated Rescanning", "Continuous security verification."],
        ["👥", "Team Collaboration", "Share reports and work with your team."],
    ];

    return (
        <section className="py-24 bg-[var(--surface-1-gradient)] border-t border-[rgba(255,255,255,0.05)]">

            {/* Header */}
            <h2
                className="
                    text-4xl md:text-5xl font-extrabold text-center mb-16
                    text-[var(--samsec-aqua)]
                    drop-shadow-[0_0_15px_var(--samsec-glow-1)]
                "
            >
                Platform Features
            </h2>

            {/* Cards */}
            <div className="max-w-7xl mx-auto grid md:grid-cols-2 lg:grid-cols-3 gap-10 px-4">
                {features.map(([icon, title, desc]) => (
                    <div
                        key={title}
                        className="
                            relative group rounded-2xl p-[2px]
                            bg-gradient-to-br
                            from-[var(--samsec-aqua)]
                            via-[var(--samsec-blue)]
                            to-[var(--samsec-teal)]
                            transition-all duration-300
                            hover:scale-[1.04]
                            hover:shadow-[0_0_35px_var(--samsec-glow-2)]
                        "
                    >
                        {/* Inner Card */}
                        <div
                            className="
                                bg-[var(--surface-2)] rounded-2xl p-6 h-full
                                shadow-[0_0_20px_rgba(0,0,0,0.45)]
                                transition-all duration-300
                                group-hover:bg-[#0d1524]
                            "
                        >
                            <div className="text-5xl mb-4 drop-shadow-[0_0_10px_var(--samsec-glow-2)]">
                                {icon}
                            </div>

                            <h3 className="text-xl font-bold mb-2 text-white">
                                {title}
                            </h3>

                            <p className="text-slate-300 text-sm leading-relaxed">
                                {desc}
                            </p>
                        </div>
                    </div>
                ))}
            </div>
        </section>
    );
}
