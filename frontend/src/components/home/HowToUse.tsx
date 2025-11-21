export default function HowToUse() {
    const steps = [
        ["1", "Add Your Targets", "Register your web apps, APIs, and infrastructure endpoints."],
        ["2", "Start Automated Scans", "Run vulnerability scans with intelligent prioritization."],
        ["3", "Prioritize & Remediate", "Review reports and fix issues with guided remediation steps."],
    ];

    return (
        <section className="py-24 bg-[var(--surface-1-gradient)] border-t border-[rgba(255,255,255,0.05)]">

            {/* HEADING */}
            <h2
                className="
                text-4xl md:text-5xl font-extrabold text-center mb-16
                text-[var(--samsec-aqua)]
                drop-shadow-[0_0_15px_var(--samsec-glow-1)]
            "
            >
                How SamSec Works
            </h2>

            {/* GRID */}
            <div className="
                max-w-6xl mx-auto grid md:grid-cols-3 gap-12 px-4
            ">
                {steps.map(([num, title, desc], i) => (
                    <div
                        key={title}
                        className="
                            relative group rounded-2xl p-[2px]
                            bg-gradient-to-br
                            from-[var(--samsec-aqua)]
                            via-[var(--samsec-blue)]
                            to-[var(--samsec-teal)]
                            hover:shadow-[0_0_35px_var(--samsec-glow-1)]
                            transition-all duration-300 hover:scale-[1.03]
                        "
                    >
                        {/* Inner Card */}
                        <div className="
                            rounded-2xl bg-[var(--surface-2)] p-8 text-center
                            shadow-[0_0_20px_rgba(0,0,0,0.45)]
                            transition duration-300 group-hover:bg-[#101722]
                        ">

                            {/* Step Number Dot */}
                            <div className="
                                w-20 h-20 mx-auto mb-6 rounded-full
                                flex items-center justify-center text-3xl font-extrabold
                                bg-gradient-to-br from-[var(--samsec-blue)] to-[var(--samsec-aqua)]
                                text-black drop-shadow-[0_0_12px_var(--samsec-glow-1)]
                                shadow-[0_0_25px_var(--samsec-glow-1)]
                                group-hover:shadow-[0_0_35px_var(--samsec-glow-2)]
                                transition
                            ">
                                {num}
                            </div>

                            {/* Title */}
                            <h3 className="text-xl font-bold text-white mb-3 drop-shadow-[0_0_6px_rgba(0,0,0,0.4)]">
                                {title}
                            </h3>

                            {/* Description */}
                            <p className="text-slate-300 leading-relaxed text-sm">
                                {desc}
                            </p>

                        </div>
                    </div>
                ))}
            </div>
        </section>
    );
}
