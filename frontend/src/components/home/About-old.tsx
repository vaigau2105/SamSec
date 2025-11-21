export default function About() {
    return (
        <section className="bg-slate-900 py-20">
            <h2 className="text-4xl font-bold text-center mb-16">About the Project</h2>

            <div className="max-w-4xl mx-auto text-slate-300 space-y-6 px-4">
                <p>
                    SamSec is a high-performance vulnerability scanner designed for security professionals, developers, and organizations who need to manage security across multiple web applications and infrastructure targets at scale.
                </p>
                <p>
                    Our platform can scan up to 1,000 assets simultaneously, delivering comprehensive security reports within minutes. With intelligent vulnerability prioritization, automated scheduling, and advanced remediation tracking, SamSec helps you maintain enterprise-grade security posture efficiently.
                </p>
                <p>
                    Built for speed and scale, SamSec offers parallel scanning capabilities, detailed reporting, team collaboration features, and API integration to seamlessly fit into your existing security workflow.
                </p>
            </div>
        </section>
    );
}
