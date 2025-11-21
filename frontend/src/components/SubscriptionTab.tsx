export default function SubscriptionTab() {
    return (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-8 space-y-10">

            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-lg font-semibold">Professional Plan</h2>
                    <p className="text-slate-400">Up to 1,000 parallel scans</p>
                </div>
                <div className="text-right">
                    <p className="text-3xl font-bold">$99/month</p>
                    <p className="text-slate-400 text-sm">Next billing: Jan 15, 2024</p>
                </div>
            </div>

            {/* Usage */}
            <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-slate-700 rounded-lg p-6">
                    <h3 className="font-semibold mb-3">Usage This Month</h3>
                    <p>Scans Performed: <span className="font-bold">1,247</span></p>
                    <p>Targets Scanned: <span className="font-bold">89</span></p>
                    <p>Reports Generated: <span className="font-bold">34</span></p>
                </div>

                <div className="bg-slate-700 rounded-lg p-6">
                    <h3 className="font-semibold mb-3">Plan Limits</h3>
                    <p>Max Parallel Scans: 1,000</p>
                    <p>Max Targets: Unlimited</p>
                    <p>API Access: <span className="text-green-400 font-bold">✔ Included</span></p>
                </div>
            </div>

            <div className="flex gap-4">
                <button className="bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg font-semibold">
                    Upgrade Plan
                </button>
                <button className="bg-slate-600 hover:bg-slate-700 px-6 py-3 rounded-lg font-semibold">
                    Download Invoice
                </button>
            </div>
        </div>
    );
}
