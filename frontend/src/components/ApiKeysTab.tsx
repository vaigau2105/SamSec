export default function ApiKeysTab() {
    return (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-8 space-y-8">

            <h2 className="text-lg font-semibold">API Key Management</h2>

            {/* Production Key */}
            <div className="bg-slate-700 rounded-lg p-6 flex justify-between items-center">
                <div>
                    <p className="font-semibold">Production API Key</p>
                    <p className="text-slate-400 text-sm">Created: Dec 1, 2023 · Last used: 2 hours ago</p>
                    <p className="bg-slate-900 mt-2 px-3 py-2 rounded-lg font-mono">sk_prod_abc123...xyz789</p>
                </div>
                <div className="flex gap-3">
                    <button className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg">Copy</button>
                    <button className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg">Revoke</button>
                </div>
            </div>

            {/* Development Key */}
            <div className="bg-slate-700 rounded-lg p-6 flex justify-between items-center">
                <div>
                    <p className="font-semibold">Development API Key</p>
                    <p className="text-slate-400 text-sm">Created: Nov 15, 2023 · Last used: 1 day ago</p>
                    <p className="bg-slate-900 mt-2 px-3 py-2 rounded-lg font-mono">sk_dev_def456...uvw012</p>
                </div>
                <div className="flex gap-3">
                    <button className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg">Copy</button>
                    <button className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg">Revoke</button>
                </div>
            </div>

            <button className="bg-green-600 hover:bg-green-700 px-6 py-3 rounded-lg font-semibold">
                Generate New API Key
            </button>

            <div className="bg-slate-700 rounded-lg p-6">
                <h3 className="font-semibold mb-2">API Documentation</h3>
                <p className="text-slate-400 text-sm mb-3">
                    Learn how to integrate SamSec into your workflow
                </p>
                <button className="text-blue-400 hover:text-blue-500">
                    View API Documentation →
                </button>
            </div>

        </div>
    );
}
