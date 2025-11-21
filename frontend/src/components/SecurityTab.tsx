export default function SecurityTab() {
    return (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-8 space-y-10">

            <div>
                <h2 className="text-lg font-semibold mb-6">Security Settings</h2>
                <div className="grid md:grid-cols-2 gap-6">
                    <div>
                        <label className="block text-sm mb-2">Current Password</label>
                        <input type="password" className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2" />
                    </div>
                    <div>
                        <label className="block text-sm mb-2">New Password</label>
                        <input type="password" className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2" />
                    </div>
                    <div>
                        <label className="block text-sm mb-2">Confirm New Password</label>
                        <input type="password" className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2" />
                    </div>
                </div>

                <button className="mt-6 bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg font-semibold">
                    Change Password
                </button>
            </div>

            <div>
                <h3 className="text-lg font-semibold">Two-Factor Authentication</h3>
                <p className="text-slate-400 text-sm mb-4">
                    Secure your account with 2FA. Add an extra layer of security to your account.
                </p>
                <button className="bg-green-600 hover:bg-green-700 px-6 py-2 rounded-lg font-semibold">
                    Enable 2FA
                </button>
            </div>
        </div>
    );
}
