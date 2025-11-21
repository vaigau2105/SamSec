export default function ProfileTab() {
    return (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-8">
            <h2 className="text-lg font-semibold mb-6">Profile Information</h2>

            <div className="grid md:grid-cols-2 gap-6">
                <div>
                    <label className="block text-sm mb-2">Full Name</label>
                    <input className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2" />
                </div>

                <div>
                    <label className="block text-sm mb-2">Email Address</label>
                    <input className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2" />
                </div>

                <div>
                    <label className="block text-sm mb-2">Company</label>
                    <input className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2" />
                </div>

                <div>
                    <label className="block text-sm mb-2">Role</label>
                    <select className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2">
                        <option>Security Engineer</option>
                        <option>Developer</option>
                        <option>Analyst</option>
                        <option>Administrator</option>
                    </select>
                </div>
            </div>

            <button className="mt-8 bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg font-semibold">
                Update Profile
            </button>
        </div>
    );
}
