// src/app/account/components/AccountActions.tsx
export default function AccountActions() {
    return (
        <div className="account-action">
            <h3 className="text-red-400 font-semibold mb-2">Account Actions</h3>

            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <p className="text-slate-300">Sign out of your SamSec account</p>
                    <p className="text-sm text-slate-400">You'll need to log in again to access your dashboard</p>
                </div>

                <div>
                    <button className="btn btn-danger">Logout</button>
                </div>
            </div>
        </div>
    );
}
