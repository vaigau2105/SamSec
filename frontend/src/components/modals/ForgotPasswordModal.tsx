"use client";

import ModalBase from "./ModalBase";

export default function ForgotPasswordModal({ open, onClose }: any) {
    return (
        <ModalBase open={open} onClose={onClose} width="max-w-sm">
            <h2 className="text-xl font-semibold mb-4">Reset Password</h2>
            <p className="text-slate-400 text-sm mb-4">
                Enter your email address and we'll send you a password reset link.
            </p>

            <input
                placeholder="you@example.com"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 mb-4"
            />

            <button className="btn btn-primary w-full">Send Reset Link</button>

            <button
                className="text-slate-400 text-sm mt-3 hover:text-white"
                onClick={onClose}
            >
                Cancel
            </button>
        </ModalBase>
    );
}
