"use client";
import { useState } from "react";
import { Eye, EyeOff } from "lucide-react";

export default function PasswordInput({ placeholder }: { placeholder: string }) {
    const [show, setShow] = useState(false);

    return (
        <div className="relative">
            <input
                type={show ? "text" : "password"}
                placeholder={placeholder}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 pr-10"
            />

            <button
                type="button"
                onClick={() => setShow(!show)}
                className="absolute right-3 top-2.5 text-slate-400 hover:text-white"
            >
                {show ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
        </div>
    );
}
