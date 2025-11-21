"use client";
import { useEffect } from "react";

interface ModalBaseProps {
    open: boolean;
    onClose: () => void;
    children: React.ReactNode;
    width?: string;
}

export default function ModalBase({ open, onClose, children, width = "max-w-md" }: ModalBaseProps) {
    useEffect(() => {
        const handleEsc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
        window.addEventListener("keydown", handleEsc);
        return () => window.removeEventListener("keydown", handleEsc);
    }, [onClose]);

    if (!open) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-black/50 backdrop-blur-sm"
                onClick={onClose}
            />

            {/* Modal Card */}
            <div
                className={`relative z-10 w-full ${width} app-card p-6 animate-fade-in`}
            >
                {children}
            </div>
        </div>
    );
}
