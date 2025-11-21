// src/app/layout.tsx
// @ts-ignore - allow importing global CSS without type declarations
import "./globals.css";
import type { ReactNode } from "react";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";

export const metadata = {
    title: "SamSec",
    description: "High-Speed Multi-Target Web Vulnerability Scanner",
};

export default function RootLayout({ children }: { children: ReactNode }) {
    return (
        <html lang="en">
            <body className="bg-slate-900 text-white min-h-screen flex flex-col" suppressHydrationWarning>
                <Navbar />
                <div className="flex-1">
                    {/* page content */}
                    {children}
                </div>
                <Footer />
            </body>
        </html>
    );
}
