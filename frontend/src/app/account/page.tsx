// src/app/account/page.tsx
"use client";

import { useState } from "react";
import AccountTabs from "../../components/AccountTabs";
import ProfileTab from "../../components/ProfileTab";
import SecurityTab from "../../components/SecurityTab";
{/*import SubscriptionTab from "../../components/SubscriptionTab";
import ApiKeysTab from "../../components/ApiKeysTab";*/}
import AccountActions from "../../components/AccountActions";

export default function AccountPage() {
    const [activeTab, setActiveTab] = useState("profile");

    const renderTab = () => {
        switch (activeTab) {
            case "profile":
                return <ProfileTab />;
            case "security":
                return <SecurityTab />;
            {/*case "subscription":
                return <SubscriptionTab />;
            case "api-keys":
                return <ApiKeysTab />;*/}
            default:
                return <ProfileTab />;
        }
    };

    return (
        <main
            className="
                min-h-screen
                bg-[var(--surface-1-gradient)]
                text-[var(--text-1)]
            "
        >
            {/* HEADER */}
            <div
                className="
                    bg-[rgba(255,255,255,0.03)]
                    backdrop-blur-xl
                    border-b border-[var(--border-1)]
                    shadow-[0_6px_20px_rgba(0,0,0,0.25)]
                    py-8
                "
            >
                <div className="page-container">
                    <h1
                        className="
                            text-3xl font-bold
                            text-[var(--accent-2)]
                        "
                    >
                        Account Management
                    </h1>

                    <p className="text-[var(--text-3)] text-sm mt-1">
                        Manage your profile, security, and subscription settings
                    </p>
                </div>
            </div>

            {/* BODY CONTENT */}
            <div className="page-container mt-10">

                {/* TABS */}
                <div className="mb-4">
                    <AccountTabs
                        activeTab={activeTab}
                        setActiveTab={setActiveTab}
                    />
                </div>

                {/* MAIN CARD */}
                <div
                    className="
                        app-card
                        border-[var(--border-1)]
                        shadow-[0_4px_16px_rgba(0,0,0,0.25)]
                        p-0
                    "
                >
                    <div className="p-6">
                        {renderTab()}
                    </div>
                </div>

                {/* ACCOUNT ACTIONS */}
                <div className="mt-10">
                    <AccountActions />
                </div>

            </div>
        </main>
    );
}
