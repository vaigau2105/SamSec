interface Tab {
  id: string
  label: string
}

interface Props {
  activeTab: string
  setActiveTab: (tab: string) => void
}

const tabs: Tab[] = [
  { id: "profile", label: "Profile" },
  { id: "security", label: "Security" },
  // { id: "subscription", label: "Subscription" },
  // { id: "api-keys", label: "API Keys" },
]

export default function AccountTabs({ activeTab, setActiveTab }: Props) {
  return (
    <div className="flex gap-10 border-b border-[rgba(255,255,255,0.07)] pb-3">

      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => setActiveTab(tab.id)}
          className={`
            pb-2 font-semibold text-sm transition
            ${
              activeTab === tab.id
                ? "text-[var(--samsec-blue)] border-b-2 border-[var(--samsec-blue)]"
                : "text-[var(--text-3)] hover:text-[var(--text-1)]"
            }
          `}
        >
          {tab.label}
        </button>
      ))}
    </div>
  )
}
