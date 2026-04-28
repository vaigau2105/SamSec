"use client";

import { useState, useEffect, useRef, useMemo } from "react";

// ─── PACKET GENERATOR (Adapted from HTML) ──────────────────────────────
const PRIVATE_IPS = ["192.168.1.1", "192.168.1.2", "192.168.1.5", "10.0.0.1", "172.16.0.1"];
const PUBLIC_IPS = ["8.8.8.8", "1.1.1.1", "104.16.133.229", "142.250.80.46", "52.84.12.12"];
const DNS_QUERIES = ["google.com", "github.com", "api.stripe.com", "cloudflare.com"];
const HTTP_PATHS = ["GET /api/v1/users HTTP/1.1", "POST /auth/login HTTP/1.1", "GET /health HTTP/1.1"];
const TLS_TYPES = ["Client Hello (TLSv1.3)", "Application Data [encrypted]", "Server Hello (TLSv1.3)"];
const MAC_POOL = ["00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF", "DE:AD:BE:EF:CA:FE"];

const randItem = (arr: any[]) => arr[Math.floor(Math.random() * arr.length)];
const randInt = (a: number, b: number) => Math.floor(Math.random() * (b - a + 1)) + a;
const randPort = () => (Math.random() < 0.4 ? randItem([80, 443, 53, 22]) : randInt(1024, 65535));

export interface Packet {
    id: number;
    time: string;
    srcIp: string;
    dstIp: string;
    srcMac: string;
    dstMac: string;
    proto: string;
    srcPort: number;
    dstPort: number;
    info: string;
    length: number;
    flags: string;
    rawBytes: number[];
    ipv: number;
    ttl: number;
    checksum: string;
}

// ─── MAIN COMPONENT ──────────────────────────────────────────────────────────
export default function PacketAnalyzerPage() {
    const [packets, setPackets] = useState<Packet[]>([]);
    const [isCapturing, setIsCapturing] = useState(false);
    const [filterText, setFilterText] = useState("");
    const [selectedPkt, setSelectedPkt] = useState<Packet | null>(null);

    const pktCounter = useRef(0);
    const startTime = useRef<number | null>(null);
    const tableRef = useRef<HTMLDivElement>(null);

    // ── Generate a single packet ──
    const generatePacket = (): Packet => {
        pktCounter.current += 1;
        if (!startTime.current) startTime.current = performance.now();
        const elapsed = ((performance.now() - startTime.current) / 1000).toFixed(4);

        const ipv = Math.random() < 0.9 ? 4 : 6;
        const srcPrivate = Math.random() < 0.6;
        let srcIp = srcPrivate ? randItem(PRIVATE_IPS) : randItem(PUBLIC_IPS);
        let dstIp = srcPrivate ? randItem(PUBLIC_IPS) : randItem(PRIVATE_IPS);
        if (ipv === 6) {
            srcIp = "fe80::1ff:fe23:4567:890a";
            dstIp = "2001:4860:4860::8888";
        }

        const roll = Math.random();
        let proto = "TCP", srcPort = randPort(), dstPort = randPort(), info = "", length = 64, flags = "";

        if (roll < 0.1) {
            proto = "DNS"; dstPort = 53;
            info = `Standard query A ${randItem(DNS_QUERIES)}`; length = randInt(60, 120);
        } else if (roll < 0.15) {
            proto = "ARP"; srcPort = 0; dstPort = 0;
            info = `Who has ${randItem(PRIVATE_IPS)}? Tell ${srcIp}`; length = 42;
        } else if (roll < 0.25) {
            proto = "TLS"; dstPort = 443;
            info = randItem(TLS_TYPES); length = randInt(100, 1500);
        } else if (roll < 0.35) {
            proto = "HTTP"; dstPort = 80;
            info = randItem(HTTP_PATHS); length = randInt(200, 1400);
        } else {
            flags = randItem(["[SYN]", "[SYN, ACK]", "[ACK]", "[PSH, ACK]"]);
            info = `${srcPort} → ${dstPort} ${flags} Seq=${randInt(1e5, 1e6)} Len=${randInt(0, 1460)}`;
            length = randInt(54, 1514);
        }

        const rawBytes = Array.from({ length: Math.min(length, 128) }, () => randInt(0, 255));

        return {
            id: pktCounter.current, time: elapsed, srcIp, dstIp, srcMac: randItem(MAC_POOL), dstMac: randItem(MAC_POOL),
            proto, srcPort, dstPort, info, length, flags, rawBytes, ipv, ttl: randInt(32, 128),
            checksum: "0x" + randInt(0, 0xffff).toString(16).padStart(4, "0")
        };
    };

    // ── Capture Loop ──
    useEffect(() => {
        if (!isCapturing) return;
        const interval = setInterval(() => {
            const burst = randInt(1, 4);
            const newPkts = Array.from({ length: burst }, generatePacket);
            
            setPackets((prev) => {
                const updated = [...prev, ...newPkts];
                // Keep memory clean, limit to last 1000 packets
                return updated.length > 1000 ? updated.slice(updated.length - 1000) : updated;
            });
            
            // Auto-scroll
            if (tableRef.current) {
                const { scrollTop, scrollHeight, clientHeight } = tableRef.current;
                if (scrollHeight - scrollTop - clientHeight < 100) {
                    tableRef.current.scrollTop = scrollHeight;
                }
            }
        }, 300);
        return () => clearInterval(interval);
    }, [isCapturing]);

    // ── Filtering ──
    const filteredPackets = useMemo(() => {
        if (!filterText) return packets;
        const f = filterText.toLowerCase();
        return packets.filter(p => 
            p.proto.toLowerCase().includes(f) || 
            p.srcIp.includes(f) || 
            p.dstIp.includes(f) || 
            p.info.toLowerCase().includes(f)
        );
    }, [packets, filterText]);

    // ── Render Helpers ──
    const getBadgeColor = (proto: string) => {
        const map: Record<string, string> = {
            TCP: "bg-blue-500/10 text-blue-400 border-blue-500/30",
            UDP: "bg-green-500/10 text-green-400 border-green-500/30",
            DNS: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
            HTTP: "bg-teal-500/10 text-teal-400 border-teal-500/30",
            TLS: "bg-purple-500/10 text-purple-400 border-purple-500/30",
            ARP: "bg-red-500/10 text-red-400 border-red-500/30",
        };
        return map[proto] || "bg-slate-500/10 text-slate-400 border-slate-500/30";
    };

    return (
        <main className="min-h-screen bg-[var(--surface-1-gradient)] text-[var(--text-1)] pb-10">
            
            {/* Header matches Dashboard */}
            <div className="bg-[rgba(255,255,255,0.03)] backdrop-blur-xl border-b border-[var(--border-1)] px-6 py-6 shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
                <div className="page-container flex justify-between items-center">
                    <div>
                        <h1 className="text-3xl font-bold text-[var(--samsec-aqua)] drop-shadow-[0_0_8px_var(--samsec-glow-1)] flex items-center gap-3">
                            <span className={`w-3 h-3 rounded-full ${isCapturing ? "bg-red-500 shadow-[0_0_10px_red] animate-pulse" : "bg-slate-500"}`}></span>
                            Live Packet Analyzer
                        </h1>
                        <p className="text-slate-400 mt-1">Monitor and filter real-time network traffic</p>
                    </div>
                    <div className="flex gap-3">
                        <button 
                            onClick={() => setIsCapturing(!isCapturing)}
                            className={`btn ${isCapturing ? "bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/50" : "btn-primary"}`}
                        >
                            {isCapturing ? "■ Stop Capture" : "▶ Start Capture"}
                        </button>
                        <button 
                            onClick={() => { setPackets([]); setSelectedPkt(null); pktCounter.current = 0; startTime.current = null; }}
                            className="btn btn-ghost border border-slate-700 hover:bg-slate-800"
                        >
                            ⟳ Clear
                        </button>
                    </div>
                </div>
            </div>

            <div className="page-container mt-6">
                
                {/* Stats & Filter Bar */}
                <div className="app-card p-4 mb-6 border border-[rgba(255,255,255,0.06)] flex gap-6 items-center">
                    <div className="flex-1 flex items-center gap-3">
                        <span className="text-xs font-bold text-slate-500 tracking-wider">FILTER</span>
                        <input 
                            type="text" 
                            placeholder="e.g. tcp, 192.168.1.1, dns..."
                            value={filterText}
                            onChange={(e) => setFilterText(e.target.value)}
                            className="flex-1 bg-black/30 border border-[rgba(255,255,255,0.1)] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[var(--samsec-aqua)] transition"
                        />
                    </div>
                    <div className="hidden md:flex gap-4 text-sm">
                        <div>Total: <span className="text-white font-bold">{packets.length}</span></div>
                        <div>Shown: <span className="text-[var(--samsec-aqua)] font-bold">{filteredPackets.length}</span></div>
                    </div>
                </div>

                {/* Main Split Layout */}
                <div className="grid lg:grid-cols-3 gap-6 h-[600px]">
                    
                    {/* Packet Table (Takes up 2/3 width) */}
                    <div className="lg:col-span-2 app-card border border-[rgba(255,255,255,0.06)] flex flex-col overflow-hidden">
                        <div className="bg-[rgba(255,255,255,0.03)] border-b border-[rgba(255,255,255,0.05)] px-4 py-2 flex text-xs font-bold text-slate-400 tracking-wider uppercase">
                            <div className="w-12">No.</div>
                            <div className="w-20">Time</div>
                            <div className="w-32">Source</div>
                            <div className="w-32">Dest</div>
                            <div className="w-20">Proto</div>
                            <div className="flex-1">Info</div>
                        </div>
                        
                        <div ref={tableRef} className="flex-1 overflow-y-auto font-mono text-xs">
                            {filteredPackets.length === 0 ? (
                                <div className="p-10 text-center text-slate-500">No packets captured or matching filter.</div>
                            ) : (
                                filteredPackets.map((pkt) => (
                                    <div 
                                        key={pkt.id} 
                                        onClick={() => setSelectedPkt(pkt)}
                                        className={`
                                            flex px-4 py-1.5 border-b border-[rgba(255,255,255,0.02)] cursor-pointer transition
                                            ${selectedPkt?.id === pkt.id ? "bg-[var(--samsec-aqua)]/10 border-[var(--samsec-aqua)]/30" : "hover:bg-white/5"}
                                        `}
                                    >
                                        <div className="w-12 text-slate-500">{pkt.id}</div>
                                        <div className="w-20 text-slate-400">{pkt.time}</div>
                                        <div className="w-32 truncate pr-2 text-slate-300">{pkt.srcIp}</div>
                                        <div className="w-32 truncate pr-2 text-slate-300">{pkt.dstIp}</div>
                                        <div className="w-20">
                                            <span className={`px-2 py-0.5 rounded text-[10px] border ${getBadgeColor(pkt.proto)}`}>
                                                {pkt.proto}
                                            </span>
                                        </div>
                                        <div className="flex-1 truncate text-slate-400">{pkt.info}</div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>

                    {/* Inspector / Hex Dump (Takes up 1/3 width) */}
                    <div className="app-card border border-[rgba(255,255,255,0.06)] flex flex-col overflow-hidden bg-black/20">
                        <div className="bg-[rgba(255,255,255,0.03)] border-b border-[rgba(255,255,255,0.05)] px-4 py-2 text-xs font-bold text-[var(--samsec-teal)] tracking-wider uppercase">
                            Packet Inspector {selectedPkt && `#${selectedPkt.id}`}
                        </div>
                        
                        <div className="flex-1 overflow-y-auto p-4 font-mono text-xs text-slate-300">
                            {!selectedPkt ? (
                                <div className="text-center text-slate-500 mt-20">
                                    <div className="text-4xl mb-2">⬡</div>
                                    Select a packet to inspect
                                </div>
                            ) : (
                                <div className="space-y-6">
                                    {/* Meta Data */}
                                    <div>
                                        <h3 className="text-white font-bold mb-2 border-b border-slate-700 pb-1">IPv{selectedPkt.ipv} Header</h3>
                                        <div className="grid grid-cols-3 gap-2 text-slate-400 mb-1"><span className="col-span-1">Source:</span><span className="col-span-2 text-[var(--samsec-aqua)]">{selectedPkt.srcIp}</span></div>
                                        <div className="grid grid-cols-3 gap-2 text-slate-400 mb-1"><span className="col-span-1">Dest:</span><span className="col-span-2 text-[var(--samsec-aqua)]">{selectedPkt.dstIp}</span></div>
                                        <div className="grid grid-cols-3 gap-2 text-slate-400 mb-1"><span className="col-span-1">Length:</span><span className="col-span-2">{selectedPkt.length} bytes</span></div>
                                        <div className="grid grid-cols-3 gap-2 text-slate-400"><span className="col-span-1">Checksum:</span><span className="col-span-2 text-yellow-400">{selectedPkt.checksum}</span></div>
                                    </div>

                                    {/* Hex Dump */}
                                    <div>
                                        <h3 className="text-white font-bold mb-2 border-b border-slate-700 pb-1">Hex Dump</h3>
                                        <div className="space-y-1">
                                            {Array.from({ length: Math.ceil(selectedPkt.rawBytes.length / 8) }).map((_, i) => {
                                                const chunk = selectedPkt.rawBytes.slice(i * 8, (i + 1) * 8);
                                                const hex = chunk.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
                                                const ascii = chunk.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
                                                return (
                                                    <div key={i} className="flex gap-4">
                                                        <span className="text-slate-600 w-8">{(i * 8).toString(16).padStart(4, '0')}</span>
                                                        <span className="text-blue-400 w-32 tracking-widest">{hex}</span>
                                                        <span className="text-slate-400">{ascii}</span>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                </div>
            </div>
        </main>
    );
}