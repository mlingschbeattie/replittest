import { Link, useLocation } from "wouter";
import { useHealthCheck, getHealthCheckQueryKey } from "@workspace/api-client-react";
import { Activity, ShieldAlert, FileText, Search, Hash, LayoutDashboard, Terminal } from "lucide-react";
import { useEffect, useState } from "react";

const NAV_ITEMS = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/scanner", label: "Vulnerability Scanner", icon: ShieldAlert },
  { href: "/packets", label: "Packet Visualizer", icon: Activity },
  { href: "/logs", label: "Log Analyzer", icon: FileText },
  { href: "/cve", label: "CVE Lookup", icon: Search },
  { href: "/hash", label: "Hash Identifier", icon: Hash },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { data: health, isError } = useHealthCheck({
    query: { refetchInterval: 30000, queryKey: getHealthCheckQueryKey() },
  });
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const isHealthy = health?.status === "ok";

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground font-sans">
      {/* Top Bar */}
      <header className="h-14 border-b border-border flex items-center justify-between px-4 shrink-0 bg-card z-10">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-primary font-bold tracking-wider">
            <Terminal className="w-5 h-5" />
            <span>SENTINEL // LAB</span>
          </div>
        </div>
        <div className="flex items-center gap-6 font-mono text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${isError ? 'bg-destructive' : isHealthy ? 'bg-primary shadow-[0_0_8px_hsl(var(--primary))]' : 'bg-muted'}`} />
            <span>SYS_STATUS: {isError ? 'ERR' : isHealthy ? 'ONLINE' : 'CONNECTING'}</span>
          </div>
          <div>
            {time.toISOString().replace('T', ' ').slice(0, 19)}Z
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden relative">
        <div className="absolute inset-0 scanline pointer-events-none z-0 opacity-20" />
        
        {/* Sidebar */}
        <aside className="w-64 border-r border-border bg-card flex flex-col z-10 shrink-0 hidden md:flex">
          <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
            <div className="text-xs font-mono text-muted-foreground mb-4 uppercase tracking-widest">Modules</div>
            {NAV_ITEMS.map((item) => {
              const active = location === item.href;
              const Icon = item.icon;
              return (
                <Link key={item.href} href={item.href} className={`flex items-center gap-3 px-3 py-2 rounded-md transition-colors text-sm font-mono ${active ? 'bg-primary/10 text-primary border border-primary/30 shadow-[inset_0_0_10px_rgba(0,255,255,0.1)]' : 'text-muted-foreground hover:bg-muted hover:text-foreground'}`}>
                  <Icon className="w-4 h-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <div className="p-4 border-t border-border">
            <div className="text-xs font-mono text-muted-foreground flex items-center justify-between">
              <span>MODE: LAB</span>
              <span className="text-primary animate-pulse">● REC</span>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto z-10 p-6">
          <div className="max-w-6xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
