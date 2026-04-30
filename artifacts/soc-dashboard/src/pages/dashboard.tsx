import { useGetStats, getGetStatsQueryKey } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ShieldAlert, Search, Hash, AlertTriangle, Activity, FileText } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { Link } from "wouter";

export default function Dashboard() {
  const { data: stats, isLoading } = useGetStats({
    query: { queryKey: getGetStatsQueryKey(), refetchInterval: 10000 },
  });

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-primary font-mono"><Activity className="w-6 h-6 animate-spin mr-2"/> INITIALIZING...</div>;
  }

  if (!stats) return null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Overview</h1>
        <p className="text-muted-foreground mt-1 font-mono text-sm">System telemetry and recent activity</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-card/50 backdrop-blur border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium font-mono text-muted-foreground uppercase">Scans Run</CardTitle>
            <ShieldAlert className="w-4 h-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-primary">{stats.scansRun}</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 backdrop-blur border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium font-mono text-muted-foreground uppercase">CVE Lookups</CardTitle>
            <Search className="w-4 h-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-primary">{stats.cveLookups}</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 backdrop-blur border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium font-mono text-muted-foreground uppercase">Hash Checks</CardTitle>
            <Hash className="w-4 h-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-primary">{stats.hashChecks}</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 backdrop-blur border-destructive/30">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium font-mono text-destructive uppercase">Critical Finds</CardTitle>
            <AlertTriangle className="w-4 h-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-destructive">{stats.criticalFindings}</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 bg-card/50 backdrop-blur border-border">
          <CardHeader>
            <CardTitle className="font-mono text-lg uppercase tracking-wider">Recent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {stats.recentActivity.map((activity, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-muted/30 rounded border border-border/50">
                  <div className="flex items-center gap-4">
                    <span className="text-xs font-mono text-primary bg-primary/10 px-2 py-1 rounded border border-primary/20">{activity.kind}</span>
                    <span className="font-mono text-sm">{activity.label}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    {activity.severity && <SeverityBadge severity={activity.severity} />}
                    <span className="text-xs font-mono text-muted-foreground">{new Date(activity.at).toLocaleString()}</span>
                  </div>
                </div>
              ))}
              {stats.recentActivity.length === 0 && (
                <div className="text-center py-8 text-muted-foreground font-mono text-sm">NO RECENT ACTIVITY</div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/50 backdrop-blur border-border">
          <CardHeader>
            <CardTitle className="font-mono text-lg uppercase tracking-wider">Quick Launch</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Link href="/scanner" className="flex items-center gap-3 p-3 rounded bg-muted hover:bg-primary/20 hover:text-primary border border-transparent hover:border-primary/50 transition-all font-mono text-sm">
              <ShieldAlert className="w-4 h-4" /> Passive Scanner
            </Link>
            <Link href="/packets" className="flex items-center gap-3 p-3 rounded bg-muted hover:bg-primary/20 hover:text-primary border border-transparent hover:border-primary/50 transition-all font-mono text-sm">
              <Activity className="w-4 h-4" /> Packet Visualizer
            </Link>
            <Link href="/logs" className="flex items-center gap-3 p-3 rounded bg-muted hover:bg-primary/20 hover:text-primary border border-transparent hover:border-primary/50 transition-all font-mono text-sm">
              <FileText className="w-4 h-4" /> Log Analyzer
            </Link>
            <Link href="/cve" className="flex items-center gap-3 p-3 rounded bg-muted hover:bg-primary/20 hover:text-primary border border-transparent hover:border-primary/50 transition-all font-mono text-sm">
              <Search className="w-4 h-4" /> CVE Lookup
            </Link>
            <Link href="/hash" className="flex items-center gap-3 p-3 rounded bg-muted hover:bg-primary/20 hover:text-primary border border-transparent hover:border-primary/50 transition-all font-mono text-sm">
              <Hash className="w-4 h-4" /> Hash Identifier
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
