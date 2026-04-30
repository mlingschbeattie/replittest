import { useState } from "react";
import { useRunScan } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ShieldAlert, Play, Globe, Activity, Clock, Info } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function Scanner() {
  const [url, setUrl] = useState("");
  const { mutate: runScan, data: result, isPending, error } = useRunScan();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    runScan({ data: { url } });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Passive Scanner</h1>
        <p className="text-muted-foreground mt-1 font-mono text-sm">Read-only HTTP header and misconfiguration analysis</p>
      </div>

      <Alert className="bg-primary/10 border-primary/30 text-primary">
        <Info className="h-4 w-4 text-primary" />
        <AlertTitle className="font-mono uppercase">Lab Mode Notice</AlertTitle>
        <AlertDescription className="font-mono text-xs">
          This scanner performs passive analysis only. It does not exploit vulnerabilities, inject payloads, or perform aggressive crawling.
        </AlertDescription>
      </Alert>

      <Card className="bg-card/50 backdrop-blur border-border">
        <CardContent className="pt-6">
          <form onSubmit={handleSubmit} className="flex gap-4">
            <Input 
              placeholder="https://target.local" 
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="font-mono bg-muted/50 border-border focus-visible:ring-primary"
            />
            <Button type="submit" disabled={isPending || !url} className="font-mono uppercase tracking-wider bg-primary text-primary-foreground hover:bg-primary/90">
              {isPending ? <Activity className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
              Run Scan
            </Button>
          </form>
          {error && (() => {
            const e = error as unknown as { error?: string; detail?: string; message?: string };
            const msg = e?.error ?? e?.message ?? "Scan failed";
            return (
              <div className="mt-4 p-3 bg-destructive/20 border border-destructive/50 text-destructive font-mono text-sm rounded">
                ERROR: {msg}{e?.detail ? ` - ${e.detail}` : ""}
              </div>
            );
          })()}
        </CardContent>
      </Card>

      {result && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="bg-card/50 border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase">Target</CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm truncate flex items-center gap-2">
                <Globe className="w-4 h-4 text-primary shrink-0" />
                {result.finalUrl || result.target}
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase">Status</CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm">
                <span className={result.statusCode && result.statusCode < 400 ? 'text-primary' : 'text-destructive'}>
                  HTTP {result.statusCode || 'N/A'}
                </span>
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase">Duration</CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm flex items-center gap-2 text-primary">
                <Clock className="w-4 h-4" />
                {result.durationMs}ms
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase">Findings</CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm flex gap-2">
                {result.summary.critical > 0 && <span className="text-destructive font-bold">{result.summary.critical} CRIT</span>}
                {result.summary.high > 0 && <span className="text-[hsl(var(--color-severity-high))]">{result.summary.high} HIGH</span>}
                {result.summary.critical === 0 && result.summary.high === 0 && <span className="text-primary">NO CRIT/HIGH</span>}
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="lg:col-span-2 bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase">Scan Findings</CardTitle>
              </CardHeader>
              <CardContent>
                {result.findings.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border hover:bg-transparent">
                        <TableHead className="font-mono uppercase text-xs">Severity</TableHead>
                        <TableHead className="font-mono uppercase text-xs">Title</TableHead>
                        <TableHead className="font-mono uppercase text-xs hidden md:table-cell">Category</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {result.findings.map((f) => (
                        <TableRow key={f.id} className="border-border hover:bg-muted/50 transition-colors cursor-default">
                          <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                          <TableCell className="font-mono text-sm">{f.title}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground hidden md:table-cell">{f.category}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <div className="text-center py-8 text-primary font-mono text-sm">NO FINDINGS REPORTED</div>
                )}
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase">Headers</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 bg-muted/30 p-3 rounded border border-border/50 max-h-[400px] overflow-y-auto">
                  {result.headers ? Object.entries(result.headers).map(([k, v]) => (
                    <div key={k} className="text-xs font-mono break-all">
                      <span className="text-primary">{k}:</span> <span className="text-muted-foreground">{v}</span>
                    </div>
                  )) : <div className="text-muted-foreground text-xs font-mono">No headers captured.</div>}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
