import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { FileText, Download, Search, ExternalLink } from "lucide-react";
import { analyzeLogs, SAMPLE_APACHE_LOG, type LogFinding } from "@/lib/logs";
import { exportFindingsToCsv } from "@/lib/csv";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";

type AnalysisResult = ReturnType<typeof analyzeLogs>;

const CATEGORY_COLORS: Record<string, string> = {
  "brute-force": "text-orange-400 bg-orange-400/10 border-orange-400/30",
  "404-sweep": "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  "sqli": "text-destructive bg-destructive/10 border-destructive/30",
  "xss": "text-rose-400 bg-rose-400/10 border-rose-400/30",
  "path-traversal": "text-red-400 bg-red-400/10 border-red-400/30",
  "cmd-injection": "text-destructive bg-destructive/10 border-destructive/30",
  "unusual-ua": "text-amber-400 bg-amber-400/10 border-amber-400/30",
  "info": "text-primary bg-primary/10 border-primary/30",
};

const CATEGORY_LABELS: Record<string, string> = {
  "brute-force": "Brute Force",
  "404-sweep": "404 Sweep",
  "sqli": "SQLi",
  "xss": "XSS",
  "path-traversal": "Path Traversal",
  "cmd-injection": "Cmd Injection",
  "unusual-ua": "Suspicious UA",
  "info": "Info",
};

export default function Logs() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [filter, setFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const handleParse = () => {
    if (!input.trim()) return;
    setResult(analyzeLogs(input));
    setFilter("");
    setExpandedId(null);
  };

  const handleLoadSample = () => {
    setInput(SAMPLE_APACHE_LOG);
    setResult(analyzeLogs(SAMPLE_APACHE_LOG));
    setFilter("");
    setExpandedId(null);
  };

  const handleExport = () => {
    if (!result) return;
    const rows = filtered.map((f: LogFinding) => ({
      severity: f.severity,
      category: f.category,
      mitre_technique: f.mitre?.technique ?? "",
      mitre_tactic: f.mitre?.tactic ?? "",
      title: f.title,
      ip: f.ip ?? "",
      userAgent: f.userAgent ?? "",
      count: f.count,
      description: f.description,
      example: f.examples[0] ?? "",
    }));
    exportFindingsToCsv(rows, "log-findings.csv");
  };

  const filtered = useMemo(() => {
    const findings = result?.findings ?? [];
    if (!filter.trim()) return findings;
    const q = filter.toLowerCase();
    return findings.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q) ||
        (f.ip ?? "").toLowerCase().includes(q) ||
        (f.mitre?.technique ?? "").toLowerCase().includes(q) ||
        (f.mitre?.tactic ?? "").toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q),
    );
  }, [result, filter]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Log Analyzer</h1>
          <p className="text-muted-foreground mt-1 font-mono text-sm">Extract anomalies with MITRE ATT&CK mapping</p>
        </div>
        <Button
          variant="outline"
          onClick={handleLoadSample}
          className="font-mono text-xs border-primary/50 text-primary hover:bg-primary/10"
        >
          Load Sample
        </Button>
      </div>

      <Card className="bg-card/50 border-border">
        <CardContent className="pt-6 space-y-4">
          <Textarea
            placeholder="Paste Apache, Nginx, or Windows Event Logs here..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="font-mono text-xs min-h-[180px] bg-muted/50 border-border focus-visible:ring-primary"
          />
          <div className="flex items-center gap-4 flex-wrap">
            <Button
              onClick={handleParse}
              disabled={!input.trim()}
              className="font-mono uppercase bg-primary text-primary-foreground hover:bg-primary/90"
            >
              <FileText className="w-4 h-4 mr-2" />
              Analyze Logs
            </Button>
            {filtered.length > 0 && (
              <Button
                onClick={handleExport}
                variant="outline"
                className="font-mono uppercase border-primary/50 text-primary hover:bg-primary/10"
              >
                <Download className="w-4 h-4 mr-2" />
                Export CSV
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {result && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Lines", value: result.totalLines },
              { label: "Parsed", value: result.parsedLines },
              { label: "Findings", value: result.findings.length },
              { label: "Unique IPs", value: result.perIp.length },
            ].map((s) => (
              <Card key={s.label} className="bg-card/50 border-border">
                <CardContent className="pt-4 pb-4 font-mono text-xs">
                  <div className="text-muted-foreground uppercase">{s.label}</div>
                  <div className="text-2xl text-primary mt-1">{s.value}</div>
                </CardContent>
              </Card>
            ))}
          </div>

          {result.timeline.length > 0 && (
            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase">Request Timeline</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={result.timeline} barCategoryGap="20%">
                    <XAxis dataKey="label" tick={{ fontFamily: "monospace", fontSize: 9, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} />
                    <YAxis tick={{ fontFamily: "monospace", fontSize: 9, fill: "hsl(var(--muted-foreground))" }} tickLine={false} axisLine={false} width={24} />
                    <Tooltip
                      contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", fontFamily: "monospace", fontSize: 10 }}
                      labelStyle={{ color: "hsl(var(--foreground))" }}
                    />
                    <Bar dataKey="requests" name="Requests" radius={[2, 2, 0, 0]}>
                      {result.timeline.map((_, i) => (
                        <Cell key={i} fill="hsl(var(--primary))" fillOpacity={0.6} />
                      ))}
                    </Bar>
                    <Bar dataKey="errors" name="Errors (4xx/5xx)" radius={[2, 2, 0, 0]}>
                      {result.timeline.map((_, i) => (
                        <Cell key={i} fill="hsl(var(--destructive))" fillOpacity={0.8} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
                <div className="flex gap-4 justify-center mt-2 font-mono text-[10px] text-muted-foreground">
                  <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-primary/60 inline-block" /> Requests</span>
                  <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-destructive/80 inline-block" /> Errors 4xx/5xx</span>
                </div>
              </CardContent>
            </Card>
          )}

          {result.findings.length > 0 && (
            <Card className="bg-card/50 border-border animate-in fade-in duration-500">
              <CardHeader>
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <CardTitle className="font-mono text-sm uppercase">
                    Anomalies Detected ({filtered.length}{filter ? ` of ${result.findings.length}` : ""})
                  </CardTitle>
                  <div className="relative w-64">
                    <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                      placeholder="Filter by IP, category, ATT&CK..."
                      className="pl-8 h-8 font-mono text-xs bg-muted/50 border-border focus-visible:ring-primary"
                    />
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="font-mono uppercase text-xs w-[90px]">Severity</TableHead>
                      <TableHead className="font-mono uppercase text-xs w-[130px]">Category</TableHead>
                      <TableHead className="font-mono uppercase text-xs w-[130px]">Source</TableHead>
                      <TableHead className="font-mono uppercase text-xs w-[70px]">Count</TableHead>
                      <TableHead className="font-mono uppercase text-xs">Description</TableHead>
                      <TableHead className="font-mono uppercase text-xs w-[130px]">MITRE ATT&CK</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.map((f) => (
                      <>
                        <TableRow
                          key={f.id}
                          className="border-border hover:bg-muted/50 transition-colors cursor-pointer"
                          onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                        >
                          <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={`font-mono text-[10px] uppercase border ${CATEGORY_COLORS[f.category] ?? "text-muted-foreground"}`}
                            >
                              {CATEGORY_LABELS[f.category] ?? f.category}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-primary">
                            {f.ip ?? f.userAgent ?? "—"}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{f.count}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            <div>{f.title}</div>
                            <div className="text-[10px] mt-0.5 opacity-70">{f.description}</div>
                          </TableCell>
                          <TableCell>
                            {f.mitre && (
                              <a
                                href={`https://attack.mitre.org/techniques/${f.mitre.technique.replace(".", "/")}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                className="font-mono text-[10px] text-primary hover:underline flex items-start gap-1 leading-tight"
                              >
                                <ExternalLink className="w-2.5 h-2.5 mt-0.5 shrink-0" />
                                <span>
                                  <span className="block font-bold">{f.mitre.technique}</span>
                                  <span className="block text-muted-foreground">{f.mitre.name}</span>
                                  <span className="block text-muted-foreground opacity-70">{f.mitre.tactic}</span>
                                </span>
                              </a>
                            )}
                          </TableCell>
                        </TableRow>
                        {expandedId === f.id && f.examples.length > 0 && (
                          <TableRow key={`${f.id}-exp`} className="border-border bg-muted/20">
                            <TableCell colSpan={6} className="pt-0 pb-3 px-4">
                              <div className="text-xs font-mono text-muted-foreground mb-1.5 uppercase">Example log entries:</div>
                              <div className="space-y-1">
                                {f.examples.map((ex, i) => (
                                  <pre key={i} className="text-[10px] font-mono bg-muted/50 border border-border rounded px-2 py-1.5 whitespace-pre-wrap break-all text-foreground">
                                    {ex}
                                  </pre>
                                ))}
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </>
                    ))}
                    {filtered.length === 0 && filter && (
                      <TableRow>
                        <TableCell colSpan={6} className="text-center font-mono text-xs text-muted-foreground py-8">
                          No findings match "{filter}"
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {result.perIp.length > 0 && (
            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase">Top Source IPs</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="font-mono uppercase text-xs">IP</TableHead>
                      <TableHead className="font-mono uppercase text-xs w-[120px]">Requests</TableHead>
                      <TableHead className="font-mono uppercase text-xs w-[120px]">Errors</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {result.perIp.map((row) => (
                      <TableRow key={row.ip} className="border-border hover:bg-muted/50 transition-colors">
                        <TableCell className="font-mono text-xs text-primary">{row.ip}</TableCell>
                        <TableCell className="font-mono text-xs">{row.count}</TableCell>
                        <TableCell className={`font-mono text-xs ${row.errors > 0 ? "text-destructive" : ""}`}>{row.errors}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {!result && !input && (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground border-2 border-dashed border-border rounded-lg bg-card/20">
          <FileText className="w-12 h-12 mb-4 opacity-50" />
          <p className="font-mono text-sm">Paste server logs to begin. Try the Load Sample button.</p>
        </div>
      )}
    </div>
  );
}
