import { useMemo, useState } from "react";
import { useRunScan } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Play,
  Globe,
  Activity,
  Clock,
  Info,
  Download,
  Wrench,
  ShieldCheck,
} from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { exportFindingsToCsv } from "@/lib/csv";

type OwaspCat = { code: string; name: string };
type FixSpec = {
  change: string;
  example: string;
  difficulty: "Low" | "Medium" | "High";
  owner: "Developer" | "Server Admin" | "IT Infrastructure";
};
type EnrichedFinding = {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  evidence?: string;
  owasp?: OwaspCat[];
  plainEnglish?: string;
  howToFix?: string;
  fix?: FixSpec;
};

function formatOwasp(cats?: OwaspCat[]): string {
  if (!cats || cats.length === 0) return "—";
  return cats.map((c) => `${c.code}: ${c.name}`).join(" / ");
}

function difficultyClasses(d: FixSpec["difficulty"]): string {
  switch (d) {
    case "Low":
      return "text-primary border-primary/40 bg-primary/10";
    case "Medium":
      return "text-[hsl(var(--color-severity-high))] border-[hsl(var(--color-severity-high))]/40 bg-[hsl(var(--color-severity-high))]/10";
    case "High":
      return "text-destructive border-destructive/40 bg-destructive/10";
  }
}

export default function Scanner() {
  const [url, setUrl] = useState("");
  const { mutate: runScan, data: result, isPending, error } = useRunScan();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    runScan({ data: { url } });
  };

  const findings = (result?.findings ?? []) as EnrichedFinding[];

  const uniqueFindings = useMemo(() => {
    const seen = new Map<string, EnrichedFinding>();
    for (const f of findings) {
      if (!seen.has(f.id)) seen.set(f.id, f);
    }
    return Array.from(seen.values());
  }, [findings]);

  const handleExport = () => {
    if (!result) return;
    const target = result.finalUrl || result.target;
    const scannedAt = result.scannedAt;
    const rows = findings.map((f) => ({
      target,
      scanned_at: scannedAt,
      finding_id: f.id,
      title: f.title,
      severity: f.severity.toUpperCase(),
      category: f.category,
      owasp_top10_2021: formatOwasp(f.owasp),
      what_this_means: f.plainEnglish ?? f.description,
      how_to_fix: f.howToFix ?? "",
      exact_change_required: f.fix?.change ?? "",
      example_correct_value: f.fix?.example ?? "",
      estimated_difficulty: f.fix?.difficulty ?? "",
      owner: f.fix?.owner ?? "",
      evidence: f.evidence ?? "",
      technical_description: f.description,
    }));
    const safeHost = (() => {
      try {
        return new URL(target).hostname.replace(/[^a-z0-9.-]/gi, "_");
      } catch {
        return "scan";
      }
    })();
    const stamp = new Date(scannedAt).toISOString().replace(/[:.]/g, "-");
    exportFindingsToCsv(rows, `scan-${safeHost}-${stamp}.csv`);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">
          Passive Scanner
        </h1>
        <p className="text-muted-foreground mt-1 font-mono text-sm">
          Read-only HTTP header and misconfiguration analysis
        </p>
      </div>

      <Alert className="bg-primary/10 border-primary/30 text-primary">
        <Info className="h-4 w-4 text-primary" />
        <AlertTitle className="font-mono uppercase">
          Lab Mode Notice
        </AlertTitle>
        <AlertDescription className="font-mono text-xs">
          This scanner performs passive analysis only. It does not exploit
          vulnerabilities, inject payloads, or perform aggressive crawling.
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
            <Button
              type="submit"
              disabled={isPending || !url}
              className="font-mono uppercase tracking-wider bg-primary text-primary-foreground hover:bg-primary/90"
            >
              {isPending ? (
                <Activity className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Play className="w-4 h-4 mr-2" />
              )}
              Run Scan
            </Button>
          </form>
          {error &&
            (() => {
              const e = error as unknown as {
                error?: string;
                detail?: string;
                message?: string;
              };
              const msg = e?.error ?? e?.message ?? "Scan failed";
              return (
                <div className="mt-4 p-3 bg-destructive/20 border border-destructive/50 text-destructive font-mono text-sm rounded">
                  ERROR: {msg}
                  {e?.detail ? ` - ${e.detail}` : ""}
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
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase">
                  Target
                </CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm truncate flex items-center gap-2">
                <Globe className="w-4 h-4 text-primary shrink-0" />
                {result.finalUrl || result.target}
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase">
                  Status
                </CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm">
                <span
                  className={
                    result.statusCode && result.statusCode < 400
                      ? "text-primary"
                      : "text-destructive"
                  }
                >
                  HTTP {result.statusCode || "N/A"}
                </span>
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase">
                  Duration
                </CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm flex items-center gap-2 text-primary">
                <Clock className="w-4 h-4" />
                {result.durationMs}ms
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-muted-foreground uppercase">
                  Findings
                </CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-sm flex gap-2">
                {result.summary.critical > 0 && (
                  <span className="text-destructive font-bold">
                    {result.summary.critical} CRIT
                  </span>
                )}
                {result.summary.high > 0 && (
                  <span className="text-[hsl(var(--color-severity-high))]">
                    {result.summary.high} HIGH
                  </span>
                )}
                {result.summary.critical === 0 &&
                  result.summary.high === 0 && (
                    <span className="text-primary">NO CRIT/HIGH</span>
                  )}
              </CardContent>
            </Card>
          </div>

          <Card className="bg-card/50 border-border">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="font-mono text-sm uppercase">
                Scan Findings
              </CardTitle>
              <Button
                onClick={handleExport}
                variant="outline"
                size="sm"
                className="font-mono uppercase border-primary/50 text-primary hover:bg-primary/10"
                disabled={findings.length === 0}
              >
                <Download className="w-4 h-4 mr-2" />
                Export CSV
              </Button>
            </CardHeader>
            <CardContent>
              {findings.length > 0 ? (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border hover:bg-transparent">
                        <TableHead className="font-mono uppercase text-xs w-[90px]">
                          Severity
                        </TableHead>
                        <TableHead className="font-mono uppercase text-xs min-w-[180px]">
                          Finding
                        </TableHead>
                        <TableHead className="font-mono uppercase text-xs min-w-[180px]">
                          OWASP Category
                        </TableHead>
                        <TableHead className="font-mono uppercase text-xs min-w-[260px]">
                          What This Means
                        </TableHead>
                        <TableHead className="font-mono uppercase text-xs min-w-[280px]">
                          How To Fix It
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {findings.map((f, idx) => (
                        <TableRow
                          key={`${f.id}-${idx}`}
                          className="border-border hover:bg-muted/50 transition-colors align-top"
                        >
                          <TableCell className="align-top">
                            <SeverityBadge severity={f.severity} />
                          </TableCell>
                          <TableCell className="font-mono text-xs align-top">
                            <div className="text-foreground">{f.title}</div>
                            <div className="text-[10px] text-muted-foreground mt-1 uppercase">
                              {f.category}
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-xs align-top">
                            {f.owasp && f.owasp.length > 0 ? (
                              <div className="flex flex-col gap-1">
                                {f.owasp.map((c) => (
                                  <span
                                    key={c.code}
                                    className="inline-block text-primary border border-primary/30 bg-primary/10 px-2 py-0.5 rounded w-fit"
                                  >
                                    {c.code}: {c.name}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell className="font-sans text-xs text-muted-foreground align-top leading-relaxed">
                            {f.plainEnglish ?? f.description}
                          </TableCell>
                          <TableCell className="font-sans text-xs text-muted-foreground align-top leading-relaxed">
                            {f.howToFix ?? "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="text-center py-8 text-primary font-mono text-sm">
                  NO FINDINGS REPORTED
                </div>
              )}
            </CardContent>
          </Card>

          {uniqueFindings.some((f) => f.fix) && (
            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase flex items-center gap-2">
                  <Wrench className="w-4 h-4 text-primary" />
                  Fix Reference
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Accordion type="multiple" className="space-y-2">
                  {uniqueFindings
                    .filter((f) => f.fix)
                    .map((f) => (
                      <AccordionItem
                        key={f.id}
                        value={f.id}
                        className="border border-border rounded bg-muted/20 px-4"
                      >
                        <AccordionTrigger className="hover:no-underline">
                          <div className="flex items-center gap-3 text-left">
                            <SeverityBadge severity={f.severity} />
                            <span className="font-mono text-sm">
                              {f.title}
                            </span>
                          </div>
                        </AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-4 pt-2">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                              <div className="border border-border bg-card/50 rounded p-3">
                                <div className="text-[10px] font-mono uppercase text-muted-foreground mb-1">
                                  OWASP Top 10
                                </div>
                                <div className="font-mono text-xs text-primary">
                                  {formatOwasp(f.owasp)}
                                </div>
                              </div>
                              <div className="border border-border bg-card/50 rounded p-3">
                                <div className="text-[10px] font-mono uppercase text-muted-foreground mb-1">
                                  Difficulty
                                </div>
                                <div
                                  className={`font-mono text-xs inline-block px-2 py-0.5 rounded border ${difficultyClasses(
                                    f.fix!.difficulty,
                                  )}`}
                                >
                                  {f.fix!.difficulty}
                                </div>
                              </div>
                              <div className="border border-border bg-card/50 rounded p-3">
                                <div className="text-[10px] font-mono uppercase text-muted-foreground mb-1">
                                  Owned By
                                </div>
                                <div className="font-mono text-xs text-foreground">
                                  {f.fix!.owner}
                                </div>
                              </div>
                            </div>

                            <div>
                              <div className="text-[10px] font-mono uppercase text-muted-foreground mb-1">
                                Required Change
                              </div>
                              <div className="font-sans text-xs text-foreground leading-relaxed">
                                {f.fix!.change}
                              </div>
                            </div>

                            <div>
                              <div className="text-[10px] font-mono uppercase text-muted-foreground mb-1 flex items-center gap-1">
                                <ShieldCheck className="w-3 h-3 text-primary" />
                                Correct Example
                              </div>
                              <pre className="font-mono text-[11px] bg-background/80 border border-primary/20 rounded p-3 text-primary whitespace-pre-wrap break-words">
                                {f.fix!.example}
                              </pre>
                            </div>

                            {f.howToFix && (
                              <div>
                                <div className="text-[10px] font-mono uppercase text-muted-foreground mb-1">
                                  Remediation Steps
                                </div>
                                <div className="font-sans text-xs text-muted-foreground leading-relaxed">
                                  {f.howToFix}
                                </div>
                              </div>
                            )}

                            {f.evidence && (
                              <div>
                                <div className="text-[10px] font-mono uppercase text-muted-foreground mb-1">
                                  Evidence From Scan
                                </div>
                                <pre className="font-mono text-[11px] bg-background/80 border border-border rounded p-3 text-muted-foreground whitespace-pre-wrap break-words">
                                  {f.evidence}
                                </pre>
                              </div>
                            )}
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    ))}
                </Accordion>
              </CardContent>
            </Card>
          )}

          <Card className="bg-card/50 border-border">
            <CardHeader>
              <CardTitle className="font-mono text-sm uppercase">
                Headers
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 bg-muted/30 p-3 rounded border border-border/50 max-h-[400px] overflow-y-auto">
                {result.headers ? (
                  Object.entries(result.headers).map(([k, v]) => (
                    <div key={k} className="text-xs font-mono break-all">
                      <span className="text-primary">{k}:</span>{" "}
                      <span className="text-muted-foreground">{v}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-muted-foreground text-xs font-mono">
                    No headers captured.
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
