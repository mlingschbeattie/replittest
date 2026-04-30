import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { FileText, Download } from "lucide-react";
import { analyzeLogs, SAMPLE_APACHE_LOG, type LogFinding } from "@/lib/logs";
import { exportFindingsToCsv } from "@/lib/csv";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/severity-badge";

type AnalysisResult = ReturnType<typeof analyzeLogs>;

export default function Logs() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const handleParse = () => {
    if (!input.trim()) return;
    setResult(analyzeLogs(input));
  };

  const handleLoadSample = () => {
    setInput(SAMPLE_APACHE_LOG);
    setResult(analyzeLogs(SAMPLE_APACHE_LOG));
  };

  const handleExport = () => {
    if (!result) return;
    const rows = result.findings.map((f: LogFinding) => ({
      severity: f.severity,
      category: f.category,
      title: f.title,
      ip: f.ip ?? "",
      userAgent: f.userAgent ?? "",
      count: f.count,
      description: f.description,
      example: f.examples[0] ?? "",
    }));
    exportFindingsToCsv(rows, "log-findings.csv");
  };

  const findings = result?.findings ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">
            Log Analyzer
          </h1>
          <p className="text-muted-foreground mt-1 font-mono text-sm">
            Extract anomalies from server logs
          </p>
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
          <div className="flex items-center gap-4">
            <Button
              onClick={handleParse}
              disabled={!input.trim()}
              className="font-mono uppercase bg-primary text-primary-foreground hover:bg-primary/90 flex-1 md:flex-none"
            >
              <FileText className="w-4 h-4 mr-2" />
              Analyze Logs
            </Button>
            {findings.length > 0 && (
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
        <Card className="bg-card/50 border-border">
          <CardContent className="pt-6 grid grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs">
            <div>
              <div className="text-muted-foreground uppercase">Lines</div>
              <div className="text-lg text-primary">{result.totalLines}</div>
            </div>
            <div>
              <div className="text-muted-foreground uppercase">Parsed</div>
              <div className="text-lg text-primary">{result.parsedLines}</div>
            </div>
            <div>
              <div className="text-muted-foreground uppercase">Findings</div>
              <div className="text-lg text-primary">{findings.length}</div>
            </div>
            <div>
              <div className="text-muted-foreground uppercase">Unique IPs</div>
              <div className="text-lg text-primary">{result.perIp.length}</div>
            </div>
          </CardContent>
        </Card>
      )}

      {findings.length > 0 && (
        <Card className="bg-card/50 border-border animate-in fade-in duration-500">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase">
              Anomalies Detected ({findings.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead className="font-mono uppercase text-xs w-[100px]">
                    Severity
                  </TableHead>
                  <TableHead className="font-mono uppercase text-xs w-[140px]">
                    Category
                  </TableHead>
                  <TableHead className="font-mono uppercase text-xs w-[140px]">
                    Source IP
                  </TableHead>
                  <TableHead className="font-mono uppercase text-xs w-[80px]">
                    Count
                  </TableHead>
                  <TableHead className="font-mono uppercase text-xs">
                    Description
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.map((f) => (
                  <TableRow
                    key={f.id}
                    className="border-border hover:bg-muted/50 transition-colors"
                  >
                    <TableCell>
                      <SeverityBadge severity={f.severity} />
                    </TableCell>
                    <TableCell className="font-mono text-xs font-bold uppercase">
                      {f.category}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-primary">
                      {f.ip ?? f.userAgent ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {f.count}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      <div>{f.title}</div>
                      <div className="text-[10px] mt-1 opacity-70">
                        {f.description}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {result && result.perIp.length > 0 && (
        <Card className="bg-card/50 border-border">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase">
              Top Source IPs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead className="font-mono uppercase text-xs">
                    IP
                  </TableHead>
                  <TableHead className="font-mono uppercase text-xs w-[120px]">
                    Requests
                  </TableHead>
                  <TableHead className="font-mono uppercase text-xs w-[120px]">
                    Errors
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.perIp.map((row) => (
                  <TableRow
                    key={row.ip}
                    className="border-border hover:bg-muted/50 transition-colors"
                  >
                    <TableCell className="font-mono text-xs text-primary">
                      {row.ip}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {row.count}
                    </TableCell>
                    <TableCell
                      className={`font-mono text-xs ${
                        row.errors > 0 ? "text-destructive" : ""
                      }`}
                    >
                      {row.errors}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {!result && !input && (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground border-2 border-dashed border-border rounded-lg bg-card/20">
          <FileText className="w-12 h-12 mb-4 opacity-50" />
          <p className="font-mono text-sm">
            Paste server logs to begin. Try the Load Sample button.
          </p>
        </div>
      )}
    </div>
  );
}
