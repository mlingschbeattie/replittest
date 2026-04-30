import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Activity, Download, FileText, AlertTriangle, KeyRound, Eye, EyeOff } from "lucide-react";
import {
  parsePackets,
  detectSuspiciousPatterns,
  detectCredentials,
  maskCredential,
  unmaskCredential,
  credentialTypeLabel,
  SAMPLE_TCPDUMP,
  type ParsedPacket,
  type SuspiciousPattern,
  type CredentialFinding,
} from "@/lib/packets";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/severity-badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

function csvEscape(value: unknown): string {
  if (value == null) return "";
  const s = String(value);
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function buildCsv(packets: ParsedPacket[], credentials: CredentialFinding[]): string {
  const credIndex = new Set(credentials.map((c) => c.packetIndex));
  const rows: string[] = [];
  rows.push(
    ["index", "timestamp", "source_ip", "source_port", "dest_ip", "dest_port", "protocol", "length", "severity", "payload"]
      .map(csvEscape)
      .join(","),
  );
  for (const p of packets) {
    rows.push(
      [
        p.index,
        p.timestamp ?? "",
        p.srcIp,
        p.srcPort ?? "",
        p.destIp,
        p.destPort ?? "",
        p.protocol,
        p.length ?? "",
        credIndex.has(p.index) ? "critical" : "",
        p.payload ?? "",
      ]
        .map(csvEscape)
        .join(","),
    );
  }

  if (credentials.length > 0) {
    rows.push("");
    rows.push("--- CREDENTIAL EXPOSURES ---");
    rows.push(
      [
        "timestamp",
        "source_ip",
        "dest_ip",
        "dest_port",
        "protocol",
        "type",
        "label",
        "field",
        "username",
        "value",
        "confidence",
      ]
        .map(csvEscape)
        .join(","),
    );
    for (const c of credentials) {
      rows.push(
        [
          c.timestamp ?? "",
          c.srcIp,
          c.destIp,
          c.destPort ?? "",
          c.protocol,
          credentialTypeLabel(c.type),
          c.label,
          c.fieldName ?? "",
          c.username ?? "",
          unmaskCredential(c),
          c.confidence,
        ]
          .map(csvEscape)
          .join(","),
      );
    }
  }
  return rows.join("\n");
}

function downloadCsv(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export default function Packets() {
  const [input, setInput] = useState("");
  const [packets, setPackets] = useState<ParsedPacket[]>([]);
  const [patterns, setPatterns] = useState<SuspiciousPattern[]>([]);
  const [credentials, setCredentials] = useState<CredentialFinding[]>([]);
  const [revealed, setRevealed] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const credentialPacketIndices = useMemo(
    () => new Set(credentials.map((c) => c.packetIndex)),
    [credentials],
  );

  const sortedPackets = useMemo(() => {
    if (credentialPacketIndices.size === 0) return packets;
    const flagged: ParsedPacket[] = [];
    const rest: ParsedPacket[] = [];
    for (const p of packets) {
      (credentialPacketIndices.has(p.index) ? flagged : rest).push(p);
    }
    return [...flagged, ...rest];
  }, [packets, credentialPacketIndices]);

  const runAnalysis = (text: string) => {
    const p = parsePackets(text);
    setPackets(p);
    setPatterns(detectSuspiciousPatterns(p));
    setCredentials(detectCredentials(p));
    setRevealed(false);
  };

  const handleParse = () => {
    if (!input.trim()) return;
    runAnalysis(input);
  };

  const handleLoadSample = () => {
    setInput(SAMPLE_TCPDUMP);
    runAnalysis(SAMPLE_TCPDUMP);
  };

  const handleToggleReveal = () => {
    if (revealed) {
      setRevealed(false);
      return;
    }
    setConfirmOpen(true);
  };

  const handleConfirmReveal = () => {
    setRevealed(true);
    setConfirmOpen(false);
  };

  const handleExportCsv = () => {
    const csv = buildCsv(sortedPackets, credentials);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadCsv(`packet-capture-${stamp}.csv`, csv);
  };

  const credByPacket = useMemo(() => {
    const m = new Map<number, CredentialFinding[]>();
    for (const c of credentials) {
      const arr = m.get(c.packetIndex) ?? [];
      arr.push(c);
      m.set(c.packetIndex, arr);
    }
    return m;
  }, [credentials]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Packet Visualizer</h1>
          <p className="text-muted-foreground mt-1 font-mono text-sm">Parse tcpdump and Wireshark output</p>
        </div>
        <div className="flex gap-2">
          {packets.length > 0 && (
            <Button
              variant="outline"
              onClick={handleExportCsv}
              className="font-mono text-xs border-primary/50 text-primary hover:bg-primary/10"
              data-testid="button-export-csv"
            >
              <Download className="w-4 h-4 mr-2" />
              Export CSV
            </Button>
          )}
          <Button
            variant="outline"
            onClick={handleLoadSample}
            className="font-mono text-xs border-primary/50 text-primary hover:bg-primary/10"
            data-testid="button-load-sample"
          >
            Load Sample
          </Button>
        </div>
      </div>

      <Card className="bg-card/50 border-border">
        <CardContent className="pt-6 space-y-4">
          <Textarea
            placeholder="Paste tcpdump or wireshark output here..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="font-mono text-xs min-h-[150px] bg-muted/50 border-border focus-visible:ring-primary"
            data-testid="textarea-packet-input"
          />
          <Button
            onClick={handleParse}
            disabled={!input.trim()}
            className="font-mono uppercase bg-primary text-primary-foreground hover:bg-primary/90 w-full md:w-auto"
            data-testid="button-parse-packets"
          >
            <Activity className="w-4 h-4 mr-2" />
            Parse Packets
          </Button>
        </CardContent>
      </Card>

      {packets.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 animate-in fade-in duration-500">
          <div className="lg:col-span-3 space-y-6">
            {credentials.length > 0 && (
              <Card
                className="bg-destructive/10 border-destructive/40 overflow-hidden"
                data-testid="card-credentials-panel"
              >
                <div className="bg-destructive text-destructive-foreground px-4 py-2 font-mono text-xs uppercase tracking-widest flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Plaintext credentials detected in capture
                </div>
                <CardHeader className="pb-3">
                  <CardTitle className="font-mono text-sm uppercase flex items-center justify-between gap-3 flex-wrap">
                    <span className="flex items-center gap-2 text-destructive">
                      <KeyRound className="w-4 h-4" />
                      Exposed Credentials
                      <Badge
                        className="bg-destructive text-destructive-foreground hover:bg-destructive font-mono"
                        data-testid="badge-credential-count"
                      >
                        {credentials.length}
                      </Badge>
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleToggleReveal}
                      className="font-mono text-xs border-destructive/60 text-destructive hover:bg-destructive/10"
                      data-testid="button-toggle-reveal"
                    >
                      {revealed ? (
                        <>
                          <EyeOff className="w-3.5 h-3.5 mr-1.5" />
                          Re-mask
                        </>
                      ) : (
                        <>
                          <Eye className="w-3.5 h-3.5 mr-1.5" />
                          Reveal Plaintext
                        </>
                      )}
                    </Button>
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-destructive/20 hover:bg-transparent">
                        <TableHead className="font-mono uppercase text-xs">Timestamp</TableHead>
                        <TableHead className="font-mono uppercase text-xs">Source IP</TableHead>
                        <TableHead className="font-mono uppercase text-xs">Dest IP</TableHead>
                        <TableHead className="font-mono uppercase text-xs">Proto</TableHead>
                        <TableHead className="font-mono uppercase text-xs">Type</TableHead>
                        <TableHead className="font-mono uppercase text-xs">Extracted Value</TableHead>
                        <TableHead className="font-mono uppercase text-xs">Confidence</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {credentials.map((c) => (
                        <TableRow
                          key={c.id}
                          className="border-destructive/20 hover:bg-destructive/5"
                          data-testid={`row-credential-${c.id}`}
                        >
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {c.timestamp ?? "—"}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-primary">{c.srcIp}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {c.destIp}
                            {c.destPort != null ? `:${c.destPort}` : ""}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{c.protocol}</TableCell>
                          <TableCell className="font-mono text-xs">
                            <div className="flex flex-col gap-0.5">
                              <span className="font-bold text-destructive">
                                {credentialTypeLabel(c.type)}
                              </span>
                              <span className="text-muted-foreground">{c.label}</span>
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-xs break-all max-w-[280px]">
                            <span
                              className={
                                revealed
                                  ? "text-destructive font-bold"
                                  : "text-foreground"
                              }
                              data-testid={`text-credential-value-${c.id}`}
                            >
                              {revealed ? unmaskCredential(c) : maskCredential(c)}
                            </span>
                          </TableCell>
                          <TableCell className="font-mono text-xs uppercase">
                            <Badge
                              variant="outline"
                              className={
                                c.confidence === "high"
                                  ? "border-destructive/60 text-destructive"
                                  : c.confidence === "medium"
                                    ? "border-amber-500/60 text-amber-400"
                                    : "border-muted text-muted-foreground"
                              }
                            >
                              {c.confidence}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}

            <Card className="bg-card/50 border-border overflow-hidden">
              <CardHeader className="bg-muted/30 border-b border-border pb-4">
                <CardTitle className="font-mono text-sm uppercase flex items-center justify-between">
                  <span>Parsed Packets ({packets.length})</span>
                  {credentials.length > 0 && (
                    <span className="text-xs text-destructive font-normal normal-case">
                      {credentialPacketIndices.size} flagged · pinned to top
                    </span>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="font-mono uppercase text-xs w-24">Severity</TableHead>
                      <TableHead className="font-mono uppercase text-xs">Time</TableHead>
                      <TableHead className="font-mono uppercase text-xs">Source</TableHead>
                      <TableHead className="font-mono uppercase text-xs">Dest</TableHead>
                      <TableHead className="font-mono uppercase text-xs">Proto</TableHead>
                      <TableHead className="font-mono uppercase text-xs hidden md:table-cell">Payload</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {sortedPackets.map((p) => {
                      const flagged = credentialPacketIndices.has(p.index);
                      const credsHere = credByPacket.get(p.index);
                      return (
                        <TableRow
                          key={p.index}
                          className={
                            flagged
                              ? "border-destructive/30 bg-destructive/5 hover:bg-destructive/10 transition-colors"
                              : "border-border hover:bg-muted/50 transition-colors"
                          }
                          data-testid={`row-packet-${p.index}`}
                        >
                          <TableCell className="font-mono text-xs">
                            {flagged ? <SeverityBadge severity="critical" /> : null}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">{p.timestamp}</TableCell>
                          <TableCell className="font-mono text-xs text-primary">{p.srcIp}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {p.destIp}
                            {p.destPort != null ? `:${p.destPort}` : ""}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{p.protocol}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground truncate max-w-[280px] hidden md:table-cell">
                            <div>{p.payload}</div>
                            {flagged && credsHere && (
                              <div className="mt-1 flex flex-wrap gap-1">
                                {credsHere.map((c) => (
                                  <Badge
                                    key={c.id}
                                    className="bg-destructive/20 text-destructive border border-destructive/40 font-mono text-[10px] uppercase"
                                  >
                                    {credentialTypeLabel(c.type)}
                                  </Badge>
                                ))}
                              </div>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-6">
            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase text-destructive flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" /> Suspicious Patterns
                </CardTitle>
              </CardHeader>
              <CardContent>
                {patterns.length > 0 ? (
                  <div className="space-y-4">
                    {patterns.map((pat, i) => (
                      <div key={i} className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                        <div className="font-mono font-bold text-destructive text-sm flex justify-between">
                          <span className="uppercase">{pat.category}</span>
                          <span>x{pat.count}</span>
                        </div>
                        <div className="font-mono text-xs text-foreground mt-1">{pat.title}</div>
                        <div className="font-mono text-xs text-muted-foreground mt-1">{pat.description}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="font-mono text-xs text-primary bg-primary/10 p-3 rounded border border-primary/20">
                    No suspicious patterns detected in capture.
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {!packets.length && !input && (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground border-2 border-dashed border-border rounded-lg bg-card/20">
          <FileText className="w-12 h-12 mb-4 opacity-50" />
          <p className="font-mono text-sm">Paste tcpdump output to begin. Try the Load Sample button.</p>
        </div>
      )}

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent className="font-mono">
          <AlertDialogHeader>
            <AlertDialogTitle className="uppercase tracking-widest text-destructive flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Reveal Plaintext Credentials?
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs leading-relaxed">
              You are about to display extracted plaintext credentials on screen. Anyone who can see this display, including over-the-shoulder observers and screen recordings, will be able to read passwords, tokens, and session identifiers. Only proceed in a controlled environment.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              className="font-mono uppercase text-xs"
              data-testid="button-cancel-reveal"
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfirmReveal}
              className="font-mono uppercase text-xs bg-destructive text-destructive-foreground hover:bg-destructive/90"
              data-testid="button-confirm-reveal"
            >
              Reveal
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
