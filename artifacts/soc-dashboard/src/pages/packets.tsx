import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Activity, Download, FileText, AlertTriangle, KeyRound, Eye, EyeOff, Network, TableProperties, X } from "lucide-react";
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

// ─── CSV export ────────────────────────────────────────────────────────────────

function csvEscape(value: unknown): string {
  if (value == null) return "";
  const s = String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildCsv(packets: ParsedPacket[], credentials: CredentialFinding[]): string {
  const credIndex = new Set(credentials.map((c) => c.packetIndex));
  const rows: string[] = [];
  rows.push(["index", "timestamp", "source_ip", "source_port", "dest_ip", "dest_port", "protocol", "length", "severity", "payload"].map(csvEscape).join(","));
  for (const p of packets) {
    rows.push([p.index, p.timestamp ?? "", p.srcIp, p.srcPort ?? "", p.destIp, p.destPort ?? "", p.protocol, p.length ?? "", credIndex.has(p.index) ? "critical" : "", p.payload ?? ""].map(csvEscape).join(","));
  }
  if (credentials.length > 0) {
    rows.push("", "--- CREDENTIAL EXPOSURES ---");
    rows.push(["timestamp", "source_ip", "dest_ip", "dest_port", "protocol", "type", "label", "field", "username", "value", "confidence"].map(csvEscape).join(","));
    for (const c of credentials) {
      rows.push([c.timestamp ?? "", c.srcIp, c.destIp, c.destPort ?? "", c.protocol, credentialTypeLabel(c.type), c.label, c.fieldName ?? "", c.username ?? "", unmaskCredential(c), c.confidence].map(csvEscape).join(","));
    }
  }
  return rows.join("\n");
}

function downloadCsv(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ─── DPI Panel ─────────────────────────────────────────────────────────────────

function highlightPayload(text: string, highlights: string[]): React.ReactNode[] {
  if (!highlights.length || !text) return [<span key="full">{text}</span>];
  const pattern = highlights
    .filter((h) => h.length > 0)
    .map((h) => h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|");
  if (!pattern) return [<span key="full">{text}</span>];
  const re = new RegExp(`(${pattern})`, "gi");
  const parts = text.split(re);
  return parts.map((part, i) =>
    re.test(part) ? (
      <mark key={i} className="bg-destructive/50 text-destructive-foreground rounded px-0.5">
        {part}
      </mark>
    ) : (
      <span key={i}>{part}</span>
    ),
  );
}

function DpiPanel({
  packet,
  credByPacket,
  revealed,
  onClose,
}: {
  packet: ParsedPacket;
  credByPacket: Map<number, CredentialFinding[]>;
  revealed: boolean;
  onClose: () => void;
}) {
  const creds = credByPacket.get(packet.index) ?? [];
  const highlights = creds.map((c) => (revealed ? unmaskCredential(c) : c.rawValue));
  const payloadDisplay = highlightPayload(packet.payload ?? packet.raw ?? "", highlights);

  const PROTO_COLORS: Record<string, string> = {
    HTTP: "text-blue-400", HTTPS: "text-primary", TLS: "text-primary",
    TCP: "text-foreground", UDP: "text-amber-400", DNS: "text-purple-400",
    FTP: "text-orange-400", TELNET: "text-destructive", ICMP: "text-muted-foreground",
  };

  return (
    <Card className="bg-card border-primary/30 ring-1 ring-primary/20 animate-in slide-in-from-top-2 duration-200">
      <CardHeader className="py-3 px-4 bg-primary/5 border-b border-primary/20">
        <div className="flex items-center justify-between">
          <CardTitle className="font-mono text-xs uppercase text-primary flex items-center gap-2">
            <TableProperties className="w-3.5 h-3.5" />
            Deep Packet Inspection — Frame #{packet.index}
          </CardTitle>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground">
            <X className="w-4 h-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="pt-4 pb-4 space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
          {[
            { label: "Frame", value: `#${packet.index}` },
            { label: "Timestamp", value: packet.timestamp ?? "—" },
            { label: "Protocol", value: <span className={PROTO_COLORS[packet.protocol] ?? ""}>{packet.protocol}</span> },
            { label: "Flags", value: packet.flags ?? "—" },
            { label: "Source", value: `${packet.srcIp}${packet.srcPort != null ? `:${packet.srcPort}` : ""}` },
            { label: "Destination", value: `${packet.destIp}${packet.destPort != null ? `:${packet.destPort}` : ""}` },
            { label: "Length", value: packet.length != null ? `${packet.length} bytes` : "—" },
            { label: "Credential flags", value: creds.length > 0 ? <span className="text-destructive">{creds.length} found</span> : <span className="text-primary">none</span> },
          ].map(({ label, value }) => (
            <div key={label} className="bg-muted/30 rounded border border-border px-2 py-1.5">
              <div className="text-muted-foreground uppercase text-[9px] mb-0.5">{label}</div>
              <div className="truncate">{value}</div>
            </div>
          ))}
        </div>

        {(packet.payload || packet.raw) && (
          <div>
            <div className="font-mono text-[10px] text-muted-foreground uppercase mb-1.5">Payload / Info</div>
            <pre className="font-mono text-xs bg-muted/50 border border-border rounded p-3 whitespace-pre-wrap break-all leading-relaxed max-h-[180px] overflow-auto">
              {payloadDisplay}
            </pre>
            {creds.length > 0 && (
              <div className="mt-1.5 font-mono text-[10px] text-destructive">
                Highlighted segments contain detected credentials {revealed ? "(revealed)" : "(masked — use Reveal Plaintext to show raw values)"}.
              </div>
            )}
          </div>
        )}

        {creds.length > 0 && (
          <div>
            <div className="font-mono text-[10px] text-muted-foreground uppercase mb-2">Credential Findings in This Frame</div>
            <div className="space-y-2">
              {creds.map((c) => (
                <div key={c.id} className="flex items-start gap-3 p-2 bg-destructive/10 border border-destructive/20 rounded font-mono text-xs">
                  <span className="font-bold text-destructive uppercase whitespace-nowrap">{credentialTypeLabel(c.type)}</span>
                  <span className="text-muted-foreground">{c.label}</span>
                  <span className="ml-auto font-bold text-destructive whitespace-nowrap">
                    {revealed ? unmaskCredential(c) : maskCredential(c)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div>
          <div className="font-mono text-[10px] text-muted-foreground uppercase mb-1.5">Raw Line</div>
          <pre className="font-mono text-[10px] bg-muted/30 border border-border rounded px-2 py-1.5 whitespace-pre-wrap break-all text-muted-foreground max-h-[80px] overflow-auto">
            {packet.raw}
          </pre>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Network Topology Graph ────────────────────────────────────────────────────

type TopologyNode = { ip: string; totalPackets: number; isSource: boolean; isDest: boolean };
type TopologyEdge = { src: string; dst: string; count: number; protocols: Set<string> };

function buildTopology(packets: ParsedPacket[]): { nodes: TopologyNode[]; edges: TopologyEdge[] } {
  const nodeMap = new Map<string, { totalPackets: number; isSource: boolean; isDest: boolean }>();
  const edgeMap = new Map<string, TopologyEdge>();

  const ensure = (ip: string) => {
    if (!nodeMap.has(ip)) nodeMap.set(ip, { totalPackets: 0, isSource: false, isDest: false });
  };

  for (const p of packets) {
    ensure(p.srcIp);
    ensure(p.destIp);
    nodeMap.get(p.srcIp)!.totalPackets++;
    nodeMap.get(p.destIp)!.totalPackets++;
    nodeMap.get(p.srcIp)!.isSource = true;
    nodeMap.get(p.destIp)!.isDest = true;

    const key = `${p.srcIp}→${p.destIp}`;
    const edge = edgeMap.get(key) ?? { src: p.srcIp, dst: p.destIp, count: 0, protocols: new Set() };
    edge.count++;
    edge.protocols.add(p.protocol);
    edgeMap.set(key, edge);
  }

  return {
    nodes: Array.from(nodeMap.entries()).map(([ip, v]) => ({ ip, ...v })),
    edges: Array.from(edgeMap.values()),
  };
}

const PROTO_EDGE_COLORS: Record<string, string> = {
  HTTP: "#60a5fa", HTTPS: "#22d3ee", TLS: "#22d3ee", DNS: "#c084fc",
  UDP: "#fbbf24", FTP: "#fb923c", TELNET: "#f87171", ICMP: "#6b7280",
  TCP: "#4ade80",
};

function TopologyGraph({ packets, credentialPacketIndices }: { packets: ParsedPacket[]; credentialPacketIndices: Set<number> }) {
  const [tooltip, setTooltip] = useState<{ ip: string; x: number; y: number } | null>(null);
  const { nodes, edges } = useMemo(() => buildTopology(packets), [packets]);

  const credIps = useMemo(() => {
    const s = new Set<string>();
    for (const p of packets) {
      if (credentialPacketIndices.has(p.index)) {
        s.add(p.srcIp);
        s.add(p.destIp);
      }
    }
    return s;
  }, [packets, credentialPacketIndices]);

  if (nodes.length === 0) return null;

  const W = 780;
  const H = 420;
  const CX = W / 2;
  const CY = H / 2;
  const RADIUS = Math.min(CX - 80, CY - 60);

  const maxPackets = Math.max(...nodes.map((n) => n.totalPackets));
  const maxEdgeCount = Math.max(...edges.map((e) => e.count));

  const nodePositions = new Map<string, { x: number; y: number }>();
  nodes.forEach((node, i) => {
    const angle = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
    nodePositions.set(node.ip, {
      x: CX + RADIUS * Math.cos(angle),
      y: CY + RADIUS * Math.sin(angle),
    });
  });

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full rounded border border-border bg-muted/20"
        style={{ maxHeight: 440 }}
        onMouseLeave={() => setTooltip(null)}
      >
        <defs>
          <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
            <path d="M0,0 L0,6 L6,3 Z" fill="rgba(100,255,218,0.4)" />
          </marker>
        </defs>

        {edges.map((edge, i) => {
          const from = nodePositions.get(edge.src);
          const to = nodePositions.get(edge.dst);
          if (!from || !to) return null;
          const ratio = maxEdgeCount > 0 ? edge.count / maxEdgeCount : 0.1;
          const strokeW = 0.5 + ratio * 3;
          const proto = Array.from(edge.protocols)[0] ?? "TCP";
          const color = PROTO_EDGE_COLORS[proto] ?? "#4ade80";
          const hasCredEdge =
            credIps.has(edge.src) && credIps.has(edge.dst);

          const dx = to.x - from.x;
          const dy = to.y - from.y;
          const len = Math.sqrt(dx * dx + dy * dy);
          const nx = dx / len;
          const ny = dy / len;
          const nodeR = 8;
          const ax = from.x + nx * nodeR;
          const ay = from.y + ny * nodeR;
          const bx = to.x - nx * (nodeR + 6);
          const by = to.y - ny * (nodeR + 6);

          return (
            <line
              key={i}
              x1={ax} y1={ay} x2={bx} y2={by}
              stroke={hasCredEdge ? "#f87171" : color}
              strokeWidth={strokeW}
              strokeOpacity={hasCredEdge ? 0.9 : 0.45}
              markerEnd="url(#arrow)"
            />
          );
        })}

        {nodes.map((node) => {
          const pos = nodePositions.get(node.ip);
          if (!pos) return null;
          const ratio = maxPackets > 0 ? node.totalPackets / maxPackets : 0.5;
          const r = 5 + ratio * 9;
          const isCredNode = credIps.has(node.ip);

          return (
            <g
              key={node.ip}
              className="cursor-pointer"
              onMouseEnter={(e) => {
                const rect = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
                setTooltip({ ip: node.ip, x: pos.x, y: pos.y });
              }}
            >
              <circle
                cx={pos.x} cy={pos.y} r={r + 4}
                fill={isCredNode ? "rgba(248,113,113,0.15)" : "rgba(34,211,238,0.1)"}
              />
              <circle
                cx={pos.x} cy={pos.y} r={r}
                fill={isCredNode ? "#ef4444" : "#22d3ee"}
                fillOpacity={0.85}
                stroke={isCredNode ? "#fca5a5" : "#67e8f9"}
                strokeWidth={1.5}
              />
              <text
                x={pos.x}
                y={pos.y - r - 5}
                textAnchor="middle"
                fontSize={8}
                fontFamily="monospace"
                fill="hsl(var(--muted-foreground))"
              >
                {node.ip}
              </text>
            </g>
          );
        })}

        {tooltip && (() => {
          const pos = nodePositions.get(tooltip.ip);
          const node = nodes.find((n) => n.ip === tooltip.ip);
          if (!pos || !node) return null;
          const edgesFrom = edges.filter((e) => e.src === tooltip.ip);
          const edgesTo = edges.filter((e) => e.dst === tooltip.ip);
          const protos = Array.from(new Set(edges.filter((e) => e.src === tooltip.ip || e.dst === tooltip.ip).flatMap((e) => Array.from(e.protocols)))).join(", ");
          const tx = pos.x > W / 2 ? pos.x - 130 : pos.x + 16;
          const ty = Math.min(pos.y, H - 80);
          return (
            <g>
              <rect x={tx - 4} y={ty - 14} width={140} height={74} rx={4} fill="hsl(var(--card))" stroke="hsl(var(--border))" strokeWidth={1} />
              <text x={tx} y={ty} fontFamily="monospace" fontSize={9} fill="hsl(var(--primary))" fontWeight="bold">{tooltip.ip}</text>
              <text x={tx} y={ty + 13} fontFamily="monospace" fontSize={8} fill="hsl(var(--muted-foreground))">Packets: {node.totalPackets}</text>
              <text x={tx} y={ty + 25} fontFamily="monospace" fontSize={8} fill="hsl(var(--muted-foreground))">Outbound: {edgesFrom.reduce((s, e) => s + e.count, 0)}</text>
              <text x={tx} y={ty + 37} fontFamily="monospace" fontSize={8} fill="hsl(var(--muted-foreground))">Inbound: {edgesTo.reduce((s, e) => s + e.count, 0)}</text>
              <text x={tx} y={ty + 49} fontFamily="monospace" fontSize={8} fill="hsl(var(--muted-foreground))">{protos || "—"}</text>
              {credIps.has(tooltip.ip) && (
                <text x={tx} y={ty + 61} fontFamily="monospace" fontSize={8} fill="#f87171">Credential exposure</text>
              )}
            </g>
          );
        })()}
      </svg>

      <div className="flex flex-wrap gap-3 mt-3 font-mono text-[10px] text-muted-foreground">
        {Object.entries(PROTO_EDGE_COLORS).slice(0, 6).map(([proto, color]) => (
          <span key={proto} className="flex items-center gap-1">
            <span className="w-4 h-0.5 rounded inline-block" style={{ background: color }} />
            {proto}
          </span>
        ))}
        <span className="flex items-center gap-1 text-destructive">
          <span className="w-2.5 h-2.5 rounded-full bg-destructive inline-block" />
          Credential node
        </span>
      </div>
    </div>
  );
}

// ─── Main component ────────────────────────────────────────────────────────────

export default function Packets() {
  const [input, setInput] = useState("");
  const [packets, setPackets] = useState<ParsedPacket[]>([]);
  const [patterns, setPatterns] = useState<SuspiciousPattern[]>([]);
  const [credentials, setCredentials] = useState<CredentialFinding[]>([]);
  const [revealed, setRevealed] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [packetView, setPacketView] = useState<"table" | "topology">("table");

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

  const credByPacket = useMemo(() => {
    const m = new Map<number, CredentialFinding[]>();
    for (const c of credentials) {
      const arr = m.get(c.packetIndex) ?? [];
      arr.push(c);
      m.set(c.packetIndex, arr);
    }
    return m;
  }, [credentials]);

  const selectedPacket = useMemo(
    () => (selectedIndex != null ? packets.find((p) => p.index === selectedIndex) ?? null : null),
    [packets, selectedIndex],
  );

  const runAnalysis = (text: string) => {
    const p = parsePackets(text);
    setPackets(p);
    setPatterns(detectSuspiciousPatterns(p));
    setCredentials(detectCredentials(p));
    setRevealed(false);
    setSelectedIndex(null);
  };

  const handleParse = () => { if (!input.trim()) return; runAnalysis(input); };
  const handleLoadSample = () => { setInput(SAMPLE_TCPDUMP); runAnalysis(SAMPLE_TCPDUMP); };
  const handleToggleReveal = () => { if (revealed) { setRevealed(false); return; } setConfirmOpen(true); };
  const handleConfirmReveal = () => { setRevealed(true); setConfirmOpen(false); };
  const handleExportCsv = () => {
    const csv = buildCsv(sortedPackets, credentials);
    downloadCsv(`packet-capture-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`, csv);
  };

  const handleRowClick = (p: ParsedPacket) => {
    setSelectedIndex(selectedIndex === p.index ? null : p.index);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Packet Visualizer</h1>
          <p className="text-muted-foreground mt-1 font-mono text-sm">Parse tcpdump — inspect payloads, topology, and credential exposures</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {packets.length > 0 && (
            <Button variant="outline" onClick={handleExportCsv} className="font-mono text-xs border-primary/50 text-primary hover:bg-primary/10">
              <Download className="w-4 h-4 mr-2" /> Export CSV
            </Button>
          )}
          <Button variant="outline" onClick={handleLoadSample} className="font-mono text-xs border-primary/50 text-primary hover:bg-primary/10">
            Load Sample
          </Button>
        </div>
      </div>

      <Card className="bg-card/50 border-border">
        <CardContent className="pt-6 space-y-4">
          <Textarea
            placeholder="Paste tcpdump or Wireshark output here..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="font-mono text-xs min-h-[150px] bg-muted/50 border-border focus-visible:ring-primary"
          />
          <Button onClick={handleParse} disabled={!input.trim()} className="font-mono uppercase bg-primary text-primary-foreground hover:bg-primary/90 w-full md:w-auto">
            <Activity className="w-4 h-4 mr-2" /> Parse Packets
          </Button>
        </CardContent>
      </Card>

      {packets.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 animate-in fade-in duration-500">
          <div className="lg:col-span-3 space-y-6">
            {credentials.length > 0 && (
              <Card className="bg-destructive/10 border-destructive/40 overflow-hidden">
                <div className="bg-destructive text-destructive-foreground px-4 py-2 font-mono text-xs uppercase tracking-widest flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Plaintext credentials detected in capture
                </div>
                <CardHeader className="pb-3">
                  <CardTitle className="font-mono text-sm uppercase flex items-center justify-between gap-3 flex-wrap">
                    <span className="flex items-center gap-2 text-destructive">
                      <KeyRound className="w-4 h-4" />
                      Exposed Credentials
                      <Badge className="bg-destructive text-destructive-foreground hover:bg-destructive font-mono">{credentials.length}</Badge>
                    </span>
                    <Button variant="outline" size="sm" onClick={handleToggleReveal} className="font-mono text-xs border-destructive/60 text-destructive hover:bg-destructive/10">
                      {revealed ? <><EyeOff className="w-3.5 h-3.5 mr-1.5" />Re-mask</> : <><Eye className="w-3.5 h-3.5 mr-1.5" />Reveal Plaintext</>}
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
                        <TableRow key={c.id} className="border-destructive/20 hover:bg-destructive/5 cursor-pointer" onClick={() => handleRowClick(packets.find((p) => p.index === c.packetIndex)!)}>
                          <TableCell className="font-mono text-xs text-muted-foreground">{c.timestamp ?? "—"}</TableCell>
                          <TableCell className="font-mono text-xs text-primary">{c.srcIp}</TableCell>
                          <TableCell className="font-mono text-xs">{c.destIp}{c.destPort != null ? `:${c.destPort}` : ""}</TableCell>
                          <TableCell className="font-mono text-xs">{c.protocol}</TableCell>
                          <TableCell className="font-mono text-xs">
                            <div className="flex flex-col gap-0.5">
                              <span className="font-bold text-destructive">{credentialTypeLabel(c.type)}</span>
                              <span className="text-muted-foreground">{c.label}</span>
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-xs break-all max-w-[280px]">
                            <span className={revealed ? "text-destructive font-bold" : "text-foreground"}>
                              {revealed ? unmaskCredential(c) : maskCredential(c)}
                            </span>
                          </TableCell>
                          <TableCell className="font-mono text-xs uppercase">
                            <Badge variant="outline" className={c.confidence === "high" ? "border-destructive/60 text-destructive" : c.confidence === "medium" ? "border-amber-500/60 text-amber-400" : "border-muted text-muted-foreground"}>
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

            {selectedPacket && (
              <DpiPanel
                packet={selectedPacket}
                credByPacket={credByPacket}
                revealed={revealed}
                onClose={() => setSelectedIndex(null)}
              />
            )}

            <Card className="bg-card/50 border-border overflow-hidden">
              <CardHeader className="bg-muted/30 border-b border-border pb-3">
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <CardTitle className="font-mono text-sm uppercase flex items-center gap-2">
                    Parsed Packets ({packets.length})
                    {credentials.length > 0 && (
                      <span className="text-xs text-destructive font-normal normal-case font-mono">
                        {credentialPacketIndices.size} flagged
                      </span>
                    )}
                  </CardTitle>
                  <Tabs value={packetView} onValueChange={(v) => setPacketView(v as "table" | "topology")}>
                    <TabsList className="h-7 bg-muted/50 border border-border">
                      <TabsTrigger value="table" className="h-6 text-[10px] font-mono uppercase px-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                        <TableProperties className="w-3 h-3 mr-1" /> Table
                      </TabsTrigger>
                      <TabsTrigger value="topology" className="h-6 text-[10px] font-mono uppercase px-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                        <Network className="w-3 h-3 mr-1" /> Topology
                      </TabsTrigger>
                    </TabsList>
                  </Tabs>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                {packetView === "table" ? (
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
                        const selected = selectedIndex === p.index;
                        const credsHere = credByPacket.get(p.index);
                        return (
                          <TableRow
                            key={p.index}
                            onClick={() => handleRowClick(p)}
                            className={`cursor-pointer transition-colors ${
                              selected
                                ? "bg-primary/10 border-primary/30"
                                : flagged
                                  ? "border-destructive/30 bg-destructive/5 hover:bg-destructive/10"
                                  : "border-border hover:bg-muted/50"
                            }`}
                          >
                            <TableCell className="font-mono text-xs">
                              {flagged ? <SeverityBadge severity="critical" /> : null}
                            </TableCell>
                            <TableCell className="font-mono text-xs text-muted-foreground">{p.timestamp}</TableCell>
                            <TableCell className="font-mono text-xs text-primary">{p.srcIp}</TableCell>
                            <TableCell className="font-mono text-xs">{p.destIp}{p.destPort != null ? `:${p.destPort}` : ""}</TableCell>
                            <TableCell className="font-mono text-xs">{p.protocol}</TableCell>
                            <TableCell className="font-mono text-xs text-muted-foreground truncate max-w-[280px] hidden md:table-cell">
                              <div>{p.payload}</div>
                              {flagged && credsHere && (
                                <div className="mt-1 flex flex-wrap gap-1">
                                  {credsHere.map((c) => (
                                    <Badge key={c.id} className="bg-destructive/20 text-destructive border border-destructive/40 font-mono text-[10px] uppercase">
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
                ) : (
                  <div className="p-4">
                    <TopologyGraph packets={packets} credentialPacketIndices={credentialPacketIndices} />
                    <div className="mt-3 font-mono text-[10px] text-muted-foreground">
                      Node size = packet volume. Edge thickness = connection frequency. Hover nodes for details. Red nodes = credential exposure.
                    </div>
                  </div>
                )}
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

            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-xs uppercase text-muted-foreground">DPI Guide</CardTitle>
              </CardHeader>
              <CardContent className="font-mono text-[10px] text-muted-foreground space-y-2">
                <p>Click any row in the packet table to open the Deep Packet Inspection panel.</p>
                <p>The DPI panel shows parsed protocol fields, the full payload, and highlights any credential substrings found.</p>
                <p>Switch to Topology view to see a graph of all IP conversations with traffic-weighted edges.</p>
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
              <AlertTriangle className="w-4 h-4" /> Reveal Plaintext Credentials?
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs leading-relaxed">
              You are about to display extracted plaintext credentials on screen. Anyone who can see this display — including over-the-shoulder observers and screen recordings — will be able to read passwords, tokens, and session identifiers. Only proceed in a controlled environment.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="font-mono uppercase text-xs">Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleConfirmReveal} className="font-mono uppercase text-xs bg-destructive text-destructive-foreground hover:bg-destructive/90">Reveal</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
