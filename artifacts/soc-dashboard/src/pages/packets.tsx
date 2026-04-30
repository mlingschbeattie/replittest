import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Activity, Download, FileText, AlertTriangle } from "lucide-react";
import { parsePackets, detectSuspiciousPatterns, SAMPLE_TCPDUMP, type ParsedPacket, type SuspiciousPattern } from "@/lib/packets";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function Packets() {
  const [input, setInput] = useState("");
  const [packets, setPackets] = useState<ParsedPacket[]>([]);
  const [patterns, setPatterns] = useState<SuspiciousPattern[]>([]);

  const handleParse = () => {
    if (!input.trim()) return;
    const p = parsePackets(input);
    setPackets(p);
    setPatterns(detectSuspiciousPatterns(p));
  };

  const handleLoadSample = () => {
    setInput(SAMPLE_TCPDUMP);
    const p = parsePackets(SAMPLE_TCPDUMP);
    setPackets(p);
    setPatterns(detectSuspiciousPatterns(p));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Packet Visualizer</h1>
          <p className="text-muted-foreground mt-1 font-mono text-sm">Parse tcpdump and Wireshark output</p>
        </div>
        <Button variant="outline" onClick={handleLoadSample} className="font-mono text-xs border-primary/50 text-primary hover:bg-primary/10">
          Load Sample
        </Button>
      </div>

      <Card className="bg-card/50 border-border">
        <CardContent className="pt-6 space-y-4">
          <Textarea 
            placeholder="Paste tcpdump or wireshark output here..." 
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="font-mono text-xs min-h-[150px] bg-muted/50 border-border focus-visible:ring-primary"
          />
          <Button onClick={handleParse} disabled={!input.trim()} className="font-mono uppercase bg-primary text-primary-foreground hover:bg-primary/90 w-full md:w-auto">
            <Activity className="w-4 h-4 mr-2" />
            Parse Packets
          </Button>
        </CardContent>
      </Card>

      {packets.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 animate-in fade-in duration-500">
          <div className="lg:col-span-3 space-y-6">
            <Card className="bg-card/50 border-border overflow-hidden">
              <CardHeader className="bg-muted/30 border-b border-border pb-4">
                <CardTitle className="font-mono text-sm uppercase flex items-center justify-between">
                  <span>Parsed Packets ({packets.length})</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="font-mono uppercase text-xs">Time</TableHead>
                      <TableHead className="font-mono uppercase text-xs">Source</TableHead>
                      <TableHead className="font-mono uppercase text-xs">Dest</TableHead>
                      <TableHead className="font-mono uppercase text-xs">Proto</TableHead>
                      <TableHead className="font-mono uppercase text-xs hidden md:table-cell">Payload</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {packets.map((p, i) => (
                      <TableRow key={i} className="border-border hover:bg-muted/50 transition-colors">
                        <TableCell className="font-mono text-xs text-muted-foreground">{p.timestamp}</TableCell>
                        <TableCell className="font-mono text-xs text-primary">{p.srcIp}</TableCell>
                        <TableCell className="font-mono text-xs">{p.destIp}{p.destPort != null ? `:${p.destPort}` : ""}</TableCell>
                        <TableCell className="font-mono text-xs">{p.protocol}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground truncate max-w-[200px] hidden md:table-cell">{p.payload}</TableCell>
                      </TableRow>
                    ))}
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
    </div>
  );
}
