import { useState, useEffect } from "react";
import { useCheckHash } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Hash as HashIcon, ShieldAlert, AlertTriangle, CheckCircle2, Search } from "lucide-react";
import { identifyHashClient } from "@/lib/hash";
import { Badge } from "@/components/ui/badge";

export default function Hash() {
  const [input, setInput] = useState("");
  const [clientTypes, setClientTypes] = useState<string[]>([]);
  const { mutate: checkHash, data: result, isPending } = useCheckHash();

  useEffect(() => {
    if (input.trim()) {
      setClientTypes(identifyHashClient(input.trim()));
    } else {
      setClientTypes([]);
    }
  }, [input]);

  const handleSubmit = () => {
    if (!input.trim()) return;
    checkHash({ data: { hash: input.trim() } });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Hash Identifier</h1>
        <p className="text-muted-foreground mt-1 font-mono text-sm">Identify algorithms and check known breaches</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <Card className="bg-card/50 border-border">
            <CardContent className="pt-6 space-y-4">
              <Textarea 
                placeholder="Paste hash here..." 
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="font-mono text-lg min-h-[100px] bg-muted/50 border-border focus-visible:ring-primary tracking-wider break-all"
              />
              <div className="flex items-center justify-between">
                <div className="font-mono text-xs text-muted-foreground">
                  Length: {input.trim().length} | Probable Type: {clientTypes.join(", ") || "None"}
                </div>
                <Button onClick={handleSubmit} disabled={!input.trim() || isPending} className="font-mono uppercase bg-primary text-primary-foreground hover:bg-primary/90">
                  {isPending ? <Search className="w-4 h-4 mr-2 animate-spin" /> : <HashIcon className="w-4 h-4 mr-2" />}
                  Identify & Check
                </Button>
              </div>
            </CardContent>
          </Card>

          {result && (
            <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <Card className="bg-card/50 border-border">
                <CardHeader className="border-b border-border bg-muted/20 pb-3">
                  <CardTitle className="font-mono text-sm uppercase">Analysis Result</CardTitle>
                </CardHeader>
                <CardContent className="pt-4 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <div className="font-mono text-xs text-muted-foreground mb-1 uppercase">Primary Type</div>
                      <Badge variant="outline" className="font-mono text-primary border-primary bg-primary/10 text-sm">
                        {result.primaryType || "Unknown"}
                      </Badge>
                    </div>
                    <div>
                      <div className="font-mono text-xs text-muted-foreground mb-1 uppercase">Possible Types</div>
                      <div className="font-mono text-sm">{result.identifiedTypes.join(", ")}</div>
                    </div>
                  </div>

                  {result.pwnedChecked && (
                    <div className="mt-4 pt-4 border-t border-border">
                      {result.pwnedCount ? (
                        <div className="flex items-start gap-3 p-4 bg-destructive/10 border border-destructive/30 rounded-md">
                          <AlertTriangle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
                          <div>
                            <div className="font-mono font-bold text-destructive">COMPROMISED HASH</div>
                            <div className="font-mono text-sm text-muted-foreground mt-1">
                              Found <strong className="text-destructive">{result.pwnedCount.toLocaleString()}</strong> times in HIBP breach data.
                            </div>
                          </div>
                        </div>
                      ) : (
                        <div className="flex items-start gap-3 p-4 bg-primary/10 border border-primary/30 rounded-md">
                          <CheckCircle2 className="w-5 h-5 text-primary shrink-0 mt-0.5" />
                          <div>
                            <div className="font-mono font-bold text-primary">CLEAR</div>
                            <div className="font-mono text-sm text-primary/80 mt-1">
                              Not found in known breach data (HIBP).
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  {result.notes && (
                    <div className="font-mono text-xs text-muted-foreground mt-2 bg-muted p-2 rounded">
                      NOTE: {result.notes}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <Card className="bg-card/50 border-border">
            <CardHeader>
              <CardTitle className="font-mono text-sm uppercase text-muted-foreground">Reference</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center border-b border-border pb-2">
                  <span className="text-muted-foreground">MD5 / NTLM</span>
                  <span className="text-primary">32 chars</span>
                </div>
                <div className="flex justify-between items-center border-b border-border pb-2">
                  <span className="text-muted-foreground">SHA-1</span>
                  <span className="text-primary">40 chars</span>
                </div>
                <div className="flex justify-between items-center border-b border-border pb-2">
                  <span className="text-muted-foreground">SHA-256</span>
                  <span className="text-primary">64 chars</span>
                </div>
                <div className="flex justify-between items-center pb-2">
                  <span className="text-muted-foreground">SHA-512</span>
                  <span className="text-primary">128 chars</span>
                </div>
                <div className="pt-2 mt-2 border-t border-border text-muted-foreground leading-relaxed">
                  Breach checks (HIBP) are only available for SHA-1 hashes using the k-anonymity API.
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
