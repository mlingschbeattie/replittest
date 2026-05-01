import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ShieldCheck, ShieldX, Eye, EyeOff, Clock, Zap, CheckCircle2, XCircle, AlertTriangle, ExternalLink } from "lucide-react";
import { analyzePassword, type PasswordAnalysis } from "@/lib/password";
import { useCheckHash } from "@workspace/api-client-react";
import { Progress } from "@/components/ui/progress";

const CLASS_LABELS: { key: keyof PasswordAnalysis["classes"]; label: string }[] = [
  { key: "lowercase", label: "Lowercase a-z" },
  { key: "uppercase", label: "Uppercase A-Z" },
  { key: "digits", label: "Digits 0-9" },
  { key: "symbols", label: "Symbols !@#..." },
  { key: "spaces", label: "Spaces" },
];

const COLOR_MAP: Record<PasswordAnalysis["color"], string> = {
  critical: "bg-[hsl(var(--color-severity-critical))]",
  high: "bg-[hsl(var(--color-severity-high))]",
  medium: "bg-[hsl(var(--color-severity-medium))]",
  low: "bg-[hsl(var(--color-severity-low))]",
  info: "bg-primary",
};

const TEXT_COLOR_MAP: Record<PasswordAnalysis["color"], string> = {
  critical: "text-destructive",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-yellow-400",
  info: "text-primary",
};

const PROGRESS_MAP: Record<0 | 1 | 2 | 3 | 4, number> = {
  0: 8, 1: 25, 2: 50, 3: 75, 4: 100,
};

async function sha1(str: string): Promise<string> {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-1", enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

const EXAMPLES = [
  { label: "Very Weak", pw: "123456" },
  { label: "Weak", pw: "monkey1!" },
  { label: "Fair", pw: "Tr0ub4dor&3" },
  { label: "Strong", pw: "c0rr3ct-H0rse#Batt3ry" },
  { label: "Very Strong", pw: "7$kM!qP2@xLv&Rn9^JhD" },
];

export default function Password() {
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [hibpHash, setHibpHash] = useState<string | null>(null);
  const [hibpLoading, setHibpLoading] = useState(false);

  const analysis: PasswordAnalysis | null = useMemo(
    () => (password ? analyzePassword(password) : null),
    [password],
  );

  const hashMutation = useCheckHash();

  const checkHibp = async () => {
    if (!password) return;
    setHibpLoading(true);
    try {
      const hash = await sha1(password);
      setHibpHash(hash);
      await hashMutation.mutateAsync({ data: { hash } });
    } catch {
      // handled via mutation state
    } finally {
      setHibpLoading(false);
    }
  };

  const hibpResult = hashMutation.data;
  const hibpBreached = (hibpResult?.pwnedCount ?? 0) > 0;
  const hibpCount = hibpResult?.pwnedCount ?? 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Password Analyzer</h1>
        <p className="text-muted-foreground mt-1 font-mono text-sm">Entropy, crack-time estimation, and breach check</p>
      </div>

      <Card className="bg-card/50 border-border">
        <CardContent className="pt-6 space-y-4">
          <div className="relative">
            <Input
              type={show ? "text" : "password"}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                setHibpHash(null);
                hashMutation.reset();
              }}
              placeholder="Enter a password to analyze..."
              className="font-mono pr-10 bg-muted/50 border-border focus-visible:ring-primary text-sm"
            />
            <button
              type="button"
              onClick={() => setShow((s) => !s)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>

          {analysis && (
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className={`uppercase font-bold ${TEXT_COLOR_MAP[analysis.color]}`}>{analysis.label}</span>
                <span className="text-muted-foreground">{analysis.entropy} bits effective entropy</span>
              </div>
              <Progress
                value={PROGRESS_MAP[analysis.score]}
                className={`h-2 [&>div]:${COLOR_MAP[analysis.color]} [&>div]:transition-all [&>div]:duration-500`}
              />
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            {EXAMPLES.map((ex) => (
              <Button
                key={ex.label}
                variant="outline"
                size="sm"
                onClick={() => { setPassword(ex.pw); hashMutation.reset(); setHibpHash(null); }}
                className="font-mono text-xs border-border hover:border-primary/50 hover:text-primary"
              >
                {ex.label}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {analysis && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in duration-500">
          <div className="lg:col-span-2 space-y-6">
            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase">Crack Time Estimates</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs font-mono text-muted-foreground mb-4">
                  Based on {analysis.entropy} bits of effective entropy. Assumes attacker knows the password hash algorithm.
                </div>
                <div className="divide-y divide-border">
                  {analysis.crackTimes.map((ct) => (
                    <div key={ct.scenario} className="flex items-center justify-between py-3">
                      <div className="flex items-center gap-2">
                        {ct.scenario.includes("Online") ? (
                          <Clock className="w-3.5 h-3.5 text-muted-foreground" />
                        ) : (
                          <Zap className="w-3.5 h-3.5 text-muted-foreground" />
                        )}
                        <span className="font-mono text-xs">{ct.scenario}</span>
                      </div>
                      <span
                        className={`font-mono text-xs font-bold ${
                          ct.time === "instant" || ct.time.includes("s") && !ct.time.includes("year")
                            ? "text-destructive"
                            : ct.time.includes("m") && !ct.time.includes("month")
                              ? "text-orange-400"
                              : ct.time.includes("h") || ct.time.includes("d")
                                ? "text-amber-400"
                                : "text-primary"
                        }`}
                      >
                        {ct.time}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {analysis.patterns.length > 0 && (
              <Card className="bg-destructive/10 border-destructive/30">
                <CardHeader>
                  <CardTitle className="font-mono text-sm uppercase text-destructive flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    Weakness Patterns ({analysis.patterns.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {analysis.patterns.map((p, i) => (
                    <div key={i} className="p-3 bg-destructive/10 border border-destructive/20 rounded">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono text-xs font-bold text-destructive uppercase">{p.name}</span>
                        <Badge variant="outline" className="font-mono text-[10px] border-destructive/40 text-destructive">
                          -{p.penaltyBits} bits
                        </Badge>
                      </div>
                      <p className="font-mono text-xs text-muted-foreground">{p.description}</p>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase flex items-center gap-2">
                  <ShieldX className="w-4 h-4 text-primary" />
                  HaveIBeenPwned Breach Check
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="font-mono text-xs text-muted-foreground">
                  Checks a SHA-1 hash of your password against known breach databases using k-anonymity (only the first 5 characters of the hash are sent).
                </p>
                {!hibpHash ? (
                  <Button
                    onClick={checkHibp}
                    disabled={hibpLoading || !password}
                    variant="outline"
                    className="font-mono text-xs border-primary/50 text-primary hover:bg-primary/10"
                  >
                    <ShieldCheck className="w-4 h-4 mr-2" />
                    {hibpLoading ? "Checking..." : "Check Breach Databases"}
                  </Button>
                ) : hibpResult ? (
                  <div className={`p-3 rounded border font-mono text-xs ${hibpBreached ? "bg-destructive/10 border-destructive/40 text-destructive" : "bg-primary/10 border-primary/30 text-primary"}`}>
                    {hibpBreached ? (
                      <>
                        <XCircle className="w-4 h-4 inline mr-2" />
                        Found in {hibpCount.toLocaleString()} breach records. This password has been compromised — do not use it.
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-4 h-4 inline mr-2" />
                        Not found in breach databases. That said, a strong password is still required.
                      </>
                    )}
                  </div>
                ) : hashMutation.isError ? (
                  <div className="p-3 rounded border border-muted font-mono text-xs text-muted-foreground">
                    Could not reach breach database. Check network connectivity.
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </div>

          <div className="space-y-6">
            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase">Composition</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div>
                    <div className="text-muted-foreground uppercase">Length</div>
                    <div className="text-lg text-primary">{analysis.length}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground uppercase">Pool</div>
                    <div className="text-lg text-primary">{analysis.poolSize}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground uppercase">Entropy</div>
                    <div className="text-lg text-primary">{analysis.entropy} bits</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground uppercase">Score</div>
                    <div className={`text-lg font-bold ${TEXT_COLOR_MAP[analysis.color]}`}>{analysis.score}/4</div>
                  </div>
                </div>

                <div className="space-y-2 pt-2 border-t border-border">
                  <div className="font-mono text-xs text-muted-foreground uppercase mb-2">Character Classes</div>
                  {CLASS_LABELS.map(({ key, label }) => (
                    <div key={key} className="flex items-center gap-2 font-mono text-xs">
                      {analysis.classes[key] ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-primary shrink-0" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      )}
                      <span className={analysis.classes[key] ? "text-foreground" : "text-muted-foreground"}>
                        {label}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-border">
              <CardHeader>
                <CardTitle className="font-mono text-sm uppercase">Teaching Notes</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 font-mono text-xs text-muted-foreground">
                <p>Entropy = log2(pool^length). Every extra character multiplies the search space by the pool size.</p>
                <p>bcrypt/argon2 slow hashes make GPU attacks impractical — entropy requirements are lower than for MD5/SHA1.</p>
                <p>Passphrases (4+ random words) are more memorable AND more secure than complex short passwords.</p>
                <a
                  href="https://pages.nist.gov/800-63-3/sp800-63b.html"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-primary hover:underline"
                >
                  <ExternalLink className="w-3 h-3" /> NIST SP 800-63B Password Guidelines
                </a>
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {!password && (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground border-2 border-dashed border-border rounded-lg bg-card/20">
          <ShieldCheck className="w-12 h-12 mb-4 opacity-50" />
          <p className="font-mono text-sm">Type a password above or click an example to see the full analysis.</p>
        </div>
      )}
    </div>
  );
}
