import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Copy, Wand2, ArrowUpDown, Code2 } from "lucide-react";
import {
  encodeBase64, decodeBase64,
  encodeUrl, decodeUrl,
  encodeHex, decodeHex,
  encodeHtml, decodeHtml,
  rot13,
  encodeBinary, decodeBinary,
  decodeJwt,
  autoDetect,
  type EncodingName,
} from "@/lib/encode";

type Direction = "encode" | "decode";

const TABS: { id: EncodingName; label: string; desc: string }[] = [
  { id: "base64", label: "Base64", desc: "RFC 4648 standard encoding — used in HTTP headers, data URIs, JWTs" },
  { id: "url", label: "URL", desc: "Percent-encoding for safe transmission in URLs (RFC 3986)" },
  { id: "hex", label: "Hex", desc: "Hexadecimal byte representation — common in shellcode and hashes" },
  { id: "html", label: "HTML Entities", desc: "Escape special HTML characters to prevent XSS" },
  { id: "binary", label: "Binary", desc: "Eight-bit binary groups per character — used in CTF challenges" },
  { id: "rot13", label: "ROT13", desc: "Caesar cipher shifted 13 places — symmetric, decoding = encoding" },
  { id: "jwt", label: "JWT Decode", desc: "Decode a JSON Web Token (header + payload only, no signature verify)" },
];

function run(tab: EncodingName, dir: Direction, input: string): string {
  if (!input) return "";
  switch (tab) {
    case "base64": return dir === "encode" ? encodeBase64(input).value : decodeBase64(input).value || decodeBase64(input).error || "";
    case "url": return dir === "encode" ? encodeUrl(input).value : decodeUrl(input).value || decodeUrl(input).error || "";
    case "hex": return dir === "encode" ? encodeHex(input).value : decodeHex(input).value || decodeHex(input).error || "";
    case "html": return dir === "encode" ? encodeHtml(input).value : decodeHtml(input).value;
    case "binary": return dir === "encode" ? encodeBinary(input).value : decodeBinary(input).value || decodeBinary(input).error || "";
    case "rot13": return rot13(input).value;
    case "jwt": return decodeJwt(input).value || decodeJwt(input).error || "";
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <Button variant="ghost" size="sm" onClick={copy} className="font-mono text-xs h-7 px-2 text-muted-foreground hover:text-primary">
      <Copy className="w-3 h-3 mr-1" />
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

export default function Encode() {
  const [activeTab, setActiveTab] = useState<EncodingName>("base64");
  const [direction, setDirection] = useState<Direction>("encode");
  const [input, setInput] = useState("");
  const [autoInput, setAutoInput] = useState("");

  const isJwt = activeTab === "jwt";
  const isRot13 = activeTab === "rot13";
  const effectiveDir = isJwt ? "decode" : isRot13 ? "encode" : direction;
  const output = run(activeTab, effectiveDir, input);
  const autoResults = autoDetect(autoInput);

  const swapDirection = useCallback(() => {
    if (isJwt || isRot13) return;
    setDirection((d) => (d === "encode" ? "decode" : "encode"));
    setInput(output);
  }, [isJwt, isRot13, output]);

  const activeTabMeta = TABS.find((t) => t.id === activeTab)!;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">Payload Encoder</h1>
        <p className="text-muted-foreground mt-1 font-mono text-sm">Encode, decode and analyze encoded payloads — essential for CTF and attack analysis</p>
      </div>

      <Tabs value={activeTab} onValueChange={(v) => { setActiveTab(v as EncodingName); setInput(""); }}>
        <TabsList className="bg-muted/50 border border-border flex flex-wrap h-auto gap-1 p-1">
          {TABS.map((t) => (
            <TabsTrigger
              key={t.id}
              value={t.id}
              className="font-mono text-xs uppercase data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
            >
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

        {TABS.map((tab) => (
          <TabsContent key={tab.id} value={tab.id} className="mt-4 space-y-4">
            <div className="text-xs font-mono text-muted-foreground bg-muted/30 border border-border rounded px-3 py-2">
              <Code2 className="w-3.5 h-3.5 inline mr-2 text-primary" />
              {tab.desc}
            </div>

            {!isJwt && !isRot13 && (
              <div className="flex items-center gap-3">
                <Badge
                  className={`font-mono uppercase text-xs cursor-pointer ${effectiveDir === "encode" ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"}`}
                  onClick={() => setDirection("encode")}
                >
                  Encode
                </Badge>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={swapDirection}
                  className="h-7 w-7 p-0 text-muted-foreground hover:text-primary"
                  title="Swap direction and transfer output to input"
                >
                  <ArrowUpDown className="w-4 h-4" />
                </Button>
                <Badge
                  className={`font-mono uppercase text-xs cursor-pointer ${effectiveDir === "decode" ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"}`}
                  onClick={() => setDirection("decode")}
                >
                  Decode
                </Badge>
              </div>
            )}

            {isJwt && (
              <div className="text-xs font-mono text-amber-400 bg-amber-500/10 border border-amber-500/30 rounded px-3 py-2">
                Decode-only mode. Signatures are NOT verified — this tool shows claims for inspection, not authentication.
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card className="bg-card/50 border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="font-mono text-xs uppercase text-muted-foreground flex items-center justify-between">
                    <span>Input {isJwt ? "(JWT)" : effectiveDir === "encode" ? "(Plaintext)" : "(Encoded)"}</span>
                    <CopyButton text={input} />
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <Textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={
                      isJwt
                        ? "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                        : effectiveDir === "encode"
                          ? "Enter plaintext to encode..."
                          : "Paste encoded value to decode..."
                    }
                    className="font-mono text-xs min-h-[140px] bg-muted/50 border-border focus-visible:ring-primary resize-none"
                  />
                </CardContent>
              </Card>

              <Card className={`border-border overflow-hidden ${output ? "bg-card/50" : "bg-muted/20"}`}>
                <CardHeader className="pb-2">
                  <CardTitle className="font-mono text-xs uppercase text-muted-foreground flex items-center justify-between">
                    <span>Output {isRot13 ? "(ROT13)" : effectiveDir === "encode" ? "(Encoded)" : "(Decoded)"}</span>
                    {output && <CopyButton text={output} />}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="font-mono text-xs min-h-[140px] bg-muted/50 rounded border border-border p-3 whitespace-pre-wrap break-all text-foreground overflow-auto max-h-[400px]">
                    {output || <span className="text-muted-foreground italic">Output will appear here</span>}
                  </pre>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        ))}
      </Tabs>

      <Card className="bg-card/50 border-border">
        <CardHeader>
          <CardTitle className="font-mono text-sm uppercase flex items-center gap-2">
            <Wand2 className="w-4 h-4 text-primary" />
            Auto-Detect Encoding
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="text-xs font-mono text-muted-foreground">
            Paste an unknown payload to automatically detect its encoding format(s).
          </div>
          <Textarea
            value={autoInput}
            onChange={(e) => setAutoInput(e.target.value)}
            placeholder="Paste any encoded string here..."
            className="font-mono text-xs min-h-[80px] bg-muted/50 border-border focus-visible:ring-primary"
          />
          {autoInput && (
            <div className="space-y-3">
              {autoResults.length === 0 ? (
                <div className="text-xs font-mono text-muted-foreground bg-muted/30 border border-border rounded px-3 py-2">
                  No known encoding detected. Could be plaintext, proprietary encoding, or a cipher.
                </div>
              ) : (
                autoResults.map((r) => (
                  <div key={r.name} className="bg-muted/30 border border-border rounded p-3 space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-xs text-primary uppercase">{r.label}</span>
                      <Badge
                        variant="outline"
                        className={`text-[10px] font-mono uppercase ${r.confidence === "high" ? "border-primary/60 text-primary" : "border-muted text-muted-foreground"}`}
                      >
                        {r.confidence} confidence
                      </Badge>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2 text-xs font-mono text-muted-foreground hover:text-primary ml-auto"
                        onClick={() => {
                          setActiveTab(r.name);
                          setInput(autoInput);
                          setDirection("decode");
                        }}
                      >
                        Open in {r.label}
                      </Button>
                    </div>
                    <pre className="font-mono text-xs text-foreground whitespace-pre-wrap break-all bg-muted/50 rounded border border-border p-2 max-h-[120px] overflow-auto">
                      {r.decoded}
                    </pre>
                  </div>
                ))
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {!input && !autoInput && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono text-muted-foreground">
          {[
            { label: "Base64 example", value: "dXNlcjpwYXNzd29yZA==", note: "Decodes to user:password — common in HTTP Basic Auth" },
            { label: "JWT example", value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", note: "JWT with sub, name, iat claims" },
            { label: "XSS payload", value: "%3Cscript%3Ealert%281%29%3C%2Fscript%3E", note: "URL-encoded XSS — paste into URL decoder" },
          ].map((ex) => (
            <div
              key={ex.label}
              className="bg-muted/30 border border-border/50 rounded p-3 cursor-pointer hover:border-primary/30 hover:bg-primary/5 transition-colors"
              onClick={() => {
                setAutoInput(ex.value);
              }}
            >
              <div className="text-primary uppercase mb-1">{ex.label}</div>
              <div className="truncate mb-2 text-foreground">{ex.value.slice(0, 40)}...</div>
              <div className="text-[10px] text-muted-foreground">{ex.note}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
