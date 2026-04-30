import { useState } from "react";
import {
  useSearchCves,
  useGetCveById,
  getSearchCvesQueryKey,
  getGetCveByIdQueryKey,
} from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Search, ShieldAlert, CheckCircle2, XCircle, ExternalLink } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";

function CveCard({ cve }: { cve: any }) {
  return (
    <Card className="bg-card/50 border-border">
      <CardHeader className="flex flex-row items-start justify-between pb-2 border-b border-border bg-muted/20">
        <div>
          <CardTitle className="font-mono text-lg text-primary">{cve.id}</CardTitle>
          <div className="flex items-center gap-4 mt-2">
            <SeverityBadge severity={cve.cvssSeverity} />
            <span className="font-mono text-xs text-muted-foreground">CVSS: {cve.cvssScore || 'N/A'}</span>
            {cve.cvssVector && <span className="font-mono text-xs text-muted-foreground hidden md:inline">{cve.cvssVector}</span>}
          </div>
        </div>
        {cve.patchAvailable ? (
          <div className="flex items-center gap-1 text-primary font-mono text-xs bg-primary/10 px-2 py-1 rounded">
            <CheckCircle2 className="w-3 h-3" /> PATCH
          </div>
        ) : (
          <div className="flex items-center gap-1 text-destructive font-mono text-xs bg-destructive/10 px-2 py-1 rounded">
            <XCircle className="w-3 h-3" /> NO PATCH
          </div>
        )}
      </CardHeader>
      <CardContent className="pt-4 space-y-4">
        <p className="text-sm font-sans text-muted-foreground leading-relaxed">{cve.description}</p>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-border">
          <div>
            <h4 className="font-mono text-xs uppercase text-muted-foreground mb-2">Affected Products</h4>
            <div className="flex flex-wrap gap-2">
              {cve.affectedProducts?.map((p: string, i: number) => (
                <span key={i} className="font-mono text-xs bg-muted px-2 py-1 rounded">{p}</span>
              ))}
              {(!cve.affectedProducts || cve.affectedProducts.length === 0) && (
                <span className="font-mono text-xs text-muted-foreground">Unknown</span>
              )}
            </div>
          </div>
          <div>
            <h4 className="font-mono text-xs uppercase text-muted-foreground mb-2">References</h4>
            <div className="space-y-1">
              {cve.references?.slice(0,3).map((ref: any, i: number) => (
                <a key={i} href={ref.url} target="_blank" rel="noreferrer" className="flex items-center gap-2 font-mono text-xs text-primary hover:underline truncate">
                  <ExternalLink className="w-3 h-3 shrink-0" />
                  <span className="truncate">{ref.url}</span>
                </a>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function Cve() {
  const [query, setQuery] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState("");

  const isCveId = submittedQuery.match(/^CVE-\d{4}-\d{4,}$/i);
  const keyword = !isCveId && submittedQuery ? submittedQuery : "";
  const idQuery = isCveId ? submittedQuery.toUpperCase() : "";

  const { data: searchResults, isFetching: isSearching } = useSearchCves(
    { keyword, limit: 10 },
    {
      query: {
        enabled: !!keyword,
        queryKey: getSearchCvesQueryKey({ keyword, limit: 10 }),
      },
    },
  );

  const { data: singleResult, isFetching: isFetchingId } = useGetCveById(
    idQuery,
    {
      query: {
        enabled: !!idQuery,
        queryKey: getGetCveByIdQueryKey(idQuery),
      },
    },
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    setSubmittedQuery(query.trim());
  };

  const isFetching = isSearching || isFetchingId;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-foreground uppercase tracking-widest">CVE Lookup</h1>
        <p className="text-muted-foreground mt-1 font-mono text-sm">Query NVD database by ID or keyword</p>
      </div>

      <Card className="bg-card/50 border-border">
        <CardContent className="pt-6">
          <form onSubmit={handleSubmit} className="flex gap-4">
            <Input 
              placeholder="e.g. CVE-2021-44228 or log4j" 
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="font-mono bg-muted/50 border-border focus-visible:ring-primary max-w-md"
            />
            <Button type="submit" disabled={isFetching || !query} className="font-mono uppercase bg-primary text-primary-foreground hover:bg-primary/90">
              <Search className="w-4 h-4 mr-2" />
              Search
            </Button>
          </form>
        </CardContent>
      </Card>

      {isFetching && (
        <div className="flex items-center justify-center py-12 text-primary font-mono">
          <ShieldAlert className="w-6 h-6 animate-pulse mr-2" />
          QUERYING DATABASE...
        </div>
      )}

      <div className="space-y-4 animate-in fade-in duration-500">
        {singleResult && (
          <CveCard cve={singleResult} />
        )}
        
        {searchResults && searchResults.items.map((cve: any) => (
          <CveCard key={cve.id} cve={cve} />
        ))}

        {!isFetching && submittedQuery && !singleResult && (!searchResults || searchResults.items.length === 0) && (
          <div className="text-center py-12 text-muted-foreground border border-border bg-card/20 rounded font-mono text-sm">
            NO RESULTS FOUND FOR "{submittedQuery}"
          </div>
        )}
      </div>

      {!submittedQuery && (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground border-2 border-dashed border-border rounded-lg bg-card/20">
          <Search className="w-12 h-12 mb-4 opacity-50" />
          <p className="font-mono text-sm">Enter a CVE ID or keyword to search the vulnerability database.</p>
        </div>
      )}
    </div>
  );
}
