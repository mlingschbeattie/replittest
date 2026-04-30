import { Router, type IRouter } from "express";
import {
  GetCveByIdParams,
  GetCveByIdResponse,
  SearchCvesQueryParams,
  SearchCvesResponse,
} from "@workspace/api-zod";
import { recordCveLookup } from "../lib/activity";

const router: IRouter = Router();

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_API_KEY = process.env["NVD_API_KEY"];

type NvdResponse = {
  totalResults?: number;
  vulnerabilities?: Array<{ cve?: NvdCve }>;
};

type NvdCve = {
  id?: string;
  published?: string;
  lastModified?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  metrics?: {
    cvssMetricV31?: Array<{
      cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
    }>;
    cvssMetricV30?: Array<{
      cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
    }>;
    cvssMetricV2?: Array<{
      cvssData?: { baseScore?: number; vectorString?: string };
      baseSeverity?: string;
    }>;
  };
  weaknesses?: Array<{
    description?: Array<{ lang?: string; value?: string }>;
  }>;
  configurations?: Array<{
    nodes?: Array<{
      cpeMatch?: Array<{ criteria?: string; vulnerable?: boolean }>;
    }>;
  }>;
  references?: Array<{ url?: string; source?: string; tags?: string[] }>;
};

function transformCve(cve: NvdCve) {
  const description =
    cve.descriptions?.find((d) => d.lang === "en")?.value ?? "";

  let cvssScore: number | null = null;
  let cvssSeverity: string | null = null;
  let cvssVector: string | null = null;

  const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  const v30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const v2Entry = cve.metrics?.cvssMetricV2?.[0];

  if (v31) {
    cvssScore = v31.baseScore ?? null;
    cvssSeverity = v31.baseSeverity ?? null;
    cvssVector = v31.vectorString ?? null;
  } else if (v30) {
    cvssScore = v30.baseScore ?? null;
    cvssSeverity = v30.baseSeverity ?? null;
    cvssVector = v30.vectorString ?? null;
  } else if (v2Entry) {
    cvssScore = v2Entry.cvssData?.baseScore ?? null;
    cvssSeverity = v2Entry.baseSeverity ?? null;
    cvssVector = v2Entry.cvssData?.vectorString ?? null;
  }

  const cweIds: string[] = [];
  for (const w of cve.weaknesses ?? []) {
    for (const d of w.description ?? []) {
      if (d.lang === "en" && d.value && /CWE-/.test(d.value)) {
        cweIds.push(d.value);
      }
    }
  }

  const productSet = new Set<string>();
  for (const cfg of cve.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const cpe of node.cpeMatch ?? []) {
        if (cpe.vulnerable && cpe.criteria) {
          // cpe:2.3:a:vendor:product:version:...
          const parts = cpe.criteria.split(":");
          if (parts.length > 5) {
            const vendor = parts[3];
            const product = parts[4];
            if (vendor && product) productSet.add(`${vendor} ${product}`);
          }
        }
      }
    }
  }

  const refs = (cve.references ?? []).slice(0, 12).map((r) => ({
    url: r.url ?? "",
    source: r.source ?? null,
  }));

  const patchAvailable = (cve.references ?? []).some((r) =>
    (r.tags ?? []).some((t) => /Patch|Vendor Advisory/i.test(t)),
  );

  return GetCveByIdResponse.parse({
    id: cve.id ?? "",
    published: cve.published,
    lastModified: cve.lastModified,
    description,
    cvssScore,
    cvssSeverity,
    cvssVector,
    cweIds: Array.from(new Set(cweIds)),
    affectedProducts: Array.from(productSet).slice(0, 30),
    references: refs,
    patchAvailable,
  });
}

async function nvdFetch(query: string): Promise<NvdResponse> {
  const headers: Record<string, string> = {
    "User-Agent": "SentinelLab/1.0",
  };
  if (NVD_API_KEY) {
    headers["apiKey"] = NVD_API_KEY;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  try {
    const res = await fetch(`${NVD_BASE}?${query}`, {
      headers,
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`NVD responded ${res.status}`);
    }
    return (await res.json()) as NvdResponse;
  } finally {
    clearTimeout(timer);
  }
}

router.get("/cve/search", async (req, res): Promise<void> => {
  const parsed = SearchCvesQueryParams.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const { keyword, limit } = parsed.data;
  const finalLimit = limit ?? 20;
  try {
    const data = await nvdFetch(
      `keywordSearch=${encodeURIComponent(
        keyword,
      )}&resultsPerPage=${finalLimit}`,
    );
    const items = (data.vulnerabilities ?? [])
      .map((v) => v.cve)
      .filter((c): c is NvdCve => Boolean(c))
      .map(transformCve);
    recordCveLookup(`Search: "${keyword}" (${items.length} results)`);
    res.json(
      SearchCvesResponse.parse({
        keyword,
        totalResults: data.totalResults ?? items.length,
        items,
      }),
    );
  } catch (err) {
    req.log.error({ err: String(err) }, "NVD search failed");
    res.status(502).json({
      error: "Upstream NVD request failed",
      detail: String(err),
    });
  }
});

router.get("/cve/:id", async (req, res): Promise<void> => {
  const parsed = GetCveByIdParams.safeParse(req.params);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const id = parsed.data.id;
  if (!/^CVE-\d{4}-\d{4,7}$/i.test(id)) {
    res.status(400).json({
      error: "Invalid CVE ID format. Expected CVE-YYYY-NNNN.",
    });
    return;
  }
  try {
    const data = await nvdFetch(`cveId=${encodeURIComponent(id.toUpperCase())}`);
    const first = data.vulnerabilities?.[0]?.cve;
    if (!first) {
      res.status(404).json({ error: `CVE ${id} not found` });
      return;
    }
    recordCveLookup(`Lookup: ${id.toUpperCase()}`);
    res.json(transformCve(first));
  } catch (err) {
    req.log.error({ err: String(err) }, "NVD lookup failed");
    res.status(502).json({
      error: "Upstream NVD request failed",
      detail: String(err),
    });
  }
});

export default router;
