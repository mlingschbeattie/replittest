import { Router, type IRouter } from "express";
import { RunScanBody, RunScanResponse } from "@workspace/api-zod";
import { recordScan } from "../lib/activity";

const router: IRouter = Router();

const TIMEOUT_MS = 8000;

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Finding = {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence?: string;
};

async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent":
          "SentinelLab/1.0 (+passive-scanner; lab use only)",
        ...(init.headers ?? {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

function normalizeUrl(input: string): URL | null {
  try {
    let candidate = input.trim();
    if (!/^https?:\/\//i.test(candidate)) {
      candidate = `https://${candidate}`;
    }
    const url = new URL(candidate);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url;
  } catch {
    return null;
  }
}

function isPrivateHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (lower === "localhost" || lower.endsWith(".local")) return true;
  if (lower === "0.0.0.0") return true;
  // 127.0.0.0/8
  if (/^127\./.test(lower)) return true;
  // 10.0.0.0/8
  if (/^10\./.test(lower)) return true;
  // 192.168.0.0/16
  if (/^192\.168\./.test(lower)) return true;
  // 169.254.0.0/16 link local
  if (/^169\.254\./.test(lower)) return true;
  // 172.16.0.0/12
  const m = lower.match(/^172\.(\d{1,3})\./);
  if (m) {
    const n = Number(m[1]);
    if (n >= 16 && n <= 31) return true;
  }
  // IPv6 loopback / link-local
  if (lower === "::1" || lower.startsWith("fe80:")) return true;
  return false;
}

function checkSecurityHeaders(headers: Headers): Finding[] {
  const findings: Finding[] = [];
  const lower = (k: string) => headers.get(k) ?? headers.get(k.toLowerCase());

  if (!lower("x-frame-options") && !lower("content-security-policy")) {
    findings.push({
      id: "missing-x-frame-options",
      title: "Missing X-Frame-Options",
      severity: "medium",
      category: "security-headers",
      description:
        "Neither X-Frame-Options nor a CSP frame-ancestors directive was set. The page may be vulnerable to clickjacking.",
    });
  }

  const csp = lower("content-security-policy");
  if (!csp) {
    findings.push({
      id: "missing-csp",
      title: "Missing Content-Security-Policy",
      severity: "high",
      category: "security-headers",
      description:
        "No Content-Security-Policy header found. CSP is the strongest defense against XSS and content injection.",
    });
  } else if (/unsafe-inline/i.test(csp) || /unsafe-eval/i.test(csp)) {
    findings.push({
      id: "weak-csp",
      title: "Permissive CSP directives",
      severity: "medium",
      category: "security-headers",
      description:
        "CSP allows 'unsafe-inline' or 'unsafe-eval', which significantly weakens the policy.",
      evidence: csp.length > 200 ? `${csp.slice(0, 200)}…` : csp,
    });
  }

  const hsts = lower("strict-transport-security");
  if (!hsts) {
    findings.push({
      id: "missing-hsts",
      title: "Missing Strict-Transport-Security (HSTS)",
      severity: "medium",
      category: "security-headers",
      description:
        "HSTS header not present. Browsers may downgrade to plaintext HTTP on subsequent visits.",
    });
  } else {
    const maxAgeMatch = hsts.match(/max-age\s*=\s*(\d+)/i);
    if (maxAgeMatch && Number(maxAgeMatch[1]) < 15552000) {
      findings.push({
        id: "weak-hsts",
        title: "HSTS max-age below recommended threshold",
        severity: "low",
        category: "security-headers",
        description:
          "HSTS max-age is shorter than 6 months. The recommended minimum is 15552000 seconds (180 days).",
        evidence: hsts,
      });
    }
  }

  if (!lower("x-content-type-options")) {
    findings.push({
      id: "missing-x-content-type-options",
      title: "Missing X-Content-Type-Options",
      severity: "low",
      category: "security-headers",
      description:
        "Without 'nosniff', browsers may MIME-sniff responses, potentially leading to XSS via untrusted uploads.",
    });
  }

  if (!lower("referrer-policy")) {
    findings.push({
      id: "missing-referrer-policy",
      title: "Missing Referrer-Policy",
      severity: "info",
      category: "security-headers",
      description:
        "Referrer-Policy not set. Browser default may leak full URLs to third parties.",
    });
  }

  const server = lower("server");
  if (server && /\d/.test(server)) {
    findings.push({
      id: "server-version-disclosure",
      title: "Server header discloses version",
      severity: "low",
      category: "information-disclosure",
      description:
        "The Server response header reveals software and version, aiding attackers in fingerprinting.",
      evidence: server,
    });
  }

  const xPoweredBy = lower("x-powered-by");
  if (xPoweredBy) {
    findings.push({
      id: "x-powered-by-disclosure",
      title: "X-Powered-By header present",
      severity: "info",
      category: "information-disclosure",
      description:
        "X-Powered-By reveals backend technology. Consider removing.",
      evidence: xPoweredBy,
    });
  }

  return findings;
}

async function checkExposedPath(
  base: URL,
  path: string,
  meta: { title: string; severity: Severity; description: string },
): Promise<Finding | null> {
  try {
    const target = new URL(path, base);
    const res = await fetchWithTimeout(target.toString(), { method: "GET" });
    if (res.status >= 200 && res.status < 400) {
      return {
        id: `exposed-${path.replace(/[^a-z0-9]/gi, "-")}`,
        title: meta.title,
        severity: meta.severity,
        category: "exposed-path",
        description: meta.description,
        evidence: `HTTP ${res.status} ${target.pathname}`,
      };
    }
  } catch {
    /* ignore network errors per path */
  }
  return null;
}

async function checkDirectoryListing(base: URL): Promise<Finding | null> {
  try {
    const res = await fetchWithTimeout(base.toString(), { method: "GET" });
    if (!res.ok) return null;
    const text = (await res.text()).slice(0, 8000);
    if (
      /<title>\s*Index of /i.test(text) ||
      /<h1>Index of /i.test(text) ||
      /Directory listing for /i.test(text)
    ) {
      return {
        id: "directory-listing",
        title: "Open directory listing",
        severity: "high",
        category: "exposed-path",
        description:
          "Server returned an auto-indexed directory listing, exposing file names and structure.",
        evidence: text.match(/<title>([^<]*)<\/title>/i)?.[1],
      };
    }
  } catch {
    /* ignore */
  }
  return null;
}

async function checkDefaultCredentialsForm(base: URL): Promise<Finding | null> {
  try {
    const res = await fetchWithTimeout(new URL("/", base).toString(), {
      method: "GET",
    });
    const text = (await res.text()).slice(0, 16000).toLowerCase();
    const looksLikeLogin =
      /<input[^>]+type=["']?password["']?/.test(text) &&
      (/admin/.test(text) ||
        /sign in/.test(text) ||
        /login/.test(text) ||
        /username/.test(text));
    const defaultHints =
      /(default password|admin\/admin|admin:admin|root\/root)/i.test(text);
    if (looksLikeLogin && defaultHints) {
      return {
        id: "default-creds-hint",
        title: "Login form references default credentials",
        severity: "high",
        category: "authentication",
        description:
          "Page contains a login form and references default credentials such as admin/admin. Verify these are not active.",
      };
    }
  } catch {
    /* ignore */
  }
  return null;
}

router.post("/scan", async (req, res): Promise<void> => {
  const parsed = RunScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const url = normalizeUrl(parsed.data.url);
  if (!url) {
    res
      .status(400)
      .json({ error: "Invalid URL. Provide a full http(s) URL." });
    return;
  }

  if (isPrivateHost(url.hostname)) {
    res.status(400).json({
      error: "Refusing to scan internal/private host.",
      detail:
        "Lab safety: scans against localhost, RFC1918, or link-local addresses are blocked.",
    });
    return;
  }

  const startedAt = Date.now();
  let response: Response;
  try {
    response = await fetchWithTimeout(url.toString(), { method: "GET" });
  } catch (err) {
    req.log.warn({ err: String(err) }, "Scan target unreachable");
    res.status(200).json(
      RunScanResponse.parse({
        target: url.toString(),
        scannedAt: new Date().toISOString(),
        durationMs: Date.now() - startedAt,
        findings: [
          {
            id: "unreachable",
            title: "Target unreachable",
            severity: "info",
            category: "transport",
            description: `Could not establish a connection: ${String(err)}`,
          },
        ],
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 1 },
      }),
    );
    return;
  }

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });

  const findings: Finding[] = [];

  if (url.protocol === "http:") {
    findings.push({
      id: "no-https",
      title: "Site served over plaintext HTTP",
      severity: "high",
      category: "transport",
      description:
        "The target responded over HTTP. All credentials, cookies, and tokens are visible to network observers.",
    });
  }

  findings.push(...checkSecurityHeaders(response.headers));

  // Cookie security
  const setCookie = response.headers.get("set-cookie");
  if (setCookie) {
    if (!/;\s*secure/i.test(setCookie)) {
      findings.push({
        id: "cookie-missing-secure",
        title: "Cookie missing Secure flag",
        severity: "medium",
        category: "cookies",
        description:
          "A Set-Cookie header was returned without the Secure attribute. Cookies may be sent over HTTP.",
      });
    }
    if (!/;\s*httponly/i.test(setCookie)) {
      findings.push({
        id: "cookie-missing-httponly",
        title: "Cookie missing HttpOnly flag",
        severity: "medium",
        category: "cookies",
        description:
          "Cookies without HttpOnly are accessible from JavaScript and exposed to XSS.",
      });
    }
  }

  // Run path probes in parallel
  const probes: Array<Promise<Finding | null>> = [
    checkExposedPath(url, "/admin", {
      title: "/admin path is reachable",
      severity: "high",
      description:
        "An /admin endpoint returned a non-error response. Verify it requires authentication.",
    }),
    checkExposedPath(url, "/phpmyadmin/", {
      title: "/phpmyadmin/ is reachable",
      severity: "critical",
      description:
        "phpMyAdmin should not be exposed publicly. Restrict access by IP or VPN.",
    }),
    checkExposedPath(url, "/.env", {
      title: ".env file exposed",
      severity: "critical",
      description:
        "A .env file is publicly readable, likely leaking secrets and credentials.",
    }),
    checkExposedPath(url, "/.git/config", {
      title: ".git directory exposed",
      severity: "critical",
      description:
        "The .git directory is web-accessible. Source code, history, and credentials may be exfiltrated.",
    }),
    checkExposedPath(url, "/server-status", {
      title: "Apache server-status exposed",
      severity: "high",
      description:
        "Apache server-status reveals request URLs, IPs, and worker state.",
    }),
    checkExposedPath(url, "/wp-admin/", {
      title: "WordPress wp-admin reachable",
      severity: "medium",
      description:
        "wp-admin is reachable. Ensure strong credentials and 2FA are enforced.",
    }),
    checkDirectoryListing(url),
    checkDefaultCredentialsForm(url),
  ];

  const probeResults = await Promise.all(probes);
  for (const f of probeResults) if (f) findings.push(f);

  if (findings.length === 0) {
    findings.push({
      id: "clean-pass",
      title: "No issues detected by passive checks",
      severity: "info",
      category: "summary",
      description:
        "Passive checks did not surface any common misconfigurations. This is not a guarantee of security.",
    });
  }

  const summary = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  recordScan(url.hostname, summary.critical);

  const result = {
    target: url.toString(),
    scannedAt: new Date().toISOString(),
    finalUrl: response.url || url.toString(),
    statusCode: response.status,
    durationMs: Date.now() - startedAt,
    headers,
    findings,
    summary,
  };

  res.json(RunScanResponse.parse(result));
});

export default router;
