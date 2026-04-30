export type LogFinding = {
  id: string;
  category: "brute-force" | "404-sweep" | "sqli" | "unusual-ua" | "info";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  ip?: string;
  userAgent?: string;
  count: number;
  examples: string[];
};

type ParsedLogLine = {
  raw: string;
  ip?: string;
  method?: string;
  path?: string;
  status?: number;
  userAgent?: string;
};

const APACHE_RE =
  /^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?/;

function parseLine(line: string): ParsedLogLine {
  const m = line.match(APACHE_RE);
  if (m) {
    return {
      raw: line,
      ip: m[1],
      method: m[2],
      path: m[3],
      status: Number(m[4]),
      userAgent: m[5],
    };
  }
  // Loose IP extraction for other formats
  const ipMatch = line.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
  const statusMatch = line.match(/\s(\d{3})\s/);
  return {
    raw: line,
    ip: ipMatch?.[1],
    status: statusMatch ? Number(statusMatch[1]) : undefined,
  };
}

const SQLI_PATTERNS = [
  /union\s+select/i,
  /or\s+1\s*=\s*1/i,
  /'\s*or\s*'/i,
  /--\s*$/,
  /\bselect\b.*\bfrom\b/i,
  /\bsleep\s*\(/i,
  /benchmark\s*\(/i,
  /information_schema/i,
  /xp_cmdshell/i,
];

const SUSPICIOUS_UA_PATTERNS = [
  { re: /sqlmap/i, label: "sqlmap" },
  { re: /nikto/i, label: "Nikto" },
  { re: /nmap/i, label: "Nmap" },
  { re: /masscan/i, label: "masscan" },
  { re: /metasploit/i, label: "Metasploit" },
  { re: /acunetix/i, label: "Acunetix" },
  { re: /nessus/i, label: "Nessus" },
  { re: /zgrab/i, label: "ZGrab" },
  { re: /\bcurl\/[\d.]+/i, label: "curl" },
  { re: /wget/i, label: "wget" },
  { re: /python-requests/i, label: "python-requests" },
  { re: /go-http-client/i, label: "Go HTTP client" },
];

const SENSITIVE_LOGIN_PATHS =
  /\/(login|signin|admin|wp-login\.php|user\/login|api\/login|auth)/i;

export function analyzeLogs(text: string): {
  findings: LogFinding[];
  totalLines: number;
  parsedLines: number;
  perIp: { ip: string; count: number; errors: number }[];
} {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const parsed = lines.map(parseLine);
  const findings: LogFinding[] = [];

  // Brute force: many requests to login paths from same IP, especially with non-200 status
  const bfMap = new Map<
    string,
    { count: number; examples: string[] }
  >();
  for (const p of parsed) {
    if (!p.ip || !p.path) continue;
    if (SENSITIVE_LOGIN_PATHS.test(p.path)) {
      const entry = bfMap.get(p.ip) ?? { count: 0, examples: [] };
      entry.count++;
      if (entry.examples.length < 3) entry.examples.push(p.raw);
      bfMap.set(p.ip, entry);
    }
  }
  let bfIdx = 0;
  for (const [ip, info] of bfMap.entries()) {
    if (info.count >= 5) {
      findings.push({
        id: `bf-${bfIdx++}`,
        category: "brute-force",
        severity: info.count >= 25 ? "critical" : "high",
        title: `Brute force from ${ip}`,
        description: `${info.count} requests to login/auth endpoints from ${ip}.`,
        ip,
        count: info.count,
        examples: info.examples,
      });
    }
  }

  // 404 sweep: many 404s from same IP
  const sweep = new Map<string, { count: number; examples: string[]; paths: Set<string> }>();
  for (const p of parsed) {
    if (!p.ip || p.status !== 404) continue;
    const entry =
      sweep.get(p.ip) ?? { count: 0, examples: [], paths: new Set() };
    entry.count++;
    if (p.path) entry.paths.add(p.path);
    if (entry.examples.length < 3) entry.examples.push(p.raw);
    sweep.set(p.ip, entry);
  }
  let sweepIdx = 0;
  for (const [ip, info] of sweep.entries()) {
    if (info.count >= 8) {
      findings.push({
        id: `sweep-${sweepIdx++}`,
        category: "404-sweep",
        severity: info.count >= 30 ? "high" : "medium",
        title: `404 sweep from ${ip}`,
        description: `${info.count} not-found responses across ${info.paths.size} unique paths. Likely directory enumeration.`,
        ip,
        count: info.count,
        examples: info.examples,
      });
    }
  }

  // SQLi patterns in GET params
  let sqliIdx = 0;
  const sqliByIp = new Map<string, { count: number; examples: string[] }>();
  for (const p of parsed) {
    if (!p.path) continue;
    if (SQLI_PATTERNS.some((re) => re.test(decodeURIComponentSafe(p.path!)))) {
      const ip = p.ip ?? "unknown";
      const entry = sqliByIp.get(ip) ?? { count: 0, examples: [] };
      entry.count++;
      if (entry.examples.length < 3) entry.examples.push(p.raw);
      sqliByIp.set(ip, entry);
    }
  }
  for (const [ip, info] of sqliByIp.entries()) {
    findings.push({
      id: `sqli-${sqliIdx++}`,
      category: "sqli",
      severity: "critical",
      title: `SQL injection attempts from ${ip}`,
      description: `${info.count} request(s) containing SQL injection signatures.`,
      ip: ip === "unknown" ? undefined : ip,
      count: info.count,
      examples: info.examples,
    });
  }

  // Unusual user agents
  let uaIdx = 0;
  const uaByLabel = new Map<
    string,
    { count: number; examples: string[]; ips: Set<string> }
  >();
  for (const p of parsed) {
    if (!p.userAgent) continue;
    for (const { re, label } of SUSPICIOUS_UA_PATTERNS) {
      if (re.test(p.userAgent)) {
        const entry =
          uaByLabel.get(label) ?? {
            count: 0,
            examples: [],
            ips: new Set<string>(),
          };
        entry.count++;
        if (p.ip) entry.ips.add(p.ip);
        if (entry.examples.length < 3) entry.examples.push(p.raw);
        uaByLabel.set(label, entry);
        break;
      }
    }
  }
  for (const [label, info] of uaByLabel.entries()) {
    findings.push({
      id: `ua-${uaIdx++}`,
      category: "unusual-ua",
      severity:
        label === "sqlmap" ||
        label === "Nikto" ||
        label === "masscan" ||
        label === "Acunetix"
          ? "high"
          : "medium",
      title: `Suspicious user agent: ${label}`,
      description: `${info.count} requests using ${label} from ${info.ips.size} IP(s).`,
      userAgent: label,
      count: info.count,
      examples: info.examples,
    });
  }

  // Per-IP summary
  const perIpMap = new Map<string, { count: number; errors: number }>();
  for (const p of parsed) {
    if (!p.ip) continue;
    const entry = perIpMap.get(p.ip) ?? { count: 0, errors: 0 };
    entry.count++;
    if (p.status && p.status >= 400) entry.errors++;
    perIpMap.set(p.ip, entry);
  }
  const perIp = Array.from(perIpMap.entries())
    .map(([ip, v]) => ({ ip, count: v.count, errors: v.errors }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 25);

  return {
    findings: findings.sort(severityRank),
    totalLines: lines.length,
    parsedLines: parsed.filter((p) => p.ip).length,
    perIp,
  };
}

function severityRank(a: LogFinding, b: LogFinding) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return order[a.severity] - order[b.severity];
}

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export const SAMPLE_APACHE_LOG = `192.168.1.10 - - [12/Apr/2026:08:15:01 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
192.168.1.10 - - [12/Apr/2026:08:15:03 +0000] "GET /assets/style.css HTTP/1.1" 200 4112 "-" "Mozilla/5.0"
203.0.113.50 - - [12/Apr/2026:08:16:01 +0000] "GET /admin HTTP/1.1" 401 287 "-" "Mozilla/5.0"
203.0.113.50 - - [12/Apr/2026:08:16:02 +0000] "POST /admin/login HTTP/1.1" 401 287 "-" "Mozilla/5.0"
203.0.113.50 - - [12/Apr/2026:08:16:03 +0000] "POST /admin/login HTTP/1.1" 401 287 "-" "Mozilla/5.0"
203.0.113.50 - - [12/Apr/2026:08:16:04 +0000] "POST /admin/login HTTP/1.1" 401 287 "-" "Mozilla/5.0"
203.0.113.50 - - [12/Apr/2026:08:16:05 +0000] "POST /admin/login HTTP/1.1" 401 287 "-" "Mozilla/5.0"
203.0.113.50 - - [12/Apr/2026:08:16:06 +0000] "POST /admin/login HTTP/1.1" 401 287 "-" "Mozilla/5.0"
203.0.113.50 - - [12/Apr/2026:08:16:07 +0000] "POST /admin/login HTTP/1.1" 401 287 "-" "Mozilla/5.0"
203.0.113.50 - - [12/Apr/2026:08:16:08 +0000] "POST /admin/login HTTP/1.1" 401 287 "-" "Mozilla/5.0"
198.51.100.7 - - [12/Apr/2026:08:18:11 +0000] "GET /backup.zip HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:12 +0000] "GET /old/ HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:13 +0000] "GET /db.sql HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:14 +0000] "GET /config.php.bak HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:15 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:16 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:17 +0000] "GET /wp-config.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:18 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:19 +0000] "GET /server-status HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
198.51.100.7 - - [12/Apr/2026:08:18:20 +0000] "GET /test.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 sqlmap/1.7.2"
45.33.19.22 - - [12/Apr/2026:08:21:01 +0000] "GET /products?id=1' OR 1=1-- HTTP/1.1" 500 412 "-" "Mozilla/5.0"
45.33.19.22 - - [12/Apr/2026:08:21:02 +0000] "GET /products?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 500 412 "-" "Mozilla/5.0"
45.33.19.22 - - [12/Apr/2026:08:21:03 +0000] "GET /search?q=test'%20OR%20'1'='1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
45.33.19.22 - - [12/Apr/2026:08:21:04 +0000] "GET /api/users?filter=1;SELECT%20sleep(5)-- HTTP/1.1" 500 412 "-" "Mozilla/5.0"
8.8.8.8 - - [12/Apr/2026:08:30:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Nikto/2.1.6"
8.8.8.8 - - [12/Apr/2026:08:30:01 +0000] "GET /robots.txt HTTP/1.1" 200 89 "-" "Nikto/2.1.6"
8.8.8.8 - - [12/Apr/2026:08:30:02 +0000] "GET /CHANGELOG HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
192.168.1.10 - - [12/Apr/2026:08:35:00 +0000] "GET /about HTTP/1.1" 200 2014 "-" "Mozilla/5.0 (Macintosh)"
192.168.1.10 - - [12/Apr/2026:08:35:05 +0000] "GET /contact HTTP/1.1" 200 1893 "-" "Mozilla/5.0 (Macintosh)"
`;
