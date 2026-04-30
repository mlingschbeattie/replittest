export type ParsedPacket = {
  index: number;
  timestamp?: string;
  protocol: string;
  srcIp: string;
  srcPort?: number;
  destIp: string;
  destPort?: number;
  flags?: string;
  length?: number;
  payload?: string;
  raw: string;
};

export type SuspiciousPattern = {
  id: string;
  category: "port-scan" | "auth-failure" | "large-transfer" | "dns-tunnel";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  involvedHosts: string[];
  count: number;
};

export type CredentialType =
  | "http-basic"
  | "form-password"
  | "ftp-credentials"
  | "telnet-auth"
  | "http-get-secret"
  | "session-cookie";

export type CredentialValueKind =
  | "password"
  | "token"
  | "cookie"
  | "username:password"
  | "credential";

export type CredentialFinding = {
  id: string;
  packetIndex: number;
  timestamp?: string;
  srcIp: string;
  destIp: string;
  destPort?: number;
  protocol: string;
  type: CredentialType;
  label: string;
  fieldName?: string;
  username?: string;
  rawValue: string;
  valueKind: CredentialValueKind;
  confidence: "high" | "medium" | "low";
};

const IP_PORT_RE = /(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d{1,5}))?/;

function splitIpPort(ipPortStr: string): { ip: string; port?: number } {
  const m = ipPortStr.match(IP_PORT_RE);
  if (!m) return { ip: ipPortStr };
  return {
    ip: m[1],
    port: m[2] ? Number(m[2]) : undefined,
  };
}

export function parsePackets(text: string): ParsedPacket[] {
  const packets: ParsedPacket[] = [];
  const lines = text.split(/\r?\n/);
  let index = 0;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith("//")) continue;

    // tcpdump format: HH:MM:SS.ffffff IP src.port > dst.port: PROTO ...
    // also handle: "IP6 ..." and Wireshark text export
    const tcpdumpMatch = line.match(
      /^(\d{2}:\d{2}:\d{2}\.\d+)?\s*(?:IP6?|IPv?6?)?\s*([\d.:a-fA-F]+(?:\.\d+)?)\s*>\s*([\d.:a-fA-F]+(?:\.\d+)?):\s*(.*)$/
    );

    if (tcpdumpMatch) {
      const [, ts, srcRaw, dstRaw, rest] = tcpdumpMatch;
      const src = splitIpPort(srcRaw);
      const dst = splitIpPort(dstRaw);
      let protocol = "TCP";
      if (/UDP/i.test(rest)) protocol = "UDP";
      else if (/ICMP/i.test(rest)) protocol = "ICMP";
      else if (/DNS/i.test(rest)) protocol = "DNS";
      else if (/TLS|SSL|HTTPS/i.test(rest)) protocol = "TLS";
      else if (/HTTP/i.test(rest)) protocol = "HTTP";
      else if (/Flags/i.test(rest)) protocol = "TCP";

      const flagsMatch = rest.match(/Flags\s*\[([^\]]+)\]/i);
      const lenMatch = rest.match(/length\s+(\d+)/i);

      packets.push({
        index: index++,
        timestamp: ts,
        protocol,
        srcIp: src.ip,
        srcPort: src.port,
        destIp: dst.ip,
        destPort: dst.port,
        flags: flagsMatch?.[1],
        length: lenMatch ? Number(lenMatch[1]) : undefined,
        payload: rest.length > 200 ? rest.slice(0, 200) + "…" : rest,
        raw: line,
      });
      continue;
    }

    // Wireshark "No. Time Source Destination Protocol Length Info" line format
    const wiresharkMatch = line.match(
      /^\d+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\w+)\s+(\d+)\s+(.*)$/
    );
    if (wiresharkMatch) {
      const [, ts, src, dst, proto, len, info] = wiresharkMatch;
      const sm = info.match(/(\d+)\s*[→>]\s*(\d+)/);
      packets.push({
        index: index++,
        timestamp: ts,
        protocol: proto.toUpperCase(),
        srcIp: src,
        srcPort: sm ? Number(sm[1]) : undefined,
        destIp: dst,
        destPort: sm ? Number(sm[2]) : undefined,
        length: Number(len),
        payload: info,
        raw: line,
      });
      continue;
    }

    // Generic IP-pair fallback: extract any two IPs in the line
    const ips = line.match(/(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?/g);
    if (ips && ips.length >= 2) {
      const a = splitIpPort(ips[0]);
      const b = splitIpPort(ips[1]);
      packets.push({
        index: index++,
        protocol: "TCP",
        srcIp: a.ip,
        srcPort: a.port,
        destIp: b.ip,
        destPort: b.port,
        payload: line.length > 200 ? line.slice(0, 200) + "…" : line,
        raw: line,
      });
    }
  }
  return packets;
}

export function detectSuspiciousPatterns(
  packets: ParsedPacket[]
): SuspiciousPattern[] {
  const patterns: SuspiciousPattern[] = [];

  // Port scan: same source IP hitting many distinct destination ports
  const srcToPorts = new Map<string, Set<number>>();
  const srcToDests = new Map<string, Set<string>>();
  for (const p of packets) {
    if (p.destPort != null) {
      if (!srcToPorts.has(p.srcIp)) srcToPorts.set(p.srcIp, new Set());
      srcToPorts.get(p.srcIp)!.add(p.destPort);
    }
    if (!srcToDests.has(p.srcIp)) srcToDests.set(p.srcIp, new Set());
    srcToDests.get(p.srcIp)!.add(p.destIp);
  }
  let scanIdx = 0;
  for (const [src, ports] of srcToPorts.entries()) {
    if (ports.size >= 10) {
      patterns.push({
        id: `scan-${scanIdx++}`,
        category: "port-scan",
        severity: ports.size >= 50 ? "critical" : "high",
        title: `Port scan from ${src}`,
        description: `${src} contacted ${ports.size} distinct ports across ${
          srcToDests.get(src)?.size ?? 1
        } host(s). Likely reconnaissance.`,
        involvedHosts: [src],
        count: ports.size,
      });
    }
  }

  // Repeated auth failures on 22 (SSH) / 3389 (RDP) — many connections from same src to same dst
  const authPair = new Map<string, number>();
  for (const p of packets) {
    if (p.destPort === 22 || p.destPort === 3389) {
      const key = `${p.srcIp}|${p.destIp}|${p.destPort}`;
      authPair.set(key, (authPair.get(key) ?? 0) + 1);
    }
  }
  let authIdx = 0;
  for (const [key, count] of authPair.entries()) {
    if (count >= 5) {
      const [src, dst, port] = key.split("|");
      patterns.push({
        id: `auth-${authIdx++}`,
        category: "auth-failure",
        severity: count >= 20 ? "critical" : "high",
        title: `Repeated ${port === "22" ? "SSH" : "RDP"} attempts to ${dst}`,
        description: `${src} made ${count} connection attempts to ${dst}:${port}. Consistent with a brute-force login attempt.`,
        involvedHosts: [src, dst],
        count,
      });
    }
  }

  // Large outbound transfers — single src->dst with large total length
  const transfer = new Map<string, number>();
  for (const p of packets) {
    if (p.length && p.length > 0) {
      const key = `${p.srcIp}|${p.destIp}`;
      transfer.set(key, (transfer.get(key) ?? 0) + p.length);
    }
  }
  let xferIdx = 0;
  for (const [key, total] of transfer.entries()) {
    if (total >= 1_000_000) {
      const [src, dst] = key.split("|");
      patterns.push({
        id: `xfer-${xferIdx++}`,
        category: "large-transfer",
        severity: total >= 10_000_000 ? "high" : "medium",
        title: `Large outbound transfer ${src} → ${dst}`,
        description: `${(total / 1_000_000).toFixed(
          2
        )} MB observed in capture. Inspect for data exfiltration.`,
        involvedHosts: [src, dst],
        count: total,
      });
    }
  }

  return patterns;
}

function safeBase64Decode(b64: string): string | null {
  try {
    if (typeof atob === "function") return atob(b64);
    if (typeof Buffer !== "undefined") return Buffer.from(b64, "base64").toString("utf8");
    return null;
  } catch {
    return null;
  }
}

function safeUriDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

const FORM_FIELD_NAMES = ["password", "passwd", "pwd", "pass", "login"] as const;
const GET_PARAM_NAMES = ["password", "passwd", "token", "api_key"] as const;
const COOKIE_TOKEN_NAMES = ["session", "auth", "jwt"] as const;

const TELNET_NOISE_RE =
  /(Flags\s*\[[^\]]+\]|length\s+\d+|seq\s+\S+|ack\s+\S+|win\s+\d+|options\s+\[[^\]]+\]|\bIP\b)/gi;

export function detectCredentials(packets: ParsedPacket[]): CredentialFinding[] {
  const findings: CredentialFinding[] = [];
  let counter = 0;
  const pendingFtpUser = new Map<string, string>();

  const push = (f: Omit<CredentialFinding, "id">) => {
    findings.push({ id: `cred-${counter++}`, ...f });
  };

  for (const p of packets) {
    const text = `${p.payload ?? ""}\n${p.raw ?? ""}`;
    const lowered = text.toLowerCase();

    // 1. HTTP Basic Auth — Authorization: Basic <base64>
    const basicRe = /Authorization:\s*Basic\s+([A-Za-z0-9+/=_-]+)/gi;
    let basicMatch: RegExpExecArray | null;
    while ((basicMatch = basicRe.exec(text)) !== null) {
      const decoded = safeBase64Decode(basicMatch[1].replace(/-/g, "+").replace(/_/g, "/"));
      if (decoded == null) continue;
      const colonIdx = decoded.indexOf(":");
      if (colonIdx < 0) continue;
      const username = decoded.slice(0, colonIdx);
      const password = decoded.slice(colonIdx + 1);
      if (!password) continue;
      push({
        packetIndex: p.index,
        timestamp: p.timestamp,
        srcIp: p.srcIp,
        destIp: p.destIp,
        destPort: p.destPort,
        protocol: p.protocol || "HTTP",
        type: "http-basic",
        label: "HTTP Basic Auth header",
        username,
        rawValue: password,
        valueKind: "username:password",
        confidence: "high",
      });
    }

    // Determine request style: GET-with-query vs POST/form-body
    const hasPost = /\bPOST\s+\S+\s+HTTP/i.test(text);
    // GET URL-parameter detection: look only at the request path's query string
    const getQueryMatch = text.match(/\bGET\s+(\S*\?\S*)/i);
    const queryString = getQueryMatch?.[1].split(/\s/)[0] ?? "";
    const recorded = new Set<string>();

    // 5. HTTP GET parameters in the URL query string
    if (queryString) {
      for (const param of GET_PARAM_NAMES) {
        const re = new RegExp(`[?&]${param}=([^&\\s"'<>#]+)`, "gi");
        let m: RegExpExecArray | null;
        while ((m = re.exec(queryString)) !== null) {
          const value = safeUriDecode(m[1]);
          if (!value) continue;
          recorded.add(`${param}=${m[1]}`);
          const valueKind: CredentialValueKind =
            param === "token" || param === "api_key" ? "token" : "password";
          push({
            packetIndex: p.index,
            timestamp: p.timestamp,
            srcIp: p.srcIp,
            destIp: p.destIp,
            destPort: p.destPort,
            protocol: p.protocol || "HTTP",
            type: "http-get-secret",
            label: `URL parameter "${param}"`,
            fieldName: param,
            rawValue: value,
            valueKind,
            confidence: "high",
          });
        }
      }
    }

    // 2. HTML form POST fields — password, passwd, pwd, pass, login
    // Search across the whole packet text. Skip exact pairs already counted as URL params.
    if (hasPost || !queryString) {
      for (const field of FORM_FIELD_NAMES) {
        const re = new RegExp(`(?:^|[&\\s"'])${field}=([^&\\s"'<>]+)`, "gi");
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          if (recorded.has(`${field}=${m[1]}`)) continue;
          const value = safeUriDecode(m[1]);
          if (!value) continue;
          push({
            packetIndex: p.index,
            timestamp: p.timestamp,
            srcIp: p.srcIp,
            destIp: p.destIp,
            destPort: p.destPort,
            protocol: p.protocol || "HTTP",
            type: "form-password",
            label: `Form field "${field}"`,
            fieldName: field,
            rawValue: value,
            valueKind: field === "login" ? "credential" : "password",
            confidence: "high",
          });
        }
      }
    }

    // 3. FTP USER followed by PASS from same source IP
    const isFtpContext =
      p.destPort === 21 || p.srcPort === 21 || /\bftp\b/i.test(text) || p.protocol === "FTP";
    if (isFtpContext) {
      const userMatch = text.match(/(?:^|[\s>:])USER\s+(\S+)/);
      if (userMatch) {
        pendingFtpUser.set(p.srcIp, userMatch[1]);
      }
      const passMatch = text.match(/(?:^|[\s>:])PASS\s+(\S+)/);
      if (passMatch) {
        const user = pendingFtpUser.get(p.srcIp);
        if (user) {
          push({
            packetIndex: p.index,
            timestamp: p.timestamp,
            srcIp: p.srcIp,
            destIp: p.destIp,
            destPort: p.destPort,
            protocol: "FTP",
            type: "ftp-credentials",
            label: "FTP USER + PASS sequence",
            username: user,
            rawValue: passMatch[1],
            valueKind: "username:password",
            confidence: "high",
          });
          pendingFtpUser.delete(p.srcIp);
        }
      }
    }

    // 4. Telnet plaintext on port 23 — login: / password: / username:
    if (p.destPort === 23 || p.srcPort === 23 || /\btelnet\b/i.test(lowered)) {
      const stripped = text.replace(TELNET_NOISE_RE, " ");
      const telnetRe = /\b(login|username|password)\s*[:=]\s*(\S+)/gi;
      let tm: RegExpExecArray | null;
      while ((tm = telnetRe.exec(stripped)) !== null) {
        const fieldName = tm[1].toLowerCase();
        const valueKind: CredentialValueKind = fieldName.includes("pass")
          ? "password"
          : "credential";
        push({
          packetIndex: p.index,
          timestamp: p.timestamp,
          srcIp: p.srcIp,
          destIp: p.destIp,
          destPort: p.destPort,
          protocol: "TELNET",
          type: "telnet-auth",
          label: `Telnet plaintext ${fieldName}`,
          fieldName,
          rawValue: tm[2],
          valueKind,
          confidence: "medium",
        });
      }
    }

    // 6. Cookie session tokens — Cookie: session=...; auth=...; jwt=...
    const cookieMatch = text.match(/Cookie:\s*([^\r\n]+)/i);
    if (cookieMatch) {
      const cookieStr = cookieMatch[1];
      for (const tokenName of COOKIE_TOKEN_NAMES) {
        const re = new RegExp(`(?:^|[;\\s])${tokenName}=([^;\\s"'<>]+)`, "gi");
        let m: RegExpExecArray | null;
        while ((m = re.exec(cookieStr)) !== null) {
          push({
            packetIndex: p.index,
            timestamp: p.timestamp,
            srcIp: p.srcIp,
            destIp: p.destIp,
            destPort: p.destPort,
            protocol: p.protocol || "HTTP",
            type: "session-cookie",
            label: `Cookie ${tokenName}`,
            fieldName: tokenName,
            rawValue: m[1],
            valueKind: tokenName === "jwt" ? "token" : "cookie",
            confidence: "medium",
          });
        }
      }
    }
  }

  // Dedupe identical findings within the same packet
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.packetIndex}|${f.type}|${f.fieldName ?? ""}|${f.username ?? ""}|${f.rawValue}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function maskCredential(finding: CredentialFinding): string {
  const v = finding.rawValue ?? "";
  const maskWord = (s: string): string => {
    if (s.length === 0) return "";
    if (s.length === 1) return "*";
    if (s.length === 2) return `${s[0]}*`;
    return `${s[0]}${"*".repeat(Math.max(1, s.length - 2))}${s[s.length - 1]}`;
  };
  switch (finding.valueKind) {
    case "password":
      return maskWord(v);
    case "username:password":
      return finding.username ? `${finding.username}:${maskWord(v)}` : maskWord(v);
    case "token":
    case "cookie":
      return v.length <= 8 ? v : `${v.slice(0, 8)}...`;
    case "credential":
      return maskWord(v);
  }
}

export function unmaskCredential(finding: CredentialFinding): string {
  if (finding.valueKind === "username:password" && finding.username) {
    return `${finding.username}:${finding.rawValue}`;
  }
  return finding.rawValue;
}

export function credentialTypeLabel(type: CredentialType): string {
  switch (type) {
    case "http-basic":
      return "HTTP Basic";
    case "form-password":
      return "Form Password";
    case "ftp-credentials":
      return "FTP Login";
    case "telnet-auth":
      return "Telnet Auth";
    case "http-get-secret":
      return "URL Secret";
    case "session-cookie":
      return "Session Token";
  }
}

export const SAMPLE_TCPDUMP = `09:14:02.123456 IP 10.0.0.42.51234 > 192.168.1.10.22: Flags [S], seq 1, length 0
09:14:02.234567 IP 10.0.0.42.51235 > 192.168.1.10.22: Flags [S], seq 1, length 0
09:14:02.334567 IP 10.0.0.42.51236 > 192.168.1.10.22: Flags [S], seq 1, length 0
09:14:02.434567 IP 10.0.0.42.51237 > 192.168.1.10.22: Flags [S], seq 1, length 0
09:14:02.534567 IP 10.0.0.42.51238 > 192.168.1.10.22: Flags [S], seq 1, length 0
09:14:02.634567 IP 10.0.0.42.51239 > 192.168.1.10.22: Flags [S], seq 1, length 0
09:14:03.001000 IP 10.0.0.99.55001 > 192.168.1.10.21: Flags [S], length 0
09:14:03.002000 IP 10.0.0.99.55002 > 192.168.1.10.22: Flags [S], length 0
09:14:03.003000 IP 10.0.0.99.55003 > 192.168.1.10.23: Flags [S], length 0
09:14:03.004000 IP 10.0.0.99.55004 > 192.168.1.10.25: Flags [S], length 0
09:14:03.005000 IP 10.0.0.99.55005 > 192.168.1.10.53: Flags [S], length 0
09:14:03.006000 IP 10.0.0.99.55006 > 192.168.1.10.80: Flags [S], length 0
09:14:03.007000 IP 10.0.0.99.55007 > 192.168.1.10.110: Flags [S], length 0
09:14:03.008000 IP 10.0.0.99.55008 > 192.168.1.10.139: Flags [S], length 0
09:14:03.009000 IP 10.0.0.99.55009 > 192.168.1.10.143: Flags [S], length 0
09:14:03.010000 IP 10.0.0.99.55010 > 192.168.1.10.443: Flags [S], length 0
09:14:03.011000 IP 10.0.0.99.55011 > 192.168.1.10.445: Flags [S], length 0
09:14:03.012000 IP 10.0.0.99.55012 > 192.168.1.10.3306: Flags [S], length 0
09:14:03.013000 IP 10.0.0.99.55013 > 192.168.1.10.3389: Flags [S], length 0
09:14:03.014000 IP 10.0.0.99.55014 > 192.168.1.10.5432: Flags [S], length 0
09:14:03.015000 IP 10.0.0.99.55015 > 192.168.1.10.6379: Flags [S], length 0
09:14:03.016000 IP 10.0.0.99.55016 > 192.168.1.10.8080: Flags [S], length 0
09:15:10.111111 IP 10.0.0.42.51301 > 192.168.1.10.22: Flags [P.], length 64
09:15:10.211111 IP 10.0.0.42.51302 > 192.168.1.10.22: Flags [P.], length 64
09:15:10.311111 IP 10.0.0.42.51303 > 192.168.1.10.22: Flags [P.], length 64
09:15:10.411111 IP 10.0.0.42.51304 > 192.168.1.10.22: Flags [P.], length 64
09:15:10.511111 IP 10.0.0.42.51305 > 192.168.1.10.22: Flags [P.], length 64
09:15:10.611111 IP 10.0.0.42.51306 > 192.168.1.10.22: Flags [P.], length 64
09:16:01.000000 IP 192.168.1.50.49152 > 198.51.100.7.443: Flags [P.], length 1500000
09:16:02.000000 IP 192.168.1.50.49152 > 198.51.100.7.443: Flags [P.], length 2200000
09:16:03.000000 IP 192.168.1.50.49152 > 198.51.100.7.443: Flags [P.], length 1800000
09:16:04.000000 IP 192.168.1.50.49152 > 198.51.100.7.443: Flags [P.], length 1700000
09:16:05.000000 IP 192.168.1.50.49152 > 198.51.100.7.443: Flags [P.], length 1900000
09:17:00.001000 IP 192.168.1.5.62100 > 8.8.8.8.53: UDP, length 64
09:17:00.001500 IP 8.8.8.8.53 > 192.168.1.5.62100: UDP, length 128
09:17:01.000000 IP 192.168.1.5.62101 > 1.1.1.1.53: UDP, length 64
09:18:00.100000 IP 10.0.0.50.51500 > 192.168.1.20.80: HTTP POST /login HTTP/1.1 username=alice&password=hunter2&login=submit length 250
09:18:01.200000 IP 10.0.0.50.51501 > 192.168.1.20.80: HTTP GET /api/data?api_key=sk_live_abc123def456ghi789 HTTP/1.1 length 180
09:18:02.300000 IP 10.0.0.50.51502 > 192.168.1.20.80: HTTP GET /dashboard HTTP/1.1 Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.signature; auth=tok_abcd1234; jwt=eyJhbGciOiJIUzI1NiJ9.payload.sig length 320
09:18:03.400000 IP 10.0.0.50.51503 > 192.168.1.20.80: HTTP GET /admin HTTP/1.1 Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM= length 200
09:18:04.500000 IP 10.0.0.51.51600 > 192.168.1.30.21: FTP USER bob length 32
09:18:05.000000 IP 10.0.0.51.51601 > 192.168.1.30.21: FTP PASS s3cretFTP! length 40
09:18:06.700000 IP 10.0.0.52.51700 > 192.168.1.40.23: TELNET login: root password: toor length 50
`;
