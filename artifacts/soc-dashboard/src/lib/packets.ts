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
`;
