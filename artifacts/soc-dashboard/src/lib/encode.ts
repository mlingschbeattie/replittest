export type EncodingName =
  | "base64"
  | "url"
  | "hex"
  | "html"
  | "rot13"
  | "binary"
  | "jwt";

export type EncodeResult = {
  value: string;
  error?: string;
};

export type DecodeResult = {
  value: string;
  error?: string;
};

export type DetectedEncoding = {
  name: EncodingName;
  label: string;
  confidence: "high" | "medium" | "low";
  decoded: string;
};

// ----- Base64 -----
export function encodeBase64(input: string): EncodeResult {
  try {
    return { value: btoa(unescape(encodeURIComponent(input))) };
  } catch (e) {
    return { value: "", error: String(e) };
  }
}
export function decodeBase64(input: string): DecodeResult {
  const clean = input.trim().replace(/\s+/g, "");
  try {
    const decoded = decodeURIComponent(escape(atob(clean)));
    return { value: decoded };
  } catch {
    try {
      return { value: atob(clean) };
    } catch (e) {
      return { value: "", error: `Invalid Base64: ${String(e)}` };
    }
  }
}

// ----- URL encoding -----
export function encodeUrl(input: string): EncodeResult {
  try {
    return { value: encodeURIComponent(input) };
  } catch (e) {
    return { value: "", error: String(e) };
  }
}
export function decodeUrl(input: string): DecodeResult {
  try {
    return { value: decodeURIComponent(input.replace(/\+/g, " ")) };
  } catch (e) {
    return { value: "", error: `Invalid URL encoding: ${String(e)}` };
  }
}

// ----- Hex -----
export function encodeHex(input: string): EncodeResult {
  return {
    value: Array.from(new TextEncoder().encode(input))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" "),
  };
}
export function decodeHex(input: string): DecodeResult {
  const hex = input.replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    return { value: "", error: "Input is not valid hex (must be even-length hex digits)" };
  }
  try {
    const bytes = new Uint8Array(
      Array.from({ length: hex.length / 2 }, (_, i) =>
        parseInt(hex.slice(i * 2, i * 2 + 2), 16),
      ),
    );
    return { value: new TextDecoder().decode(bytes) };
  } catch (e) {
    return { value: "", error: String(e) };
  }
}

// ----- HTML entities -----
const HTML_ENCODE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#039;",
};
const HTML_DECODE_MAP: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#039;": "'",
  "&apos;": "'",
  "&nbsp;": "\u00a0",
};
export function encodeHtml(input: string): EncodeResult {
  return {
    value: input.replace(/[&<>"']/g, (ch) => HTML_ENCODE_MAP[ch] ?? ch),
  };
}
export function decodeHtml(input: string): DecodeResult {
  return {
    value: input
      .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
      .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(
        /&(?:amp|lt|gt|quot|#039|apos|nbsp);/g,
        (m) => HTML_DECODE_MAP[m] ?? m,
      ),
  };
}

// ----- ROT13 -----
export function rot13(input: string): EncodeResult {
  const rotated = input.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
  return { value: rotated };
}

// ----- Binary -----
export function encodeBinary(input: string): EncodeResult {
  const bytes = new TextEncoder().encode(input);
  return {
    value: Array.from(bytes)
      .map((b) => b.toString(2).padStart(8, "0"))
      .join(" "),
  };
}
export function decodeBinary(input: string): DecodeResult {
  const groups = input.trim().split(/\s+/);
  if (groups.some((g) => !/^[01]{8}$/.test(g))) {
    return { value: "", error: "Input must be space-separated 8-bit binary groups" };
  }
  try {
    const bytes = new Uint8Array(groups.map((g) => parseInt(g, 2)));
    return { value: new TextDecoder().decode(bytes) };
  } catch (e) {
    return { value: "", error: String(e) };
  }
}

// ----- JWT decode (no verify) -----
export function decodeJwt(input: string): DecodeResult {
  const parts = input.trim().split(".");
  if (parts.length !== 3) {
    return { value: "", error: "Not a valid JWT (expected 3 parts separated by '.')" };
  }
  try {
    const pad = (s: string) => s + "=".repeat((4 - (s.length % 4)) % 4);
    const header = JSON.parse(atob(pad(parts[0])));
    const payload = JSON.parse(atob(pad(parts[1])));
    return {
      value: JSON.stringify(
        { header, payload, signature: `[${parts[2].length} chars — not verified]` },
        null,
        2,
      ),
    };
  } catch (e) {
    return { value: "", error: `Could not decode JWT: ${String(e)}` };
  }
}

// ----- Auto-detect -----
export function autoDetect(input: string): DetectedEncoding[] {
  const results: DetectedEncoding[] = [];
  const trimmed = input.trim();

  // Base64
  if (/^[A-Za-z0-9+/=]{4,}$/.test(trimmed.replace(/\s/g, ""))) {
    const r = decodeBase64(trimmed);
    if (!r.error && r.value && r.value !== trimmed) {
      results.push({
        name: "base64",
        label: "Base64",
        confidence: "high",
        decoded: r.value,
      });
    }
  }

  // URL encoded
  if (/%[0-9a-fA-F]{2}/.test(trimmed)) {
    const r = decodeUrl(trimmed);
    if (!r.error && r.value !== trimmed) {
      results.push({
        name: "url",
        label: "URL encoding",
        confidence: "high",
        decoded: r.value,
      });
    }
  }

  // HTML entities
  if (/&(?:\w+|#\d+|#x[0-9a-fA-F]+);/.test(trimmed)) {
    const r = decodeHtml(trimmed);
    if (!r.error && r.value !== trimmed) {
      results.push({
        name: "html",
        label: "HTML entities",
        confidence: "high",
        decoded: r.value,
      });
    }
  }

  // Hex
  const hexClean = trimmed.replace(/\s/g, "");
  if (/^[0-9a-fA-F]+$/.test(hexClean) && hexClean.length % 2 === 0 && hexClean.length >= 4) {
    const r = decodeHex(trimmed);
    if (!r.error && r.value) {
      results.push({
        name: "hex",
        label: "Hex",
        confidence: /^\s*[0-9a-fA-F]{2}(\s[0-9a-fA-F]{2})*\s*$/.test(trimmed)
          ? "high"
          : "medium",
        decoded: r.value,
      });
    }
  }

  // Binary
  if (/^[01]{8}(\s[01]{8})*$/.test(trimmed)) {
    const r = decodeBinary(trimmed);
    if (!r.error && r.value) {
      results.push({ name: "binary", label: "Binary", confidence: "high", decoded: r.value });
    }
  }

  // JWT
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(trimmed)) {
    const r = decodeJwt(trimmed);
    if (!r.error) {
      results.push({ name: "jwt", label: "JWT", confidence: "high", decoded: r.value });
    }
  }

  return results;
}
