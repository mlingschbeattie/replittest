import { createHash } from "node:crypto";
import { Router, type IRouter } from "express";
import { CheckHashBody, CheckHashResponse } from "@workspace/api-zod";
import { recordHashCheck } from "../lib/activity";

const router: IRouter = Router();

const HIBP_RANGE = "https://api.pwnedpasswords.com/range";

function identifyHash(hash: string): {
  identifiedTypes: string[];
  primaryType: string | null;
} {
  const trimmed = hash.trim();
  if (!trimmed) return { identifiedTypes: [], primaryType: null };

  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(trimmed)) {
    return { identifiedTypes: ["bcrypt"], primaryType: "bcrypt" };
  }
  if (/^\$1\$/.test(trimmed)) {
    return { identifiedTypes: ["MD5 crypt"], primaryType: "MD5 crypt" };
  }
  if (/^\$5\$/.test(trimmed)) {
    return { identifiedTypes: ["SHA-256 crypt"], primaryType: "SHA-256 crypt" };
  }
  if (/^\$6\$/.test(trimmed)) {
    return { identifiedTypes: ["SHA-512 crypt"], primaryType: "SHA-512 crypt" };
  }
  if (/^\$argon2(id|i|d)\$/.test(trimmed)) {
    return { identifiedTypes: ["Argon2"], primaryType: "Argon2" };
  }

  if (!/^[a-fA-F0-9]+$/.test(trimmed)) {
    return { identifiedTypes: ["Unknown"], primaryType: null };
  }

  switch (trimmed.length) {
    case 32:
      return {
        identifiedTypes: ["MD5", "NTLM", "MD4", "LM"],
        primaryType: "MD5",
      };
    case 40:
      return {
        identifiedTypes: ["SHA-1", "RIPEMD-160"],
        primaryType: "SHA-1",
      };
    case 56:
      return { identifiedTypes: ["SHA-224"], primaryType: "SHA-224" };
    case 64:
      return {
        identifiedTypes: ["SHA-256", "SHA3-256"],
        primaryType: "SHA-256",
      };
    case 96:
      return { identifiedTypes: ["SHA-384"], primaryType: "SHA-384" };
    case 128:
      return {
        identifiedTypes: ["SHA-512", "SHA3-512", "Whirlpool"],
        primaryType: "SHA-512",
      };
    default:
      return { identifiedTypes: ["Unknown"], primaryType: null };
  }
}

async function checkHibp(sha1Upper: string): Promise<number> {
  const prefix = sha1Upper.slice(0, 5);
  const suffix = sha1Upper.slice(5);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(`${HIBP_RANGE}/${prefix}`, {
      signal: controller.signal,
      headers: {
        "User-Agent": "SentinelLab/1.0",
        "Add-Padding": "true",
      },
    });
    if (!res.ok) {
      throw new Error(`HIBP responded ${res.status}`);
    }
    const text = await res.text();
    for (const line of text.split(/\r?\n/)) {
      const [hashSuffix, countStr] = line.split(":");
      if (hashSuffix && hashSuffix.toUpperCase() === suffix) {
        return Number(countStr) || 0;
      }
    }
    return 0;
  } finally {
    clearTimeout(timer);
  }
}

router.post("/hash/check", async (req, res): Promise<void> => {
  const parsed = CheckHashBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const hash = parsed.data.hash.trim();
  if (!hash) {
    res.status(400).json({ error: "Hash cannot be empty" });
    return;
  }

  const { identifiedTypes, primaryType } = identifyHash(hash);
  let pwnedCount: number | null = null;
  let pwnedChecked = false;
  let notes: string | null = null;

  if (primaryType === "SHA-1") {
    try {
      pwnedCount = await checkHibp(hash.toUpperCase());
      pwnedChecked = true;
    } catch (err) {
      req.log.warn({ err: String(err) }, "HIBP lookup failed");
      notes = `HIBP lookup failed: ${String(err)}`;
    }
  } else if (primaryType === "MD5" || primaryType === "SHA-256") {
    notes =
      "HIBP only accepts SHA-1 hashes. Hash type identified but breach lookup is not available.";
  } else if (primaryType === "bcrypt" || primaryType?.endsWith("crypt") || primaryType === "Argon2") {
    notes =
      "Salted KDFs (bcrypt/argon2/sha-crypt) are designed to resist offline attacks and cannot be looked up in breach corpora.";
  } else {
    notes = "Hash format unrecognized. Provide a hex digest or a known prefixed format.";
  }

  // For demo convenience: if user pasted plaintext, also offer guidance.
  if (identifiedTypes.includes("Unknown") && hash.length < 20) {
    notes =
      "Input does not look like a hash. If this is a plaintext password, hash it first (the lab does not transmit plaintext).";
  }

  recordHashCheck(
    `${primaryType ?? "Unknown"} ${hash.slice(0, 12)}…`,
    (pwnedCount ?? 0) > 0,
  );

  res.json(
    CheckHashResponse.parse({
      hash,
      identifiedTypes,
      primaryType,
      length: hash.length,
      pwnedCount,
      pwnedChecked,
      notes,
    }),
  );
});

// Helper used during development; not currently exposed via OpenAPI.
export function sha1Hex(input: string): string {
  return createHash("sha1").update(input).digest("hex");
}

export default router;
