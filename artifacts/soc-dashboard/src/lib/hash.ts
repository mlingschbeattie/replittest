export function identifyHashClient(hash: string): string[] {
  const trimmed = hash.trim();
  if (!trimmed) return [];

  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(trimmed)) {
    return ["bcrypt"];
  }
  if (/^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$/.test(trimmed)) {
    return ["MD5 crypt"];
  }
  if (/^\$5\$/.test(trimmed)) return ["SHA-256 crypt"];
  if (/^\$6\$/.test(trimmed)) return ["SHA-512 crypt"];
  if (/^\$argon2(id|i|d)\$/.test(trimmed)) return ["Argon2"];

  if (!/^[a-fA-F0-9]+$/.test(trimmed)) {
    return ["Unknown"];
  }

  const len = trimmed.length;
  if (len === 32) return ["MD5", "NTLM", "MD4", "LM"];
  if (len === 40) return ["SHA-1", "RIPEMD-160"];
  if (len === 56) return ["SHA-224"];
  if (len === 64) return ["SHA-256", "SHA3-256"];
  if (len === 96) return ["SHA-384"];
  if (len === 128) return ["SHA-512", "SHA3-512", "Whirlpool"];
  return ["Unknown"];
}
