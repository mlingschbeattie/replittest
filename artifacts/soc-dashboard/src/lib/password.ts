export type PasswordAnalysis = {
  entropy: number;
  length: number;
  classes: {
    lowercase: boolean;
    uppercase: boolean;
    digits: boolean;
    symbols: boolean;
    spaces: boolean;
  };
  poolSize: number;
  crackTimes: CrackTime[];
  patterns: PasswordPattern[];
  score: 0 | 1 | 2 | 3 | 4;
  label: "Very Weak" | "Weak" | "Fair" | "Strong" | "Very Strong";
  color: "critical" | "high" | "medium" | "low" | "info";
};

export type CrackTime = {
  scenario: string;
  guessesPerSecond: number;
  time: string;
};

export type PasswordPattern = {
  name: string;
  description: string;
  penaltyBits: number;
};

const COMMON_PASSWORDS = new Set([
  "password", "123456", "password1", "qwerty", "12345678", "111111",
  "123456789", "1234567", "letmein", "12345", "1234567890", "password123",
  "abc123", "monkey", "sunshine", "master", "dragon", "shadow",
  "mustang", "superman", "princess", "welcome", "login", "passw0rd",
  "admin", "iloveyou", "football", "baseball", "hello", "charlie",
  "donald", "admin123", "qazwsx", "trustno1", "batman", "solo",
]);

const KEYBOARD_WALKS = [
  "qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm",
  "1qaz2wsx", "1q2w3e4r", "qweasd", "1234qwer", "!qaz@wsx",
];

const LEET_MAP: Record<string, string> = {
  "4": "a", "@": "a", "8": "b", "(": "c", "3": "e", "6": "g",
  "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t",
  "+": "t", "2": "z",
};

function unLeet(s: string): string {
  return Array.from(s.toLowerCase())
    .map((ch) => LEET_MAP[ch] ?? ch)
    .join("");
}

function poolSize(chars: PasswordAnalysis["classes"]): number {
  let pool = 0;
  if (chars.lowercase) pool += 26;
  if (chars.uppercase) pool += 26;
  if (chars.digits) pool += 10;
  if (chars.symbols) pool += 32;
  if (chars.spaces) pool += 1;
  return pool;
}

function entropy(length: number, pool: number): number {
  if (pool === 0 || length === 0) return 0;
  return length * Math.log2(pool);
}

function formatCrackTime(seconds: number): string {
  if (!isFinite(seconds)) return "centuries";
  if (seconds < 1) return "instant";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  if (seconds < 2592000) return `${Math.round(seconds / 86400)}d`;
  if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
  if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} years`;
  return "centuries";
}

export function analyzePassword(password: string): PasswordAnalysis {
  const lower = password.toLowerCase();
  const unLeeted = unLeet(lower);

  const classes: PasswordAnalysis["classes"] = {
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    digits: /[0-9]/.test(password),
    symbols: /[^a-zA-Z0-9\s]/.test(password),
    spaces: /\s/.test(password),
  };

  const pool = poolSize(classes);
  const bits = entropy(password.length, pool);

  const patterns: PasswordPattern[] = [];

  // Common password
  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(unLeeted)) {
    patterns.push({
      name: "Common password",
      description: "This exact string (or its leet-speak equivalent) appears in breach dictionaries.",
      penaltyBits: 30,
    });
  }

  // Repeated characters (aaaa, 1111)
  if (/(.)\1{2,}/.test(password)) {
    patterns.push({
      name: "Repeated characters",
      description: "Three or more consecutive identical characters significantly reduce entropy.",
      penaltyBits: 10,
    });
  }

  // Sequential characters (abcd, 1234)
  let seqCount = 0;
  for (let i = 0; i < password.length - 2; i++) {
    const d1 = password.charCodeAt(i + 1) - password.charCodeAt(i);
    const d2 = password.charCodeAt(i + 2) - password.charCodeAt(i + 1);
    if (d1 === d2 && (d1 === 1 || d1 === -1)) seqCount++;
  }
  if (seqCount >= 3) {
    patterns.push({
      name: "Sequential characters",
      description: "Long runs of sequential characters (abc, 123) reduce the effective keyspace.",
      penaltyBits: 8,
    });
  }

  // Keyboard walks
  if (KEYBOARD_WALKS.some((walk) => lower.includes(walk) || lower.split("").reverse().join("").includes(walk))) {
    patterns.push({
      name: "Keyboard walk",
      description: "Contains a common keyboard pattern (qwerty, asdf, etc.) attackers know to try.",
      penaltyBits: 15,
    });
  }

  // Only digits
  if (/^\d+$/.test(password)) {
    patterns.push({
      name: "Digits only",
      description: "A numeric-only password reduces the pool to 10 symbols, making brute-force trivial.",
      penaltyBits: 5,
    });
  }

  // Single character class (all lower, all upper)
  const classCount = Object.values(classes).filter(Boolean).length;
  if (classCount === 1 && !classes.digits) {
    patterns.push({
      name: "Single character class",
      description: "Using only one character class (e.g. only lowercase) reduces the search space.",
      penaltyBits: 8,
    });
  }

  // Leet-speak substitution of common word
  if (
    unLeeted !== lower &&
    (COMMON_PASSWORDS.has(unLeeted) || unLeeted.match(/^(password|admin|login|welcome|qwerty|letmein)$/))
  ) {
    patterns.push({
      name: "Leet substitution",
      description: "Simple number/symbol substitutions on common words are part of every cracking dictionary.",
      penaltyBits: 20,
    });
  }

  // Trailing digits on a word
  if (/^[a-zA-Z]+\d{1,4}$/.test(password)) {
    patterns.push({
      name: "Word + trailing digits",
      description: "Appending 1–4 digits to a word is one of the most predicted password patterns.",
      penaltyBits: 10,
    });
  }

  const totalPenalty = patterns.reduce((s, p) => s + p.penaltyBits, 0);
  const effectiveBits = Math.max(0, bits - totalPenalty);

  const guessesNeeded = Math.pow(2, effectiveBits) / 2;

  const crackTimes: CrackTime[] = [
    {
      scenario: "Online attack (10 req/s)",
      guessesPerSecond: 10,
      time: formatCrackTime(guessesNeeded / 10),
    },
    {
      scenario: "Offline slow hash (bcrypt)",
      guessesPerSecond: 10_000,
      time: formatCrackTime(guessesNeeded / 10_000),
    },
    {
      scenario: "Single GPU (MD5)",
      guessesPerSecond: 1_000_000_000,
      time: formatCrackTime(guessesNeeded / 1_000_000_000),
    },
    {
      scenario: "Botnet / cloud (100 GPUs)",
      guessesPerSecond: 100_000_000_000,
      time: formatCrackTime(guessesNeeded / 100_000_000_000),
    },
  ];

  let score: 0 | 1 | 2 | 3 | 4 = 0;
  if (effectiveBits >= 80) score = 4;
  else if (effectiveBits >= 60) score = 3;
  else if (effectiveBits >= 40) score = 2;
  else if (effectiveBits >= 20) score = 1;

  const LABELS: PasswordAnalysis["label"][] = [
    "Very Weak", "Weak", "Fair", "Strong", "Very Strong",
  ];
  const COLORS: PasswordAnalysis["color"][] = [
    "critical", "high", "medium", "low", "info",
  ];

  return {
    entropy: Math.round(effectiveBits),
    length: password.length,
    classes,
    poolSize: pool,
    crackTimes,
    patterns,
    score,
    label: LABELS[score],
    color: COLORS[score],
  };
}
