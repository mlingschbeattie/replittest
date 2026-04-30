export type OwaspCategory = { code: string; name: string };

export type FindingFix = {
  change: string;
  example: string;
  difficulty: "Low" | "Medium" | "High";
  owner: "Developer" | "Server Admin" | "IT Infrastructure";
};

export type FindingEnrichment = {
  owasp: OwaspCategory[];
  plainEnglish: string;
  howToFix: string;
  fix: FindingFix;
};

const A02: OwaspCategory = { code: "A02", name: "Cryptographic Failures" };
const A05: OwaspCategory = { code: "A05", name: "Security Misconfiguration" };
const A07: OwaspCategory = {
  code: "A07",
  name: "Identification and Authentication Failures",
};

const ENRICHMENT: Record<string, FindingEnrichment> = {
  "missing-csp": {
    owasp: [A05],
    plainEnglish:
      "The site does not tell the browser which scripts are allowed to run, which makes it much easier for an attacker who finds any small flaw to inject malicious code that runs against your visitors.",
    howToFix:
      "Add a Content-Security-Policy response header on every HTML response. Start with a restrictive default and explicitly allow only the script, style, and image sources you actually use.",
    fix: {
      change:
        "Set the Content-Security-Policy HTTP response header on all HTML responses.",
      example:
        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
      difficulty: "Medium",
      owner: "Developer",
    },
  },
  "weak-csp": {
    owasp: [A05],
    plainEnglish:
      "Your Content-Security-Policy is in place but allows inline scripts or eval, which removes most of its protection against script-injection attacks.",
    howToFix:
      "Remove 'unsafe-inline' and 'unsafe-eval' from script-src and style-src. Move inline scripts/styles to external files or use per-request nonces or hashes.",
    fix: {
      change:
        "Tighten the script-src and style-src directives in your Content-Security-Policy header.",
      example:
        "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM_PER_REQUEST'; style-src 'self'; object-src 'none'",
      difficulty: "Medium",
      owner: "Developer",
    },
  },
  "missing-hsts": {
    owasp: [A02],
    plainEnglish:
      "Without HSTS, a visitor's browser can be tricked into using unencrypted HTTP, allowing an attacker on the same network to read or modify their traffic.",
    howToFix:
      "Send the Strict-Transport-Security header from every HTTPS response, with a max-age of at least 6 months. Only enable preload after you have verified all subdomains support HTTPS.",
    fix: {
      change:
        "Add the Strict-Transport-Security HTTP response header for all HTTPS traffic.",
      example:
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "weak-hsts": {
    owasp: [A02],
    plainEnglish:
      "HSTS is enabled but expires too quickly, leaving a window where browsers can be tricked into downgrading to plain HTTP.",
    howToFix:
      "Increase the max-age value to at least 15552000 (180 days). For production sites, 31536000 (1 year) is recommended.",
    fix: {
      change:
        "Update the max-age value in the Strict-Transport-Security header.",
      example:
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "missing-x-frame-options": {
    owasp: [A05],
    plainEnglish:
      "Other websites can embed your pages inside a hidden frame and trick users into clicking buttons they cannot see (clickjacking).",
    howToFix:
      "Either set the X-Frame-Options header to DENY or SAMEORIGIN, or add a frame-ancestors directive to your Content-Security-Policy.",
    fix: {
      change:
        "Add the X-Frame-Options HTTP response header (or a CSP frame-ancestors directive).",
      example: "X-Frame-Options: DENY",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "missing-x-content-type-options": {
    owasp: [A05],
    plainEnglish:
      "The browser is allowed to guess what type of file it received, which can let an attacker upload a file that runs as a script in someone else's browser.",
    howToFix:
      "Send the X-Content-Type-Options: nosniff header on every response so browsers honor the declared content type.",
    fix: {
      change:
        "Add the X-Content-Type-Options HTTP response header on all responses.",
      example: "X-Content-Type-Options: nosniff",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "missing-referrer-policy": {
    owasp: [A05],
    plainEnglish:
      "Without a referrer policy, your visitors' browsers may leak the full URL of the page they were on (including search terms or session tokens in the path) to any third-party link they click.",
    howToFix:
      "Set the Referrer-Policy header to 'strict-origin-when-cross-origin' or 'no-referrer' depending on your privacy needs.",
    fix: {
      change: "Add the Referrer-Policy HTTP response header.",
      example: "Referrer-Policy: strict-origin-when-cross-origin",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "server-version-disclosure": {
    owasp: [A05],
    plainEnglish:
      "Your server is telling the world exactly which software and version it runs, which lets attackers look up known exploits for that exact version.",
    howToFix:
      "Suppress or generalize the Server header in your reverse proxy or web server configuration.",
    fix: {
      change: "Hide or rewrite the Server response header.",
      example:
        "nginx: server_tokens off;   |   Apache: ServerTokens Prod and ServerSignature Off",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "x-powered-by-disclosure": {
    owasp: [A05],
    plainEnglish:
      "Your application is advertising the framework or runtime it uses, which helps attackers narrow their search for working exploits.",
    howToFix:
      "Remove the X-Powered-By header at the application or proxy layer.",
    fix: {
      change: "Strip the X-Powered-By response header.",
      example:
        "Express: app.disable('x-powered-by')   |   PHP: expose_php = Off in php.ini",
      difficulty: "Low",
      owner: "Developer",
    },
  },
  "no-https": {
    owasp: [A02],
    plainEnglish:
      "The site is served over plain HTTP, so anyone on the same network can read or modify everything sent to or from it, including passwords and session cookies.",
    howToFix:
      "Obtain a TLS certificate (Let's Encrypt is free), serve the site over HTTPS, and 301-redirect all HTTP traffic to HTTPS.",
    fix: {
      change: "Enable HTTPS and force-redirect HTTP to HTTPS.",
      example:
        "nginx: return 301 https://$host$request_uri;   |   then add Strict-Transport-Security: max-age=31536000; includeSubDomains",
      difficulty: "Medium",
      owner: "Server Admin",
    },
  },
  "cookie-missing-secure": {
    owasp: [A02],
    plainEnglish:
      "Your session cookies can be sent over an unencrypted connection, where anyone on the same network can capture them and impersonate the user.",
    howToFix:
      "Set the Secure attribute on every cookie so it is only ever sent over HTTPS.",
    fix: {
      change: "Add the Secure attribute to every Set-Cookie response.",
      example:
        "Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
      difficulty: "Low",
      owner: "Developer",
    },
  },
  "cookie-missing-httponly": {
    owasp: [A05],
    plainEnglish:
      "Your session cookies are readable by JavaScript running on the page, so any cross-site scripting flaw can be turned into a full account takeover.",
    howToFix:
      "Add the HttpOnly attribute to every authentication or session cookie so JavaScript cannot read them.",
    fix: {
      change: "Add the HttpOnly attribute to session-related Set-Cookie headers.",
      example:
        "Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
      difficulty: "Low",
      owner: "Developer",
    },
  },
  "exposed--admin": {
    owasp: [A05],
    plainEnglish:
      "Your administrative login page is reachable from anywhere on the public internet, giving attackers an unlimited number of guesses against admin accounts.",
    howToFix:
      "Restrict /admin to a corporate VPN, an allowlist of office IPs, or place it behind an authenticated reverse proxy. Always require strong passwords plus MFA.",
    fix: {
      change:
        "Restrict access to the /admin path by network ACL, VPN, or basic-auth at the proxy.",
      example:
        "nginx:\n  location /admin { allow 203.0.113.0/24; deny all; auth_basic \"admin\"; auth_basic_user_file /etc/nginx/.htpasswd; }",
      difficulty: "Medium",
      owner: "IT Infrastructure",
    },
  },
  "exposed--phpmyadmin-": {
    owasp: [A05],
    plainEnglish:
      "phpMyAdmin gives full database access through a web page. Leaving it exposed means a single weak password can hand over your entire database.",
    howToFix:
      "Take phpMyAdmin off the public internet entirely. Move it behind a VPN or SSH tunnel, or uninstall it and use a database client over an SSH tunnel instead.",
    fix: {
      change:
        "Remove phpMyAdmin from the public web root or restrict it to internal networks only.",
      example:
        "Apache: <Location /phpmyadmin> Require ip 10.0.0.0/8 </Location>   |   or simply uninstall phpmyadmin and use SSH tunneling.",
      difficulty: "Medium",
      owner: "IT Infrastructure",
    },
  },
  "exposed--wp-admin-": {
    owasp: [A05],
    plainEnglish:
      "The WordPress admin panel is reachable publicly, making it a target for automated brute-force attacks.",
    howToFix:
      "Place wp-admin behind an HTTP basic-auth challenge or an IP allowlist, and require MFA for all admin users.",
    fix: {
      change:
        "Add HTTP basic auth or an IP allowlist on /wp-admin and /wp-login.php.",
      example:
        "nginx:\n  location ~ ^/(wp-admin|wp-login\\.php) { allow 203.0.113.0/24; deny all; }",
      difficulty: "Medium",
      owner: "IT Infrastructure",
    },
  },
  "exposed--env": {
    owasp: [A02, A05],
    plainEnglish:
      "Your .env file is downloadable from the public internet. These files almost always contain database passwords, API keys, and other secrets that fully compromise the application.",
    howToFix:
      "Immediately remove the file from the web root, rotate every secret it contained, and configure the web server to deny dotfiles.",
    fix: {
      change:
        "Block all dotfiles at the web server and rotate every credential the file contained.",
      example:
        "nginx:\n  location ~ /\\. { deny all; return 404; }\n\nThen rotate DB passwords, API keys, and JWT secrets.",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "exposed--git-config": {
    owasp: [A02, A05],
    plainEnglish:
      "The .git directory is readable over the web, which lets anyone download your full source code and commit history — frequently including passwords that were checked in by mistake.",
    howToFix:
      "Block all dotfiles at the web server, then audit your git history for any committed secrets and rotate them.",
    fix: {
      change:
        "Deny access to /.git/* at the web server and audit history for leaked secrets.",
      example:
        "nginx:\n  location ~ /\\.git { deny all; return 404; }\n\nApache:\n  <DirectoryMatch \"^/.*/\\.git/\"> Require all denied </DirectoryMatch>",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "exposed--server-status": {
    owasp: [A05],
    plainEnglish:
      "Apache's server-status page is exposing real-time information about every request, including IP addresses and URLs, which helps attackers map your traffic and find sensitive endpoints.",
    howToFix:
      "Restrict the server-status handler to localhost or an internal monitoring network.",
    fix: {
      change:
        "Limit the /server-status handler to internal/monitoring IPs only.",
      example:
        "Apache:\n  <Location /server-status>\n    SetHandler server-status\n    Require ip 127.0.0.1 10.0.0.0/8\n  </Location>",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "directory-listing": {
    owasp: [A05],
    plainEnglish:
      "Visitors who browse to a directory see an automatically generated list of every file inside it, often revealing backups, uploads, or files that were never meant to be public.",
    howToFix:
      "Disable directory auto-indexing in your web server configuration.",
    fix: {
      change:
        "Turn off automatic directory listings in your web server.",
      example:
        "nginx: autoindex off;\nApache: Options -Indexes",
      difficulty: "Low",
      owner: "Server Admin",
    },
  },
  "default-creds-hint": {
    owasp: [A07],
    plainEnglish:
      "The login page itself mentions default credentials like admin/admin. If those have not been changed, anyone in the world can log in as an administrator.",
    howToFix:
      "Force a password change on first login, remove any default accounts, and require strong passwords plus multi-factor authentication for all administrators.",
    fix: {
      change:
        "Disable or rename default accounts, force a password change at first login, and enforce MFA on admin accounts.",
      example:
        "Policy: minimum 14 chars, MFA required for all admin and remote access, no shared accounts.",
      difficulty: "Medium",
      owner: "IT Infrastructure",
    },
  },
  unreachable: {
    owasp: [],
    plainEnglish:
      "We were unable to connect to the target. This is not necessarily a security issue — the host may be offline, behind a firewall, or rate-limiting our scanner.",
    howToFix:
      "Verify the URL is correct, that the host is online, and that your scanner's IP is not being blocked.",
    fix: {
      change: "Check connectivity to the target host.",
      example: "curl -vI https://target.example",
      difficulty: "Low",
      owner: "IT Infrastructure",
    },
  },
  "clean-pass": {
    owasp: [],
    plainEnglish:
      "No common passive misconfigurations were found. This is a good baseline, but is not a substitute for an authenticated penetration test.",
    howToFix:
      "Continue with regular dependency audits, authenticated scans, and periodic penetration testing.",
    fix: {
      change: "No action required from this finding.",
      example: "Continue running passive scans on a regular schedule.",
      difficulty: "Low",
      owner: "Developer",
    },
  },
};

export function enrichFinding(id: string): FindingEnrichment | null {
  return ENRICHMENT[id] ?? null;
}
