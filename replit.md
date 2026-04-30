# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.

## Artifacts

- **api-server** (`artifacts/api-server`) — Express 5 API. Routes: `/api/healthz`, `/api/scan`, `/api/cve/search`, `/api/cve/:id`, `/api/hash/check`, `/api/stats`. In-memory activity tracker. Optional env: `NVD_API_KEY`.
- **soc-dashboard** (`artifacts/soc-dashboard`, slug `/`) — "Sentinel // Lab" SOC-style React+Vite dashboard. Five tools: Vulnerability Scanner (passive HTTP), Packet Visualizer (tcpdump/Wireshark parsing), Log Analyzer (CSV export), CVE Lookup (NVD), Hash Identifier (HIBP k-anonymity for SHA-1). Dark theme, JetBrains Mono, no emojis.
- **mockup-sandbox** — design canvas (not used by SOC dashboard).

## Backend Notes

- Scanner blocks private/loopback IPs to prevent SSRF.
- HIBP check only runs against SHA-1 input; uses k-anonymity (5-char prefix).
- CVE proxy uses NVD 2.0; if `NVD_API_KEY` is set, sends `apiKey` header for higher rate limits.
