type ActivityKind = "scan" | "cve" | "hash";

export type ActivityEntry = {
  kind: ActivityKind;
  label: string;
  at: string;
  severity?: string;
};

const MAX_ACTIVITY = 50;

const state = {
  scansRun: 0,
  cveLookups: 0,
  hashChecks: 0,
  criticalFindings: 0,
  recent: [] as ActivityEntry[],
};

export function recordScan(target: string, criticalFindings: number) {
  state.scansRun++;
  state.criticalFindings += criticalFindings;
  prepend({
    kind: "scan",
    label: `Scanned ${target}`,
    at: new Date().toISOString(),
    severity: criticalFindings > 0 ? "critical" : undefined,
  });
}

export function recordCveLookup(label: string) {
  state.cveLookups++;
  prepend({
    kind: "cve",
    label,
    at: new Date().toISOString(),
  });
}

export function recordHashCheck(label: string, pwned: boolean) {
  state.hashChecks++;
  prepend({
    kind: "hash",
    label,
    at: new Date().toISOString(),
    severity: pwned ? "high" : undefined,
  });
}

function prepend(entry: ActivityEntry) {
  state.recent.unshift(entry);
  if (state.recent.length > MAX_ACTIVITY) {
    state.recent.length = MAX_ACTIVITY;
  }
}

export function getStats() {
  return {
    scansRun: state.scansRun,
    cveLookups: state.cveLookups,
    hashChecks: state.hashChecks,
    criticalFindings: state.criticalFindings,
    recentActivity: state.recent.slice(0, 25),
  };
}
