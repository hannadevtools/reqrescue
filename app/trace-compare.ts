import {
  type Analysis,
  type RequestRow,
  formatBytes,
  formatDuration,
} from "./trace-engine";

export type ComparisonChange = {
  rank: number;
  confidence: "high" | "medium" | "low";
  kind: "failure" | "query" | "status" | "presence" | "latency";
  title: string;
  explanation: string;
  evidence: string[];
  nextStep: string;
};

export type HarComparison = {
  baseline: Analysis;
  changed: Analysis;
  changes: ComparisonChange[];
  title: string;
  markdown: string;
  findingCount: number;
  safetyScore: number;
};

type EndpointSnapshot = {
  method: string;
  host: string;
  path: string;
  count: number;
  failureCount: number;
  statuses: Set<number>;
  queryKeys: Set<string>;
  durations: number[];
};

const REQRESCUE_URL = "https://app.reqrescue.workers.dev";

function safeQueryKey(value: string): string {
  const trimmed = value.trim();
  if (/^[a-zA-Z0-9_.~-]{1,60}$/.test(trimmed)) return trimmed;
  return "[non-standard query key]";
}

function queryKeys(path: string): string[] {
  const query = path.includes("?") ? path.slice(path.indexOf("?") + 1) : "";
  if (!query) return [];

  try {
    return [...new Set([...new URLSearchParams(query).keys()].map(safeQueryKey))];
  } catch {
    return [];
  }
}

function pathWithoutQuery(path: string): string {
  const clean = path.split("?")[0] || "/";
  return clean.length > 180 ? `${clean.slice(0, 177)}…` : clean;
}

function endpointKey(row: RequestRow): string {
  return `${row.method}\u0000${row.host}\u0000${pathWithoutQuery(row.path)}`;
}

function snapshots(rows: RequestRow[]): Map<string, EndpointSnapshot> {
  const result = new Map<string, EndpointSnapshot>();

  for (const row of rows) {
    const key = endpointKey(row);
    const current = result.get(key) ?? {
      method: row.method,
      host: row.host,
      path: pathWithoutQuery(row.path),
      count: 0,
      failureCount: 0,
      statuses: new Set<number>(),
      queryKeys: new Set<string>(),
      durations: [],
    };

    current.count += 1;
    if (row.failure) current.failureCount += 1;
    current.statuses.add(row.status);
    current.durations.push(row.duration);
    for (const queryKey of queryKeys(row.path)) current.queryKeys.add(queryKey);
    result.set(key, current);
  }

  return result;
}

function sortedDifference(left: Set<string>, right: Set<string>): string[] {
  return [...left].filter((value) => !right.has(value)).sort();
}

function statusLabel(statuses: Set<number>): string {
  return [...statuses]
    .sort((a, b) => a - b)
    .map((status) => (status ? String(status) : "network error"))
    .join(", ");
}

function p95(values: number[]): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)];
}

function endpointLabel(snapshot: EndpointSnapshot): string {
  return `${snapshot.method} ${snapshot.host}${snapshot.path}`;
}

function inlineCode(value: string): string {
  return `\`${value.replace(/`/g, "ˋ")}\``;
}

function buildChange(
  baseline: EndpointSnapshot | undefined,
  changed: EndpointSnapshot | undefined,
): (Omit<ComparisonChange, "rank"> & { score: number }) | null {
  if (!baseline && !changed) return null;

  const sample = changed ?? baseline!;
  const label = endpointLabel(sample);

  if (!baseline) {
    return {
      score: changed!.failureCount ? 95 : 45,
      confidence: changed!.failureCount ? "high" : "medium",
      kind: "presence",
      title: `${label} appears only in capture B`,
      explanation: changed!.failureCount
        ? "Capture B introduces this endpoint and it fails. That makes it a strong candidate for the first changed branch in the broken flow."
        : "Capture B introduces this endpoint. This is an observed structural difference, not proof that the request caused the symptom.",
      evidence: [
        "Capture A: endpoint absent",
        `Capture B: ${changed!.count} request${changed!.count === 1 ? "" : "s"} · status ${statusLabel(changed!.statuses)}`,
      ],
      nextStep:
        "Identify which user action or client branch created this request, then inspect the first response or console event immediately before it.",
    };
  }

  if (!changed) {
    return {
      score: baseline.failureCount ? 55 : 48,
      confidence: "medium",
      kind: "presence",
      title: `${label} disappears from capture B`,
      explanation:
        "The endpoint is present in the baseline but never sent in capture B. A missing prerequisite request can be more important than a later HTTP error.",
      evidence: [
        `Capture A: ${baseline.count} request${baseline.count === 1 ? "" : "s"} · status ${statusLabel(baseline.statuses)}`,
        "Capture B: endpoint absent",
      ],
      nextStep:
        "Compare the user action, console output, and immediately preceding request to find why the client stopped before this endpoint.",
    };
  }

  const missingQuery = sortedDifference(baseline.queryKeys, changed.queryKeys);
  const addedQuery = sortedDifference(changed.queryKeys, baseline.queryKeys);
  const baselineStatuses = statusLabel(baseline.statuses);
  const changedStatuses = statusLabel(changed.statuses);
  const statusChanged = baselineStatuses !== changedStatuses;
  const newFailures = changed.failureCount > baseline.failureCount;
  const baselineP95 = p95(baseline.durations);
  const changedP95 = p95(changed.durations);
  const latencyRegression =
    changedP95 >= 1_000 &&
    changedP95 >= baselineP95 * 1.8 &&
    changedP95 - baselineP95 >= 500;

  if (
    !missingQuery.length &&
    !addedQuery.length &&
    !statusChanged &&
    !newFailures &&
    !latencyRegression
  ) {
    return null;
  }

  let score = 0;
  if (newFailures) score += 65;
  if (missingQuery.length) score += 45;
  if (statusChanged) score += 35;
  if (addedQuery.length) score += 18;
  if (latencyRegression) score += 22;

  const evidence = [
    `Capture A: ${baseline.count} request${baseline.count === 1 ? "" : "s"} · status ${baselineStatuses} · p95 ${formatDuration(baselineP95)}`,
    `Capture B: ${changed.count} request${changed.count === 1 ? "" : "s"} · status ${changedStatuses} · p95 ${formatDuration(changedP95)}`,
  ];
  if (missingQuery.length) {
    evidence.push(`Query keys present in A but missing from B: ${missingQuery.join(", ")}`);
  }
  if (addedQuery.length) {
    evidence.push(`Query keys added in B: ${addedQuery.join(", ")}`);
  }

  if (missingQuery.length) {
    const names = missingQuery.map(inlineCode).join(", ");
    return {
      score,
      confidence: newFailures || statusChanged ? "high" : "medium",
      kind: "query",
      title: `${names} ${missingQuery.length === 1 ? "disappears" : "disappear"} before ${label}`,
      explanation: newFailures
        ? "Capture B loses query structure that exists in A and the same endpoint records more failures. The correlation is strong, but the server response or signature rules must confirm causality."
        : "Capture B loses query structure that exists in A. This is a concrete request mutation, although the HAR alone cannot prove it caused the reported symptom.",
      evidence,
      nextStep:
        "Compare the URL when the application creates it with the final outgoing request. Check extensions, service workers, redirects, and URL-cleaning middleware before changing server code.",
    };
  }

  if (newFailures || statusChanged) {
    return {
      score,
      confidence: newFailures ? "high" : "medium",
      kind: newFailures ? "failure" : "status",
      title: `${label} changes from ${baselineStatuses} to ${changedStatuses}`,
      explanation: newFailures
        ? "The same endpoint has more failed attempts in capture B. This is an observed regression at a stable request boundary."
        : "The endpoint returns a different status pattern between the two captures. The response transition is observed; its root cause still needs server or client logs.",
      evidence,
      nextStep:
        "Inspect the first differing response body or response header in a private environment, then correlate it with the server request ID and application logs.",
    };
  }

  if (latencyRegression) {
    return {
      score,
      confidence: "medium",
      kind: "latency",
      title: `${label} slows from ${formatDuration(baselineP95)} to ${formatDuration(changedP95)}`,
      explanation:
        "The endpoint's p95 latency materially increases in capture B. HAR timing identifies the boundary, not whether the delay came from the network, cache, or upstream service.",
      evidence,
      nextStep:
        "Compare blocked, connect, wait, and receive timings, then check cache status and the matching upstream trace.",
    };
  }

  return null;
}

function markdownEscape(value: string): string {
  return value.replace(/[\\`*_{}[\]()#+.!|>-]/g, "\\$&");
}

function buildMarkdown(
  baseline: Analysis,
  changed: Analysis,
  title: string,
  changes: ComparisonChange[],
): string {
  const changeBody = changes.length
    ? changes
        .map(
          (change) => `### ${change.rank}. ${change.title}

**Confidence:** ${change.confidence}

${change.explanation}

${change.evidence.map((item) => `- ${item}`).join("\n")}

**Next check:** ${change.nextStep}`,
        )
        .join("\n\n")
    : `No material endpoint, status, query-key, failure-count, or latency difference was detected.

This does not mean the two sessions behaved identically. Console exceptions, WebSocket frames, EME/DRM events, DOM state, and response-body semantics may not be represented by this structural HAR comparison.`;

  return `# ${markdownEscape(title)}

## Captures

| | Capture A — baseline | Capture B — changed |
|---|---:|---:|
| File | ${inlineCode(baseline.sourceName)} | ${inlineCode(changed.sourceName)} |
| Requests | ${baseline.totalRequests} | ${changed.totalRequests} |
| Failed | ${baseline.failedRequests} | ${changed.failedRequests} |
| Domains | ${baseline.domainCount} | ${changed.domainCount} |
| p95 latency | ${formatDuration(baseline.p95Duration)} | ${formatDuration(changed.p95Duration)} |
| Transferred | ${formatBytes(baseline.totalBytes)} | ${formatBytes(changed.totalBytes)} |

## Ranked structural differences

${changeBody}

## Interpretation boundary

ReqRescue compares sanitized request structure, query-key presence, status patterns, request counts, and latency. It does not compare secret values or upload HAR contents. Treat each ranked item as a hypothesis until it is confirmed by the corresponding application or server log.

Generated locally by [ReqRescue](${REQRESCUE_URL}) — local HAR analysis, A/B comparison, secret removal, and incident handoff. **0 HAR bytes uploaded.**
`;
}

export function compareAnalyses(
  baseline: Analysis,
  changed: Analysis,
): HarComparison {
  const baselineSnapshots = snapshots(baseline.requests);
  const changedSnapshots = snapshots(changed.requests);
  const keys = new Set([...baselineSnapshots.keys(), ...changedSnapshots.keys()]);

  const ranked = [...keys]
    .map((key) => buildChange(baselineSnapshots.get(key), changedSnapshots.get(key)))
    .filter(
      (
        item,
      ): item is Omit<ComparisonChange, "rank"> & {
        score: number;
      } => Boolean(item),
    )
    .sort((a, b) => b.score - a.score || a.title.localeCompare(b.title))
    .slice(0, 12)
    .map((change, index) => ({
      rank: index + 1,
      confidence: change.confidence,
      kind: change.kind,
      title: change.title,
      explanation: change.explanation,
      evidence: change.evidence,
      nextStep: change.nextStep,
    }));

  const title = ranked[0]
    ? `HAR comparison: ${ranked[0].title}`
    : "HAR comparison: no material structural difference detected";
  const findingCount = baseline.findingCount + changed.findingCount;
  const safetyScore = Math.min(baseline.safetyScore, changed.safetyScore);

  return {
    baseline,
    changed,
    changes: ranked,
    title,
    markdown: buildMarkdown(baseline, changed, title, ranked),
    findingCount,
    safetyScore,
  };
}
