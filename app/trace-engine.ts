export type HarHeader = { name?: string; value?: string };
export type HarCookie = { name?: string; value?: string };
export type HarQuery = { name?: string; value?: string };

export type HarEntry = {
  startedDateTime?: string;
  time?: number;
  request?: {
    method?: string;
    url?: string;
    headers?: HarHeader[];
    cookies?: HarCookie[];
    queryString?: HarQuery[];
    postData?: {
      mimeType?: string;
      text?: string;
      params?: Array<{ name?: string; value?: string; fileName?: string }>;
    };
  };
  response?: {
    status?: number;
    statusText?: string;
    headers?: HarHeader[];
    cookies?: HarCookie[];
    content?: {
      size?: number;
      mimeType?: string;
      text?: string;
      encoding?: string;
    };
    bodySize?: number;
    _transferSize?: number;
  };
  cache?: unknown;
  timings?: Record<string, number>;
  serverIPAddress?: string;
  connection?: string;
  _error?: string;
};

export type HarFile = {
  log: {
    version?: string;
    creator?: { name?: string; version?: string };
    browser?: { name?: string; version?: string };
    pages?: Array<{
      id?: string;
      title?: string;
      startedDateTime?: string;
      pageTimings?: Record<string, number>;
    }>;
    entries: HarEntry[];
  };
};

export type FindingKind =
  | "authorization"
  | "cookie"
  | "api-key"
  | "token"
  | "password"
  | "email"
  | "ip-address"
  | "private-host"
  | "body";

export type Finding = {
  kind: FindingKind;
  label: string;
  count: number;
  severity: "critical" | "high" | "medium";
};

export type Suspect = {
  rank: number;
  confidence: "high" | "medium" | "low";
  title: string;
  explanation: string;
  evidence: string[];
};

export type RequestRow = {
  id: number;
  method: string;
  host: string;
  path: string;
  status: number;
  statusText: string;
  duration: number;
  size: number;
  startedAt: string;
  mimeType: string;
  failure: boolean;
};

export type Analysis = {
  sourceName: string;
  totalRequests: number;
  failedRequests: number;
  clientErrors: number;
  serverErrors: number;
  redirects: number;
  totalBytes: number;
  totalDuration: number;
  p95Duration: number;
  domainCount: number;
  findings: Finding[];
  findingCount: number;
  suspects: Suspect[];
  requests: RequestRow[];
  markdown: string;
  aiPrompt: string;
  sanitized: HarFile;
  safetyScore: number;
  title: string;
};

const SENSITIVE_NAME =
  /(^|[-_.])(authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|secret|client-secret|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|session|sessionid|csrf|xsrf|jwt|signature|sig|private[-_]?key)($|[-_.])/i;

const AUTH_HEADER = /^(authorization|proxy-authorization)$/i;
const COOKIE_HEADER = /^(cookie|set-cookie)$/i;
const API_KEY_HEADER = /(^|[-_])(api[-_]?key|subscription[-_]?key|client[-_]?secret)($|[-_])/i;
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const JWT = /\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\b/g;
const BEARER = /\bBearer\s+[a-zA-Z0-9._~+/=-]{8,}\b/gi;
const BASIC = /\bBasic\s+[a-zA-Z0-9+/=]{8,}\b/gi;
const COMMON_SECRET =
  /\b(?:sk_live_[a-zA-Z0-9]{12,}|sk_test_[a-zA-Z0-9]{12,}|gh[pousr]_[a-zA-Z0-9]{20,}|AIza[a-zA-Z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b/g;
const PRIVATE_HOST =
  /^(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|[^.]+\.local)$/i;

const FAILURE_EXPLANATIONS: Record<number, string> = {
  400: "The server rejected the request shape or payload.",
  401: "Credentials were missing, expired, or rejected.",
  403: "The request reached the server but permission, CSRF, or a security rule blocked it.",
  404: "The requested route or resource was not found.",
  408: "The request timed out before the server completed it.",
  409: "The request conflicted with the current server-side state.",
  422: "The payload was understood but failed validation.",
  429: "The caller hit a rate or quota limit.",
  500: "The server failed while handling an otherwise reachable request.",
  502: "A gateway received an invalid response from an upstream service.",
  503: "The service was unavailable or overloaded.",
  504: "A gateway timed out waiting for an upstream service.",
};

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function percentile(values: number[], amount: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * amount) - 1)];
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const power = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** power;
  return `${value >= 10 || power === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[power]}`;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "0 ms";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms >= 10_000 ? 1 : 2)} s`;
  return `${(ms / 60_000).toFixed(1)} min`;
}

function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function getEntrySize(entry: HarEntry): number {
  const response = entry.response;
  if (!response) return 0;
  const candidates = [
    response._transferSize,
    response.bodySize,
    response.content?.size,
  ];
  return Math.max(0, ...candidates.map(asNumber));
}

function addFinding(
  map: Map<FindingKind, Finding>,
  kind: FindingKind,
  label: string,
  severity: Finding["severity"],
  count = 1,
) {
  const current = map.get(kind);
  if (current) {
    current.count += count;
  } else {
    map.set(kind, { kind, label, severity, count });
  }
}

function scanText(
  value: string,
  findings: Map<FindingKind, Finding>,
  includeBody = false,
) {
  const emails = value.match(EMAIL)?.length ?? 0;
  if (emails) addFinding(findings, "email", "Email addresses", "medium", emails);

  const ips = value.match(IPV4)?.length ?? 0;
  if (ips) addFinding(findings, "ip-address", "IP addresses", "medium", ips);

  const tokens =
    (value.match(JWT)?.length ?? 0) +
    (value.match(BEARER)?.length ?? 0) +
    (value.match(BASIC)?.length ?? 0) +
    (value.match(COMMON_SECRET)?.length ?? 0);
  if (tokens) addFinding(findings, "token", "Token-shaped secrets", "critical", tokens);

  if (includeBody && value.length > 0) {
    addFinding(findings, "body", "Captured request/response bodies", "high");
  }
}

function scanNamedValue(
  name: string,
  value: string,
  findings: Map<FindingKind, Finding>,
) {
  if (AUTH_HEADER.test(name)) {
    addFinding(findings, "authorization", "Authorization headers", "critical");
  } else if (COOKIE_HEADER.test(name) || /cookie|session/i.test(name)) {
    addFinding(findings, "cookie", "Cookies and sessions", "critical");
  } else if (API_KEY_HEADER.test(name)) {
    addFinding(findings, "api-key", "API keys", "critical");
  } else if (/pass(word)?|pwd/i.test(name)) {
    addFinding(findings, "password", "Passwords", "critical");
  } else if (SENSITIVE_NAME.test(name)) {
    addFinding(findings, "token", "Token-shaped fields", "critical");
  }
  scanText(value, findings);
}

function collectFindings(har: HarFile): Finding[] {
  const findings = new Map<FindingKind, Finding>();

  for (const entry of har.log.entries) {
    const url = safeUrl(entry.request?.url ?? "");
    if (url) {
      if (PRIVATE_HOST.test(url.hostname)) {
        addFinding(findings, "private-host", "Private hostnames", "high");
      }
      for (const [name, value] of url.searchParams.entries()) {
        scanNamedValue(name, value, findings);
      }
    }

    for (const header of entry.request?.headers ?? []) {
      scanNamedValue(header.name ?? "", header.value ?? "", findings);
    }
    for (const header of entry.response?.headers ?? []) {
      scanNamedValue(header.name ?? "", header.value ?? "", findings);
    }
    for (const cookie of entry.request?.cookies ?? []) {
      addFinding(findings, "cookie", "Cookies and sessions", "critical");
      scanText(cookie.value ?? "", findings);
    }
    for (const cookie of entry.response?.cookies ?? []) {
      addFinding(findings, "cookie", "Cookies and sessions", "critical");
      scanText(cookie.value ?? "", findings);
    }
    for (const query of entry.request?.queryString ?? []) {
      scanNamedValue(query.name ?? "", query.value ?? "", findings);
    }

    const postText = entry.request?.postData?.text;
    if (postText) scanText(postText, findings, true);
    for (const param of entry.request?.postData?.params ?? []) {
      scanNamedValue(param.name ?? "", param.value ?? "", findings);
    }
    const responseText = entry.response?.content?.text;
    if (responseText) scanText(responseText, findings, true);
  }

  return [...findings.values()].sort((a, b) => {
    const priority = { critical: 3, high: 2, medium: 1 };
    return priority[b.severity] - priority[a.severity] || b.count - a.count;
  });
}

function maskText(value: string): string {
  return value
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(BASIC, "Basic [REDACTED]")
    .replace(JWT, "[REDACTED_JWT]")
    .replace(COMMON_SECRET, "[REDACTED_SECRET]")
    .replace(EMAIL, "[REDACTED_EMAIL]")
    .replace(IPV4, "[REDACTED_IP]");
}

function redactStructuredText(value: string): string {
  let next = maskText(value);

  try {
    const parsed = JSON.parse(value);
    const redacted = redactObject(parsed);
    next = JSON.stringify(redacted);
  } catch {
    next = next.replace(
      /((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|session|jwt|authorization)\s*[=:]\s*)(["']?)[^&\s,"'}]+/gi,
      "$1$2[REDACTED]",
    );
  }

  return next;
}

function redactObject(value: unknown, key = ""): unknown {
  if (SENSITIVE_NAME.test(key)) return "[REDACTED]";
  if (typeof value === "string") return redactStructuredText(value);
  if (Array.isArray(value)) return value.map((item) => redactObject(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([childKey, childValue]) => [
        childKey,
        redactObject(childValue, childKey),
      ]),
    );
  }
  return value;
}

function redactHeaders(headers: HarHeader[] | undefined): HarHeader[] | undefined {
  return headers?.map((header) => {
    const name = header.name ?? "";
    const value = header.value ?? "";
    return {
      ...header,
      value: SENSITIVE_NAME.test(name) || AUTH_HEADER.test(name) || COOKIE_HEADER.test(name)
        ? "[REDACTED]"
        : maskText(value),
    };
  });
}

function redactCookies(cookies: HarCookie[] | undefined): HarCookie[] | undefined {
  return cookies?.map((cookie) => ({ ...cookie, value: "[REDACTED]" }));
}

function redactQuery(query: HarQuery[] | undefined): HarQuery[] | undefined {
  return query?.map((item) => ({
    ...item,
    value: SENSITIVE_NAME.test(item.name ?? "")
      ? "[REDACTED]"
      : maskText(item.value ?? ""),
  }));
}

function redactUrl(raw: string | undefined): string | undefined {
  if (!raw) return raw;
  const url = safeUrl(raw);
  if (!url) return maskText(raw);

  for (const [key, value] of url.searchParams.entries()) {
    url.searchParams.set(key, SENSITIVE_NAME.test(key) ? "[REDACTED]" : maskText(value));
  }
  if (PRIVATE_HOST.test(url.hostname)) url.hostname = "private-host.invalid";
  return url.toString();
}

export function sanitizeHar(har: HarFile): HarFile {
  const cloned = structuredClone(har);

  cloned.log.entries = cloned.log.entries.map((entry) => {
    const next = entry;
    if (next.request) {
      next.request.url = redactUrl(next.request.url);
      next.request.headers = redactHeaders(next.request.headers);
      next.request.cookies = redactCookies(next.request.cookies);
      next.request.queryString = redactQuery(next.request.queryString);
      if (next.request.postData?.text) {
        next.request.postData.text = redactStructuredText(next.request.postData.text);
      }
      if (next.request.postData?.params) {
        next.request.postData.params = next.request.postData.params.map((param) => ({
          ...param,
          value: SENSITIVE_NAME.test(param.name ?? "")
            ? "[REDACTED]"
            : maskText(param.value ?? ""),
        }));
      }
    }
    if (next.response) {
      next.response.headers = redactHeaders(next.response.headers);
      next.response.cookies = redactCookies(next.response.cookies);
      if (next.response.content?.text) {
        next.response.content.text = redactStructuredText(next.response.content.text);
      }
    }
    if (next.serverIPAddress) next.serverIPAddress = "[REDACTED_IP]";
    return next;
  });

  return cloned;
}

function toRequestRows(entries: HarEntry[]): RequestRow[] {
  return entries.map((entry, index) => {
    const url = safeUrl(entry.request?.url ?? "");
    const status = asNumber(entry.response?.status);
    return {
      id: index + 1,
      method: entry.request?.method?.toUpperCase() || "GET",
      host: url?.hostname || "unknown-host",
      path: url ? `${url.pathname}${url.search}` : entry.request?.url || "/",
      status,
      statusText: entry.response?.statusText || entry._error || "",
      duration: Math.max(0, asNumber(entry.time)),
      size: getEntrySize(entry),
      startedAt: entry.startedDateTime || "",
      mimeType: entry.response?.content?.mimeType || "",
      failure: status === 0 || status >= 400,
    };
  });
}

function endpointLabel(row: RequestRow): string {
  const path = row.path.split("?")[0];
  return `${row.method} ${row.host}${path}`;
}

function buildSuspects(rows: RequestRow[], p95Duration: number): Suspect[] {
  const suspects: Array<Omit<Suspect, "rank"> & { score: number }> = [];
  const failures = rows.filter((row) => row.failure);

  const groupedFailures = new Map<string, RequestRow[]>();
  for (const row of failures) {
    const key = `${row.status}:${row.host}:${row.path.split("?")[0]}`;
    groupedFailures.set(key, [...(groupedFailures.get(key) ?? []), row]);
  }

  for (const group of groupedFailures.values()) {
    const sample = group[0];
    const status = sample.status;
    const explanation =
      status === 0
        ? "The browser recorded no HTTP response. Common causes are CORS, DNS, TLS, an aborted request, an extension, or lost connectivity."
        : FAILURE_EXPLANATIONS[status] ??
          (status >= 500
            ? "The request reached the service and failed on the server side."
            : "The request completed with an unsuccessful HTTP status.");
    const repeated = group.length > 1;
    suspects.push({
      score:
        (status >= 500 ? 90 : status === 401 || status === 403 ? 84 : status === 0 ? 76 : 70) +
        Math.min(9, group.length - 1),
      confidence: repeated || status >= 500 ? "high" : "medium",
      title: `${status || "Network"} failure at ${endpointLabel(sample)}`,
      explanation,
      evidence: [
        `${group.length} matching failed request${group.length === 1 ? "" : "s"}`,
        status ? `HTTP ${status}${sample.statusText ? ` ${sample.statusText}` : ""}` : "No HTTP status returned",
        `${formatDuration(sample.duration)} observed duration`,
      ],
    });
  }

  const slow = rows
    .filter((row) => !row.failure && row.duration > Math.max(1000, p95Duration))
    .sort((a, b) => b.duration - a.duration)
    .slice(0, 2);
  for (const row of slow) {
    suspects.push({
      score: 56,
      confidence: "low",
      title: `Latency hotspot at ${endpointLabel(row)}`,
      explanation:
        "This request succeeded, but it sits in the slow tail and may be delaying the user-visible flow.",
      evidence: [
        `${formatDuration(row.duration)} duration`,
        `Slow-tail threshold ${formatDuration(p95Duration)}`,
        `HTTP ${row.status}`,
      ],
    });
  }

  const redirectsByHost = new Map<string, RequestRow[]>();
  for (const row of rows.filter((item) => item.status >= 300 && item.status < 400)) {
    redirectsByHost.set(row.host, [...(redirectsByHost.get(row.host) ?? []), row]);
  }
  for (const [host, group] of redirectsByHost) {
    if (group.length >= 3) {
      suspects.push({
        score: 62 + Math.min(group.length, 10),
        confidence: "medium",
        title: `Redirect churn on ${host}`,
        explanation:
          "Several redirects were recorded for one host. Check canonical URL, login, locale, and trailing-slash rules.",
        evidence: [
          `${group.length} redirect responses`,
          `Statuses ${[...new Set(group.map((row) => row.status))].join(", ")}`,
        ],
      });
    }
  }

  if (!suspects.length && rows.length) {
    const slowest = [...rows].sort((a, b) => b.duration - a.duration)[0];
    suspects.push({
      score: 35,
      confidence: "low",
      title: "No explicit network failure was captured",
      explanation:
        "Every recorded request returned below HTTP 400. The problem may be in client-side JavaScript, rendering, state, or an interaction that happened outside this capture.",
      evidence: [
        `${rows.length} requests inspected`,
        `Slowest request: ${endpointLabel(slowest)} in ${formatDuration(slowest.duration)}`,
      ],
    });
  }

  return suspects
    .sort((a, b) => b.score - a.score)
    .slice(0, 5)
    .map((suspect, index) => ({
      rank: index + 1,
      confidence: suspect.confidence,
      title: suspect.title,
      explanation: suspect.explanation,
      evidence: suspect.evidence,
    }));
}

function markdownEscape(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function buildReport(
  sourceName: string,
  har: HarFile,
  rows: RequestRow[],
  suspects: Suspect[],
  findings: Finding[],
  metrics: {
    totalBytes: number;
    totalDuration: number;
    p95Duration: number;
    domainCount: number;
  },
): { title: string; markdown: string; aiPrompt: string } {
  const failures = rows.filter((row) => row.failure);
  const firstFailure = failures[0];
  const title = firstFailure
    ? `Network failure: ${firstFailure.status || "no response"} at ${endpointLabel(firstFailure)}`
    : `Network trace review: ${rows.length} requests, no HTTP failure`;
  const browser = har.log.browser
    ? `${har.log.browser.name ?? "Unknown"} ${har.log.browser.version ?? ""}`.trim()
    : "Not recorded";
  const creator = har.log.creator
    ? `${har.log.creator.name ?? "Unknown"} ${har.log.creator.version ?? ""}`.trim()
    : "Not recorded";
  const started = rows.find((row) => row.startedAt)?.startedAt || "Not recorded";
  const page = har.log.pages?.[0]?.title || "Not recorded";
  const topEvidence = rows
    .filter((row) => row.failure)
    .slice(0, 12)
    .map(
      (row) =>
        `| ${markdownEscape(row.method)} | ${row.status || "—"} | \`${markdownEscape(
          `${row.host}${row.path.split("?")[0]}`,
        )}\` | ${formatDuration(row.duration)} |`,
    );

  const markdown = `# ${title}

## Summary

- ${rows.length} requests across ${metrics.domainCount} domains
- ${failures.length} failed request${failures.length === 1 ? "" : "s"}
- ${formatDuration(metrics.p95Duration)} p95 request time
- ${formatBytes(metrics.totalBytes)} transferred
- ${findings.reduce((sum, item) => sum + item.count, 0)} sensitive value${findings.reduce((sum, item) => sum + item.count, 0) === 1 ? "" : "s"} removed from the shareable HAR

## Ranked suspects

${suspects
  .map(
    (suspect) => `### ${suspect.rank}. ${suspect.title}

**Confidence:** ${suspect.confidence}

${suspect.explanation}

Evidence:
${suspect.evidence.map((item) => `- ${item}`).join("\n")}`,
  )
  .join("\n\n")}

## Failed requests

| Method | Status | Endpoint | Time |
|---|---:|---|---:|
${topEvidence.length ? topEvidence.join("\n") : "| — | — | No HTTP failures captured | — |"}

## Capture context

- Source: ${sourceName}
- Started: ${started}
- Page: ${page}
- Browser: ${browser}
- HAR creator: ${creator}
- Trace span: ${formatDuration(metrics.totalDuration)}

## Reproduction notes

1. Open the affected flow.
2. Reproduce the issue with DevTools Network recording enabled.
3. Compare the first failed endpoint and status with the ranked suspects above.
4. Inspect server logs around the capture timestamp.

## Privacy

Generated locally by ReqRescue. The attached sanitized HAR should still be reviewed before sharing. Automated redaction reduces risk but cannot guarantee removal of every domain-specific secret.
`;

  const aiPrompt = `You are debugging a web incident. Treat the evidence below as facts and the ranked suspects as hypotheses. Identify the most likely root cause, explicitly cite supporting requests, list what cannot be concluded, and propose the smallest next diagnostic step.

${markdown}`;

  return { title, markdown, aiPrompt };
}

export function parseHar(text: string): HarFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("This file is not valid JSON.");
  }

  const candidate = parsed as Partial<HarFile>;
  if (!candidate?.log || !Array.isArray(candidate.log.entries)) {
    throw new Error("This JSON does not contain a HAR log.entries array.");
  }
  if (!candidate.log.entries.length) {
    throw new Error("The HAR is valid, but it contains no network requests.");
  }
  return candidate as HarFile;
}

export function analyzeHar(har: HarFile, sourceName: string): Analysis {
  const rows = toRequestRows(har.log.entries);
  const durations = rows.map((row) => row.duration);
  const started = rows
    .map((row) => Date.parse(row.startedAt))
    .filter((value) => Number.isFinite(value));
  const ended = rows
    .map((row) => {
      const time = Date.parse(row.startedAt);
      return Number.isFinite(time) ? time + row.duration : NaN;
    })
    .filter((value) => Number.isFinite(value));
  const totalDuration =
    started.length && ended.length
      ? Math.max(0, Math.max(...ended) - Math.min(...started))
      : durations.reduce((sum, value) => sum + value, 0);
  const p95Duration = percentile(durations, 0.95);
  const findings = collectFindings(har);
  const sanitized = sanitizeHar(har);
  const suspects = buildSuspects(rows, p95Duration);
  const totalBytes = rows.reduce((sum, row) => sum + row.size, 0);
  const domainCount = new Set(rows.map((row) => row.host)).size;
  const findingCount = findings.reduce((sum, finding) => sum + finding.count, 0);
  const report = buildReport(sourceName, har, rows, suspects, findings, {
    totalBytes,
    totalDuration,
    p95Duration,
    domainCount,
  });
  const criticalCount = findings
    .filter((item) => item.severity === "critical")
    .reduce((sum, item) => sum + item.count, 0);
  const highCount = findings
    .filter((item) => item.severity === "high")
    .reduce((sum, item) => sum + item.count, 0);
  const safetyScore = Math.max(5, 100 - criticalCount * 12 - highCount * 5);

  return {
    sourceName,
    totalRequests: rows.length,
    failedRequests: rows.filter((row) => row.failure).length,
    clientErrors: rows.filter((row) => row.status >= 400 && row.status < 500).length,
    serverErrors: rows.filter((row) => row.status >= 500).length,
    redirects: rows.filter((row) => row.status >= 300 && row.status < 400).length,
    totalBytes,
    totalDuration,
    p95Duration,
    domainCount,
    findings,
    findingCount,
    suspects,
    requests: rows,
    markdown: report.markdown,
    aiPrompt: report.aiPrompt,
    sanitized,
    safetyScore,
    title: report.title,
  };
}

export function buildSanitizedPreview(analysis: Pick<Analysis, "sanitized">): string {
  const selected = [...analysis.sanitized.log.entries]
    .sort((a, b) => {
      const aFailed = (a.response?.status ?? 0) >= 400 || Boolean(a._error);
      const bFailed = (b.response?.status ?? 0) >= 400 || Boolean(b._error);
      return Number(bFailed) - Number(aFailed);
    })
    .slice(0, 2)
    .map((entry) => ({
      request: {
        method: entry.request?.method ?? "GET",
        url: entry.request?.url ?? "",
        headers: entry.request?.headers?.slice(0, 8) ?? [],
        cookies: entry.request?.cookies?.slice(0, 4) ?? [],
        query: entry.request?.queryString?.slice(0, 6) ?? [],
        body: entry.request?.postData?.text?.slice(0, 500) || undefined,
      },
      response: {
        status: entry.response?.status ?? 0,
        headers: entry.response?.headers?.slice(0, 8) ?? [],
        cookies: entry.response?.cookies?.slice(0, 4) ?? [],
        body: entry.response?.content?.text?.slice(0, 500) || undefined,
      },
    }));

  return JSON.stringify({ preview: "sanitized locally", requests: selected }, null, 2);
}

export function buildDemoHar(): HarFile {
  const started = new Date(Date.now() - 14_000).toISOString();
  const entry = (
    offset: number,
    method: string,
    url: string,
    status: number,
    time: number,
    options: {
      statusText?: string;
      requestHeaders?: HarHeader[];
      responseHeaders?: HarHeader[];
      requestBody?: string;
      responseBody?: string;
      size?: number;
    } = {},
  ): HarEntry => ({
    startedDateTime: new Date(Date.parse(started) + offset).toISOString(),
    time,
    request: {
      method,
      url,
      headers: options.requestHeaders ?? [],
      cookies: [{ name: "session", value: "sess_live_demo_9f8a7b6c" }],
      queryString: safeUrl(url)
        ? [...safeUrl(url)!.searchParams.entries()].map(([name, value]) => ({ name, value }))
        : [],
      ...(options.requestBody
        ? {
            postData: {
              mimeType: "application/json",
              text: options.requestBody,
            },
          }
        : {}),
    },
    response: {
      status,
      statusText: options.statusText ?? "",
      headers: options.responseHeaders ?? [],
      content: {
        size: options.size ?? 1024,
        mimeType: "application/json",
        ...(options.responseBody ? { text: options.responseBody } : {}),
      },
      bodySize: options.size ?? 1024,
      _transferSize: (options.size ?? 1024) + 340,
    },
    timings: {
      blocked: 0,
      dns: 3,
      connect: 15,
      ssl: 10,
      send: 1,
      wait: Math.max(0, time - 30),
      receive: 1,
    },
  });

  return {
    log: {
      version: "1.2",
      creator: { name: "Chrome", version: "126.0" },
      browser: { name: "Chrome", version: "126.0" },
      pages: [
        {
          id: "page_1",
          title: "Checkout — Example Store",
          startedDateTime: started,
        },
      ],
      entries: [
        entry(0, "GET", "https://shop.example.test/checkout", 200, 184, { size: 24_800 }),
        entry(
          240,
          "GET",
          "https://api.example.test/v1/cart?session=sess_live_demo_9f8a7b6c&email=alex@example.com",
          200,
          318,
          {
            requestHeaders: [
              { name: "Authorization", value: "Bearer eyJhbGciOiJIUzI1NiJ9.demo.signature" },
            ],
            size: 4_820,
          },
        ),
        entry(710, "POST", "https://api.example.test/v1/checkout", 401, 462, {
          statusText: "Unauthorized",
          requestHeaders: [
            { name: "Authorization", value: "Bearer eyJhbGciOiJIUzI1NiJ9.expired.signature" },
            { name: "Content-Type", value: "application/json" },
          ],
          responseHeaders: [{ name: "Set-Cookie", value: "session=expired; HttpOnly" }],
          requestBody: JSON.stringify({
            email: "alex@example.com",
            password: "not-a-real-password",
            cartId: "cart_725",
          }),
          responseBody: JSON.stringify({
            error: "token_expired",
            access_token: "sk_test_1234567890abcdefghijkl",
          }),
          size: 186,
        }),
        entry(1_410, "POST", "https://api.example.test/v1/auth/refresh", 401, 390, {
          statusText: "Unauthorized",
          requestHeaders: [
            { name: "Cookie", value: "session=sess_live_demo_9f8a7b6c" },
            { name: "X-Api-Key", value: "AIzaSyDemoKeyThatShouldNeverBeShared" },
          ],
          responseBody: JSON.stringify({ error: "refresh_token_revoked" }),
          size: 124,
        }),
        entry(2_050, "GET", "https://cdn.example.test/app.js", 200, 2_850, {
          size: 486_000,
        }),
        entry(5_150, "POST", "https://api.example.test/v1/checkout", 401, 447, {
          statusText: "Unauthorized",
          requestHeaders: [
            { name: "Authorization", value: "Bearer eyJhbGciOiJIUzI1NiJ9.expired.signature" },
          ],
          requestBody: JSON.stringify({ cartId: "cart_725" }),
          responseBody: JSON.stringify({ error: "token_expired" }),
          size: 156,
        }),
        entry(6_100, "POST", "https://logs.vendor.test/collect", 0, 5_000, {
          statusText: "Failed",
          requestBody: JSON.stringify({ ip: "192.168.1.24", user: "alex@example.com" }),
          size: 0,
        }),
      ],
    },
  };
}
