import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  analyzeHar,
  buildDemoHar,
  buildSanitizedPreview,
  type HarFile,
  parseHar,
  sanitizeHar,
} from "../app/trace-engine";

function entry(
  url: string,
  status: number,
  time = 100,
): HarFile["log"]["entries"][number] {
  return {
    startedDateTime: "2026-07-27T08:00:00.000Z",
    time,
    request: { method: "GET", url, headers: [] },
    response: {
      status,
      statusText: status >= 400 ? "Dangerous internal detail" : "OK",
      headers: [],
      content: { size: 12, mimeType: "application/json" },
      bodySize: 12,
    },
    timings: { wait: time },
  };
}

function har(entries: HarFile["log"]["entries"]): HarFile {
  return { log: { version: "1.2", entries } };
}

test("ranks the repeated auth failure above an unrelated telemetry failure", () => {
  const analysis = analyzeHar(buildDemoHar(), "demo.har");

  assert.equal(analysis.totalRequests, 7);
  assert.equal(analysis.failedRequests, 4);
  assert.match(analysis.suspects[0].title, /authentication chain failed/i);
  assert.equal(analysis.suspects[0].confidence, "high");
  assert.match(analysis.suspects[0].evidence.join(" "), /checkout.*auth\/refresh/i);
  assert.match(analysis.suspects[0].nextStep, /fresh session|authentication service/i);
  assert.match(analysis.markdown, /Ranked suspects/);
  assert.match(analysis.markdown, /Recommended next check/);
  assert.match(
    analysis.markdown,
    /\[ReqRescue\]\(https:\/\/app\.reqrescue\.workers\.dev\)/,
  );
  assert.match(analysis.markdown, /0 HAR bytes uploaded/);
});

test("removes the known secrets and PII in the demo HAR", () => {
  const raw = buildDemoHar();
  const clean = JSON.stringify(sanitizeHar(raw));

  assert.doesNotMatch(clean, /alex@example\.com/);
  assert.doesNotMatch(clean, /sess_live_demo/);
  assert.doesNotMatch(clean, /not-a-real-password/);
  assert.doesNotMatch(clean, /sk_test_/);
  assert.doesNotMatch(clean, /192\.168\.1\.24/);
  assert.match(clean, /\[REDACTED/);
});

test("builds the preview only from sanitized evidence", () => {
  const analysis = analyzeHar(buildDemoHar(), "demo.har");
  const preview = buildSanitizedPreview(analysis);
  const parsed = JSON.parse(preview) as { requests: unknown[] };

  assert.equal(parsed.requests.length, 2);
  assert.match(preview, /\[REDACTED/);
  assert.doesNotMatch(preview, /alex@example\.com/);
  assert.doesNotMatch(preview, /sess_live_demo/);
  assert.doesNotMatch(preview, /not-a-real-password/);
});

test("parses a real HAR fixture and identifies the 403", async () => {
  const text = await readFile(
    new URL("./fixtures/qa-sample.har", import.meta.url),
    "utf8",
  );
  const analysis = analyzeHar(parseHar(text), "qa-sample.har");

  assert.equal(analysis.totalRequests, 1);
  assert.equal(analysis.failedRequests, 1);
  assert.match(analysis.title, /403/);
  assert.match(analysis.suspects[0].explanation, /permission|CSRF|security rule/i);
  assert.match(analysis.suspects[0].nextStep, /permission|CSRF|WAF|policy/i);
});

test("strictly allowlists exported fields and strips adversarial secrets everywhere", () => {
  const raw = {
    log: {
      version: "1.2",
      creator: { name: "Browser", version: "1", _vendorSecret: "creator-leak" },
      pages: [
        {
          id: "page-private",
          title: "alex@example.com private dashboard",
          startedDateTime: "2026-07-27T08:00:00.000Z",
          _vendorSecret: "page-leak",
        },
      ],
      entries: [
        {
          ...entry(
            "https://alex:password@example.com/users/alex%40example.com/550e8400-e29b-41d4-a716-446655440000?token=path-query-secret",
            500,
          ),
          serverIPAddress: "fd00::1234",
          _vendorSecret: "entry-leak",
          request: {
            method: "POST",
            url: "https://alex:password@example.com/users/alex%40example.com/550e8400-e29b-41d4-a716-446655440000?token=path-query-secret",
            headers: [
              { name: "X-Token", value: "opaque-token-value", _vendorSecret: "header-leak" },
              { name: "X-Customer-Reference", value: "unknown-header-secret" },
            ],
            cookies: [{ name: "theme", value: "still-private" }],
            queryString: [{ name: "token", value: "path-query-secret" }],
            postData: {
              mimeType: "application/octet-stream",
              text: "YWxleEBleGFtcGxlLmNvbTpzdXBlcnNlY3JldA==",
              params: [
                {
                  name: "upload",
                  value: "private-file-body",
                  fileName: "alex-tax-return.pdf",
                },
              ],
            },
          },
          response: {
            status: 500,
            statusText: "SQL failed for alex@example.com",
            headers: [],
            cookies: [{ name: "theme", value: "response-private" }],
            content: {
              size: 40,
              mimeType: "application/json",
              text: "YWxleEBleGFtcGxlLmNvbTpzdXBlcnNlY3JldA==",
              encoding: "base64",
              _vendorSecret: "content-leak",
            },
            bodySize: 40,
          },
        },
      ],
      _vendorSecret: "log-leak",
    },
  } as unknown as HarFile;

  const analysis = analyzeHar(raw, "capture-alex@example.com.har");
  const output = JSON.stringify({
    sanitized: analysis.sanitized,
    markdown: analysis.markdown,
    aiPrompt: analysis.aiPrompt,
  });

  for (const secret of [
    "alex@example.com",
    "password",
    "path-query-secret",
    "opaque-token-value",
    "unknown-header-secret",
    "still-private",
    "private-file-body",
    "alex-tax-return.pdf",
    "YWxleEBleGFtcGxlLmNvbTpzdXBlcnNlY3JldA==",
    "fd00::1234",
    "SQL failed",
    "creator-leak",
    "page-leak",
    "entry-leak",
    "header-leak",
    "content-leak",
  ]) {
    assert.doesNotMatch(output, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  }
  assert.match(output, /\[REDACTED_BODY\]/);
  assert.match(output, /redacted-path-value/);
  assert.match(analysis.aiPrompt, /untrusted captured data/i);
  assert.match(analysis.markdown, /same sanitized evidence model/i);
});

test("redacts private IPv6 hosts and unsupported URL schemes", () => {
  const clean = sanitizeHar(
    har([
      entry("http://[fd00::1234]/private", 200),
      entry("data:text/plain,opaque-secret-value", 200),
    ]),
  );
  const output = JSON.stringify(clean);
  assert.doesNotMatch(output, /fd00::1234|opaque-secret-value/);
  assert.match(output, /private-host\.invalid/);
  assert.match(output, /\[REDACTED_UNSUPPORTED_URL\]/);
});

test("rejects malformed nested HAR structures with controlled messages", () => {
  assert.throws(
    () => parseHar('{"log":{"entries":[null]}}'),
    /HAR entry 1 must be an object/,
  );
  assert.throws(
    () =>
      parseHar(
        '{"log":{"entries":[{"request":{"headers":"not-an-array"},"response":{}}]}}',
      ),
    /request\.headers must be an array/,
  );
});

test("rejects traces above the request-count safety bound", () => {
  const entries = Array.from({ length: 50_001 }, () => ({}));
  assert.throws(
    () => parseHar(JSON.stringify({ log: { entries } })),
    /safe limit is 50(?:[,\s\u00a0\u202f]?000)/,
  );
});

test("does not double-count a token represented in URL and queryString", () => {
  const analysis = analyzeHar(
    har([
      {
        ...entry("https://example.com/api?token=one-secret-value", 200),
        request: {
          method: "GET",
          url: "https://example.com/api?token=one-secret-value",
          queryString: [{ name: "token", value: "one-secret-value" }],
          headers: [],
        },
      },
    ]),
    "query.har",
  );
  const token = analysis.findings.find((finding) => finding.kind === "token");
  assert.equal(token?.count, 1);
});

test("uses evidence volume before assigning high confidence", () => {
  const single = analyzeHar(har([entry("https://api.example.com/orders/12345", 500)]), "one.har");
  assert.equal(single.suspects[0].confidence, "medium");

  const repeated = analyzeHar(
    har([
      entry("https://api.example.com/orders/12345", 500),
      entry("https://api.example.com/orders/67890", 500),
      entry("https://api.example.com/orders/99999", 500),
    ]),
    "three.har",
  );
  assert.equal(repeated.suspects[0].confidence, "high");
  assert.match(repeated.suspects[0].evidence.join(" "), /3 matching failed requests/i);
});
