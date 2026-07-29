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
import { compareAnalyses } from "../app/trace-compare";

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

test("detects a successful auth callback followed by a return to login", () => {
  const sentryFailure = {
    ...entry("https://errors.ingest.us.sentry.io/api/1/envelope/", 429),
    startedDateTime: "2026-07-27T08:00:00.000Z",
    request: {
      method: "POST",
      url: "https://errors.ingest.us.sentry.io/api/1/envelope/",
      headers: [],
    },
  };
  const failedCallback = {
    ...entry("https://wallet.example.com/api/login/email/callback", 401),
    startedDateTime: "2026-07-27T08:00:05.000Z",
    request: {
      method: "POST",
      url: "https://wallet.example.com/api/login/email/callback",
      headers: [],
    },
  };
  const successfulCallback = {
    ...entry("https://wallet.example.com/api/login/email/callback", 200),
    startedDateTime: "2026-07-27T08:00:10.000Z",
    request: {
      method: "POST",
      url: "https://wallet.example.com/api/login/email/callback",
      headers: [],
    },
  };
  const callbackPreflight = {
    ...entry("https://wallet.example.com/api/login/email/callback", 204),
    startedDateTime: "2026-07-27T08:00:10.001Z",
    request: {
      method: "OPTIONS",
      url: "https://wallet.example.com/api/login/email/callback",
      headers: [],
    },
  };
  const cacheValidation = {
    ...entry("https://app.example.com/app.js", 304),
    startedDateTime: "2026-07-27T08:00:11.000Z",
  };
  const websocketUpgrade = {
    ...entry("https://app.example.com/socket", 101, 60_000),
    startedDateTime: "2026-07-27T08:00:11.500Z",
  };
  const telemetryRedirects = Array.from({ length: 4 }, (_, index) => ({
    ...entry("https://googleads.g.doubleclick.net/pagead/conversion/", 302),
    startedDateTime: `2026-07-27T08:00:1${2 + index}.000Z`,
  }));
  const returnedToLogin = {
    ...entry("https://app.example.com/auth/login", 200),
    startedDateTime: "2026-07-27T08:00:22.000Z",
  };

  const analysis = analyzeHar(
    har([
      sentryFailure,
      failedCallback,
      successfulCallback,
      callbackPreflight,
      cacheValidation,
      websocketUpgrade,
      ...telemetryRedirects,
      returnedToLogin,
    ]),
    "auth-loop.har",
  );

  assert.match(analysis.suspects[0].title, /login state was not retained/i);
  assert.match(analysis.suspects[0].evidence.join(" "), /1 successful auth callback/i);
  assert.match(analysis.suspects[0].evidence.join(" "), /12(?:\.0)? s/i);
  assert.match(analysis.title, /login state was not retained/i);
  assert.equal(analysis.redirects, 4);
  assert.ok(
    analysis.suspects.every((suspect) => !/doubleclick|socket/i.test(suspect.title)),
  );
  assert.ok(
    analysis.suspects.findIndex((suspect) => /recovered 401/i.test(suspect.title)) >
      analysis.suspects.findIndex((suspect) => /login state was not retained/i.test(suspect.title)),
  );
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

test("preserves ISO timestamps while redacting IPv6 text", () => {
  const timestamp = "2026-07-29T10:45:59.780Z";
  const clean = sanitizeHar({
    log: {
      version: "1.2",
      creator: {
        name: `capture ${timestamp} from 2001:db8::1`,
        version: "1",
      },
      entries: [
        {
          ...entry("https://example.com/status", 200),
          startedDateTime: timestamp,
        },
      ],
    },
  });
  const output = JSON.stringify(clean);

  assert.match(output, new RegExp(timestamp.replace(/[.]/g, "\\.")));
  assert.doesNotMatch(output, /2001:db8::1/);
  assert.match(output, /\[REDACTED_IP\]/);
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

test("accepts a valid HAR with a UTF-8 byte-order mark", () => {
  const parsed = parseHar(
    `\uFEFF${JSON.stringify(har([entry("https://example.com/with-bom", 200)]))}`,
  );

  assert.equal(parsed.log.entries.length, 1);
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

test("extracts bounded JSON error clues while stripping the original body", () => {
  const responseBody = JSON.stringify({
    code: "BadRequest",
    statusCode: 4_111_111_111_111_111,
    message: JSON.stringify({
      code: 2105,
      description:
        'DOWNSTREAMSTATUSCODE=400 (BADREQUEST), DEPENDENCY=ONEVET, RESPONSEBODY={"MODELSTATE":{"BusinessProfile.Address.City":["CITY IS REQUIRED."],"User.privatePersonSecret":["PRIVATE"]}}',
    }),
    errorName: "BadRequest",
    isRetryable: false,
    resourceProvider: "AMSProvider:UpdateAccount",
    customerEmail: "private-person@example.com",
    diagnosticToken: "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
  });
  const failed = entry(
    "https://partner.example.com/enroll?session=private-session-value",
    400,
    10_067,
  );
  failed.request = {
    method: "POST",
    url: "https://partner.example.com/enroll?session=private-session-value",
    headers: [],
    postData: {
      mimeType: "application/json",
      text: JSON.stringify({ address: { city: "Private City" } }),
    },
  };
  failed.response = {
    ...failed.response,
    content: {
      size: responseBody.length,
      mimeType: "application/json",
      text: responseBody,
    },
  };

  const analysis = analyzeHar(har([failed]), "partner-private.har");
  const output = JSON.stringify({
    diagnosticClues: analysis.diagnosticClues,
    markdown: analysis.markdown,
    suspects: analysis.suspects,
    sanitized: analysis.sanitized,
  });

  assert.equal(analysis.diagnosticClues.length, 1);
  assert.match(output, /Error code: 2105/);
  assert.match(output, /Dependency: ONEVET/);
  assert.match(output, /Downstream HTTP 400/);
  assert.match(output, /Validation field: BusinessProfile\.Address\.City/);
  assert.match(output, /Retryable: no/);
  assert.match(output, /resourceProvider: AMSProvider:UpdateAccount/);
  assert.match(analysis.markdown, /Safely extracted error clues/);
  assert.match(output, /\[REDACTED_BODY\]/);
  assert.doesNotMatch(output, /private-person@example\.com/i);
  assert.doesNotMatch(output, /abcdefghijklmnopqrstuvwxyz1234567890/i);
  assert.doesNotMatch(output, /4111111111111111/);
  assert.doesNotMatch(output, /Private City|private-session-value/i);
  assert.doesNotMatch(output, /privatePersonSecret/i);
  assert.doesNotMatch(output, /CITY IS REQUIRED/i);
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

test("compares two HARs and ranks a missing signed query key with a new failure", () => {
  const baseline = analyzeHar(
    har([
      {
        ...entry(
          "https://uploads.example.com/singleFileUpload?tk=one&ref=signed&uuid=abc",
          200,
        ),
        request: {
          method: "POST",
          url: "https://uploads.example.com/singleFileUpload?tk=one&ref=signed&uuid=abc",
          headers: [],
        },
      },
    ]),
    "working.har",
  );
  const changed = analyzeHar(
    har([
      {
        ...entry(
          "https://uploads.example.com/singleFileUpload?tk=two&uuid=abc",
          400,
        ),
        request: {
          method: "POST",
          url: "https://uploads.example.com/singleFileUpload?tk=two&uuid=abc",
          headers: [],
        },
      },
    ]),
    "broken.har",
  );

  const comparison = compareAnalyses(baseline, changed);

  assert.equal(comparison.changes[0].kind, "query");
  assert.equal(comparison.changes[0].confidence, "high");
  assert.match(comparison.changes[0].title, /ref.*disappears/i);
  assert.match(comparison.changes[0].evidence.join(" "), /200.*400/);
  assert.match(comparison.markdown, /Capture A — baseline/);
  assert.match(comparison.markdown, /0 HAR bytes uploaded/);
  assert.doesNotMatch(comparison.markdown, /signed|tk=one|tk=two/);
});
