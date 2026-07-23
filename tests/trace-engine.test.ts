import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  analyzeHar,
  buildDemoHar,
  parseHar,
  sanitizeHar,
} from "../app/trace-engine";

test("ranks the repeated auth failure above an unrelated telemetry failure", () => {
  const analysis = analyzeHar(buildDemoHar(), "demo.har");

  assert.equal(analysis.totalRequests, 7);
  assert.equal(analysis.failedRequests, 4);
  assert.match(analysis.suspects[0].title, /401 failure.*checkout/i);
  assert.equal(analysis.suspects[0].confidence, "high");
  assert.match(analysis.markdown, /Ranked suspects/);
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

test("parses a real HAR fixture and identifies the 403", async () => {
  const text = await readFile(
    new URL("../work/qa-sample.har", import.meta.url),
    "utf8",
  );
  const analysis = analyzeHar(parseHar(text), "qa-sample.har");

  assert.equal(analysis.totalRequests, 1);
  assert.equal(analysis.failedRequests, 1);
  assert.match(analysis.title, /403/);
  assert.match(analysis.suspects[0].explanation, /permission|CSRF|security rule/i);
});
