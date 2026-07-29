import assert from "node:assert/strict";
import test from "node:test";

async function render(path = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`http://localhost${path}`, {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the ReqRescue product shell", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(
    html,
    /<title>ReqRescue — Turn browser failures into safe bug reports<\/title>/i,
  );
  assert.match(html, /A website broke/);
  assert.match(html, /Send (?:<em>)?evidence, not guesswork/);
  assert.match(html, /Drop the browser recording \(HAR\)/);
  assert.match(html, /Nothing is uploaded/);
  assert.match(html, /Run a 15-second demo — no HAR needed/);
  assert.match(html, /Need a HAR\? Export one in 3 steps/);
  assert.match(html, /Compare two HARs \(A\/B\)/);
  assert.match(html, /ReqRescue, in plain English/);
  assert.match(html, /Support, QA, developers, and technical founders/);
  assert.match(html, /Saved an hour\? Help a cat instead/);
  assert.match(html, /Israel Cat Lovers/);
  assert.match(html, /S\.O\.S Pets Israel/);
  assert.match(html, /No paywall, license key, account, subscription/);
  assert.doesNotMatch(html, /Gumroad|Support ReqRescue · \$12|honorware/i);
  assert.match(html, /github\.com\/hannadevtools\/reqrescue/);
  assert.match(
    html,
    /<link rel="canonical" href="https:\/\/app\.reqrescue\.workers\.dev\/"\/?>/,
  );
  assert.match(html, /class="mobile-menu"/);
  assert.match(html, /type="application\/ld\+json"/);
  assert.match(html, /"@type":\["SoftwareApplication","WebApplication"\]/);
  assert.match(html, /"isAccessibleForFree":true/);
  assert.match(html, /github\.com\/hannadevtools\/reqrescue/);
  assert.match(html, /How is this different from a HAR viewer or sanitizer/);
  assert.doesNotMatch(html, /react-loading-skeleton|Your site is taking shape/);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
});

test("serves crawler discovery files", async () => {
  const robots = await render("/robots.txt");
  assert.equal(robots.status, 200);
  assert.match(robots.headers.get("content-type") ?? "", /^text\/plain\b/i);
  assert.match(await robots.text(), /Sitemap: .*\/sitemap\.xml/);

  const sitemap = await render("/sitemap.xml");
  assert.equal(sitemap.status, 200);
  assert.match(sitemap.headers.get("content-type") ?? "", /^application\/xml\b/i);
  assert.match(
    await sitemap.text(),
    /<loc>https:\/\/app\.reqrescue\.workers\.dev\/<\/loc>/,
  );
  assert.match(await (await render("/privacy")).text(), /Your HAR stays in your browser/);
  assert.match(await (await render("/terms")).text(), /Use the evidence\. Verify the conclusion/);
});

test("returns a controlled response for an unknown route", async () => {
  const response = await render("/missing-page");
  assert.equal(response.status, 404);
});
