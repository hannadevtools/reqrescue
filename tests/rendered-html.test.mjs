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
    /<title>ReqRescue — Free local HAR analyzer, sanitizer &amp; incident brief<\/title>/i,
  );
  assert.match(html, /Stop sending raw traces/);
  assert.match(html, /Drop a HAR\. Get the case\./);
  assert.match(html, /Nothing is uploaded/);
  assert.match(html, /Run a 15-second demo — no HAR needed/);
  assert.match(html, /Get Pro · \$12/);
  assert.match(html, /Get lifetime Pro · \$12/);
  assert.match(html, /One payment\. No ReqRescue account/);
  assert.match(html, /github\.com\/hannadevtools\/reqrescue/);
  assert.match(html, /https:\/\/app\.reqrescue\.workers\.dev\//);
  assert.match(html, /class="mobile-menu"/);
  assert.match(html, /application\/ld\+json/);
  assert.match(html, /How is this different from a HAR viewer or sanitizer/);
  assert.doesNotMatch(html, /react-loading-skeleton|Your site is taking shape/);
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
});

test("returns a controlled response for an unknown route", async () => {
  const response = await render("/missing-page");
  assert.equal(response.status, 404);
});
