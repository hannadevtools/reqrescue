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
    /<title>ReqRescue — Turn a HAR into an actionable incident brief<\/title>/i,
  );
  assert.match(html, /Stop sending raw traces/);
  assert.match(html, /Drop a HAR\. Get the case\./);
  assert.match(html, /Nothing is uploaded/);
  assert.match(html, /Try the broken checkout demo/);
  assert.doesNotMatch(html, /react-loading-skeleton|Your site is taking shape/);
});

test("returns a controlled response for an unknown route", async () => {
  const response = await render("/missing-page");
  assert.equal(response.status, 404);
});
