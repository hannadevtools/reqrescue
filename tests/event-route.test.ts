import assert from "node:assert/strict";
import test from "node:test";
import { POST } from "../app/api/event/route";

function request(
  body: string,
  origin = "https://app.reqrescue.workers.dev",
): Request {
  return new Request("https://app.reqrescue.workers.dev/api/event", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin,
    },
    body,
  });
}

test("accepts an allowlisted same-origin event", async () => {
  const originalLog = console.log;
  console.log = () => {};
  try {
    const response = await POST(
      request(
        JSON.stringify({
          event: "analysis_cancelled",
          session: "test-session",
          detail: "local",
        }),
      ),
    );
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("cache-control"), "no-store");
  } finally {
    console.log = originalLog;
  }
});

test("rejects unknown, cross-origin, and oversized event requests", async () => {
  assert.equal(
    (await POST(request('{"event":"arbitrary-event"}'))).status,
    400,
  );
  assert.equal(
    (
      await POST(
        request('{"event":"page_view"}', "https://attacker.example"),
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await POST(
        new Request("https://app.reqrescue.workers.dev/api/event", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: '{"event":"page_view"}',
        }),
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await POST(
        request(
          JSON.stringify({
            event: "feedback_note",
            detail: "x".repeat(3_000),
          }),
        ),
      )
    ).status,
    413,
  );
});

test("accepts the public proxy origin when the route runs on the Sites origin", async () => {
  const originalLog = console.log;
  console.log = () => {};
  try {
    const response = await POST(
      new Request("https://reqrescue.funt1k.chatgpt.site/api/event", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "https://app.reqrescue.workers.dev",
        },
        body: JSON.stringify({
          event: "page_view",
          session: "proxy-test-session",
        }),
      }),
    );
    assert.equal(response.status, 204);
  } finally {
    console.log = originalLog;
  }
});
