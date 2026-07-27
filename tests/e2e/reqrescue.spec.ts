import { readFile } from "node:fs/promises";
import { expect, type Page, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.on("console", (message) => {
    if (message.type() === "error") console.error(`Browser console: ${message.text()}`);
  });
  page.on("pageerror", (error) => console.error(`Browser page error: ${error.message}`));
});

async function openApp(page: Page) {
  await page.goto("/");
  await page.waitForFunction(
    () => document.documentElement.dataset.reqrescueReady === "true",
  );
}

test("runs the synthetic demo and exposes only evidence-based results", async ({
  page,
}) => {
  await openApp(page);
  await page.getByRole("button", { name: /Run a 15-second demo/i }).click();

  await expect(
    page.getByRole("heading", { name: /Network failure:/i }),
  ).toBeVisible();
  await expect(page.getByText("medium evidence confidence").first()).toBeVisible();
  await expect(page.getByText("Recommended next check").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Download clean HAR" })).toBeVisible();
  await expect(page.getByText("proof of a server-side root cause")).toBeVisible();
});

test("accepts a HAR file, previews sanitized data, and exports safe files", async ({
  page,
}) => {
  await openApp(page);
  await page.locator('input[type="file"]').setInputFiles("tests/fixtures/qa-sample.har");

  await expect(
    page.getByRole("heading", { name: /Network failure: 403/i }),
  ).toBeVisible();
  await page.getByText("Preview sanitized data").click();
  await expect(page.locator(".sanitized-preview pre")).toContainText("[REDACTED");

  const harDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download clean HAR" }).click();
  const harDownload = await harDownloadPromise;
  expect(harDownload.suggestedFilename()).toMatch(/-sanitized\.har$/);

  const reportDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download report" }).click();
  const reportDownload = await reportDownloadPromise;
  expect(reportDownload.suggestedFilename()).toMatch(/-incident\.md$/);
  const reportPath = await reportDownload.path();
  expect(reportPath).not.toBeNull();
  const reportText = await readFile(reportPath!, "utf8");
  expect(reportText).toContain("Recommended next check");
  expect(reportText).toContain(
    "[ReqRescue](https://app.reqrescue.workers.dev)",
  );
  expect(reportText).toContain("0 HAR bytes uploaded");
});

test("keeps adversarial values out of the report and sanitized preview", async ({
  page,
}) => {
  const secret = "never-leak-alex@example.com";
  const trace = {
    log: {
      version: "1.2",
      pages: [{ id: "secret-page", title: secret }],
      entries: [
        {
          startedDateTime: "2026-07-27T08:00:00.000Z",
          time: 180,
          request: {
            method: "POST",
            url: `https://user:password@example.com/user/${encodeURIComponent(secret)}?token=private-token`,
            headers: [{ name: "X-Token", value: "opaque-secret" }],
            postData: { mimeType: "text/plain", text: secret },
          },
          response: {
            status: 500,
            statusText: secret,
            headers: [],
            content: { size: 20, mimeType: "text/plain", text: secret },
          },
        },
      ],
    },
  };

  await openApp(page);
  await page.locator('input[type="file"]').setInputFiles({
    name: `capture-${secret}.har`,
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(trace)),
  });
  await expect(
    page.getByRole("heading", { name: /Network failure: 500/i }),
  ).toBeVisible();
  await page.getByText("Preview sanitized data").click();
  await expect(page.locator("body")).not.toContainText(secret);
  await expect(page.locator(".sanitized-preview pre")).not.toContainText("opaque-secret");
  await expect(page.locator(".sanitized-preview pre")).toContainText("[REDACTED_BODY]");
});

test("shows controlled errors and lets the same file be selected again", async ({
  page,
}) => {
  await openApp(page);
  const input = page.locator('input[type="file"]');
  const invalid = {
    name: "broken.har",
    mimeType: "application/json",
    buffer: Buffer.from('{"log":{"entries":[null]}}'),
  };
  await input.setInputFiles(invalid);
  await expect(page.getByRole("alert")).toContainText(
    "HAR entry 1 must be an object",
  );
  await input.setInputFiles(invalid);
  await expect(page.getByRole("alert")).toContainText(
    "HAR entry 1 must be an object",
  );
});

test("traps and restores focus in the honorware dialog", async ({ page }) => {
  await openApp(page);
  const opener = page.getByRole("button", { name: "Support · $12" });
  await opener.click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("button", { name: "Close" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
  await expect(opener).toBeFocused();
});

test("has no horizontal overflow on a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await openApp(page);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
  ).toBe(true);
  await page.getByRole("button", { name: /Run a 15-second demo/i }).click();
  await expect(page.getByRole("heading", { name: /Network failure:/i })).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
  ).toBe(true);
});
