import { NextResponse } from "next/server";

const MAX_BODY_BYTES = 2_048;
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 60;
const GLOBAL_RATE_LIMIT = 3_000;
const recentEvents = new Map<string, number[]>();
let recentGlobalEvents: number[] = [];

const ALLOWED_EVENTS = new Set([
  "page_view",
  "analysis_complete",
  "analysis_error",
  "analysis_cancelled",
  "comparison_complete",
  "comparison_error",
  "comparison_copy_report",
  "comparison_export_markdown",
  "comparison_export_sanitized",
  "copy_report",
  "copy_ai_prompt",
  "export_sanitized_har",
  "export_markdown",
  "report_helpful",
  "feedback_note",
  "pdf_print",
  "case_saved",
  "history_copy",
  "cat_charity_click",
]);

function noStoreJson(body: unknown, status: number) {
  return NextResponse.json(body, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return (
    origin === new URL(request.url).origin ||
    origin === "https://app.reqrescue.workers.dev"
  );
}

function underRateLimit(session: string): boolean {
  const now = Date.now();
  const cutoff = now - RATE_WINDOW_MS;
  recentGlobalEvents = recentGlobalEvents.filter((time) => time > cutoff);
  if (recentGlobalEvents.length >= GLOBAL_RATE_LIMIT) return false;

  const previous = recentEvents.get(session)?.filter((time) => time > cutoff) ?? [];
  if (previous.length >= RATE_LIMIT) {
    recentEvents.set(session, previous);
    return false;
  }
  previous.push(now);
  recentGlobalEvents.push(now);
  recentEvents.set(session, previous);

  if (recentEvents.size > 2_000) {
    for (const [key, timestamps] of recentEvents) {
      if (!timestamps.some((time) => time > cutoff)) recentEvents.delete(key);
    }
  }
  return true;
}

function sanitizeDetail(value: string): string {
  return value
    .replace(/[\r\n\t]/g, " ")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]")
    .replace(
      /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
      "[REDACTED_IP]",
    )
    .replace(/\b(?:Bearer|Basic)\s+[a-zA-Z0-9._~+/=-]{8,}\b/gi, "[REDACTED_AUTH]")
    .replace(
      /\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\b/g,
      "[REDACTED_JWT]",
    )
    .replace(
      /\b(?:sk_live_[a-zA-Z0-9]{12,}|sk_test_[a-zA-Z0-9]{12,}|gh[pousr]_[a-zA-Z0-9]{20,})\b/g,
      "[REDACTED_SECRET]",
    )
    .slice(0, 220);
}

export async function POST(request: Request) {
  if (!sameOrigin(request)) return noStoreJson({ ok: false }, 403);

  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return noStoreJson({ ok: false }, 413);
  }

  try {
    const text = await request.text();
    if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) {
      return noStoreJson({ ok: false }, 413);
    }

    const body = JSON.parse(text) as {
      event?: unknown;
      session?: unknown;
      detail?: unknown;
    };
    if (typeof body.event !== "string" || !ALLOWED_EVENTS.has(body.event)) {
      return noStoreJson({ ok: false }, 400);
    }

    const session =
      typeof body.session === "string"
        ? body.session.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 48) || "anonymous"
        : "anonymous";
    if (!underRateLimit(session)) return noStoreJson({ ok: false }, 429);

    const detail =
      typeof body.detail === "string"
        ? sanitizeDetail(body.detail)
        : "";

    console.log(
      JSON.stringify({
        type: "reqrescue_event",
        event: body.event,
        session,
        detail,
        at: new Date().toISOString(),
      }),
    );
    return new NextResponse(null, {
      status: 204,
      headers: { "cache-control": "no-store" },
    });
  } catch {
    return noStoreJson({ ok: false }, 400);
  }
}
