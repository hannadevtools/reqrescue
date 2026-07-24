import { NextResponse } from "next/server";

const ALLOWED_EVENTS = new Set([
  "page_view",
  "analysis_complete",
  "analysis_error",
  "copy_report",
  "copy_ai_prompt",
  "export_sanitized_har",
  "export_markdown",
  "report_helpful",
  "feedback_note",
  "pro_checkout_click",
  "pro_activation_success",
  "pro_activation_error",
  "pro_pdf_print",
  "pro_case_saved",
  "pro_history_copy",
]);

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as {
      event?: unknown;
      session?: unknown;
      detail?: unknown;
    };
    const event =
      typeof body.event === "string" && ALLOWED_EVENTS.has(body.event)
        ? body.event
        : "unknown";
    const session =
      typeof body.session === "string"
        ? body.session.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 48)
        : "anonymous";
    const detail =
      typeof body.detail === "string"
        ? body.detail.replace(/[\r\n\t]/g, " ").slice(0, 60)
        : "";

    console.log(
      JSON.stringify({
        type: "reqrescue_event",
        event,
        session,
        detail,
        at: new Date().toISOString(),
      }),
    );
    return new NextResponse(null, {
      status: 204,
      headers: {
        "cache-control": "no-store",
      },
    });
  } catch {
    return NextResponse.json({ ok: false }, { status: 400 });
  }
}
