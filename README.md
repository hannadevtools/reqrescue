# ReqRescue

ReqRescue turns a browser HAR into an actionable incident packet:

- ranked failure suspects with confidence and cited evidence;
- a sanitized HAR with common credentials and PII removed;
- a Markdown bug report and AI-debugger handoff;
- an optional print-ready PDF workflow and local case history.

Try the hosted build: **[app.reqrescue.workers.dev](https://app.reqrescue.workers.dev/)**

## What is a HAR?

A HAR (HTTP Archive) is a standard JSON recording of the network requests a
browser made while a page loaded or a problem was reproduced. Support, QA, and
engineering teams use it to inspect failed API calls, slow requests, redirects,
and response status codes.

In Chrome or Edge, open **Developer Tools → Network**, reproduce the issue, and
choose **Export HAR**. In Firefox, use **Developer Tools → Network → Save all as
HAR**.

## Why this exists

HAR sanitizers remove risk. HAR viewers expose rows. ReqRescue does both of
those jobs and then performs a deterministic first triage pass: it groups
failures, ranks plausible causes, cites the requests behind every hypothesis,
and produces a handoff an engineer can verify.

It does not claim to prove a server-side root cause without server logs.

## Privacy you can verify

HAR parsing, ranking, redaction, and export generation run in the browser:

- [`app/trace-engine.ts`](app/trace-engine.ts) contains the parser, heuristics,
  redaction, and report generation.
- [`app/page.tsx`](app/page.tsx) reads files with the browser `File` API and
  passes their text directly to that engine. It also renders a small preview of
  the sanitized copy before export.
- [`app/api/event/route.ts`](app/api/event/route.ts) accepts only an anonymous
  event name, session identifier, and short acquisition detail.

The hosted build never sends HAR contents, file names, URLs, headers, bodies,
or generated reports to ReqRescue. Gumroad license activation, when used, sends
only the license key to Gumroad.

Automated redaction cannot recognize every product-specific secret. Review a
sanitized export before sharing it.

## Free and Pro

The analyzer, sanitizer, clean HAR export, Markdown incident report, and source
code are free under the MIT license.

The hosted build offers a voluntary **$12 one-time Pro unlock** for convenience:

- print or save the complete incident brief as PDF;
- analyze local HAR files up to 250 MB, subject to device memory;
- keep up to 10 incident briefs in this browser's local storage.

There is no ReqRescue account and no subscription. Because the source is open,
the license gate is intentionally lightweight; the purchase supports the hosted
build and future maintenance.

## Development

Requirements: Node.js 22.13 or later.

```bash
npm ci
npm run dev
```

## Verification

```bash
npm test
npx tsc --project tsconfig.app.json --noEmit
```

Tests cover server rendering, deterministic suspect ranking, real HAR parsing,
and removal of representative tokens, sessions, passwords, email addresses,
API keys, and IP addresses.

## Responsible disclosure

Do not open a public issue containing a real HAR, token, cookie, or private
endpoint. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
