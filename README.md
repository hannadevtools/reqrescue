# ReqRescue

ReqRescue turns a browser HAR into an actionable incident packet:

- ranked failure suspects with confidence and cited evidence;
- local A/B comparison of two HAR captures;
- a sanitized HAR with common credentials and PII removed;
- a Markdown bug report and AI-debugger handoff;
- a print-ready PDF workflow and local case history.

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
- [`app/trace-compare.ts`](app/trace-compare.ts) compares only sanitized request
  structure and produces the A/B report.
- [`app/page.tsx`](app/page.tsx) reads files with the browser `File` API and
  transfers their bytes to a dedicated browser worker. It also renders a small
  preview of the sanitized copy before export.
- [`app/api/event/route.ts`](app/api/event/route.ts) accepts only an anonymous
  event name, session identifier, and short acquisition detail.

The hosted build never sends HAR contents, file names, URLs, headers, bodies,
or generated reports to ReqRescue. It records only an allowlist of pseudonymous
product events and optional feedback.

Automated redaction cannot recognize every product-specific secret. Review a
sanitized export before sharing it.

## Free, with no payment to ReqRescue

The analyzer, A/B comparison, sanitizer, clean HAR export, Markdown incident
report, PDF printing, 75 MB per-file local limit, on-device history, and source
code are free under the MIT license.

ReqRescue has no account, subscription, paywall, license key, or donation
checkout. The hosted site instead links directly to two independent Israeli
animal organizations. ReqRescue is not affiliated with them and receives
nothing.

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

Tests cover server rendering, local browser-worker uploads, exports,
accessibility interactions, deterministic suspect ranking, A/B comparison,
malformed HARs, event API boundaries, and adversarial removal of
credentials, bodies, vendor fields, tokens, sessions, passwords, email
addresses, API keys, private hosts, and IP addresses. In CI, `npm test`
installs the pinned Playwright Chromium runtime before running browser tests.

## Responsible disclosure

Do not open a public issue containing a real HAR, token, cookie, or private
endpoint. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
