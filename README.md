# ReqRescue

ReqRescue turns a browser HAR into an actionable incident packet:

- ranked failure suspects with confidence and cited evidence;
- a sanitized HAR with common credentials and PII removed;
- a Markdown bug report;
- a compact handoff prompt for an AI debugger.

The HAR is parsed and transformed entirely in the browser. The server receives
only anonymous product events such as `page_view`, `analysis_complete`, and
`export_sanitized_har`; it never receives HAR contents, URLs, headers, bodies,
or file names.

## Development

```bash
npm ci
npm run dev
```

## Verification

```bash
npm test
npx tsc --project tsconfig.app.json --noEmit
```

The tests cover server rendering, deterministic suspect ranking, real HAR
parsing, and removal of representative tokens, sessions, passwords, email
addresses, API keys, and IP addresses.

## Current commercial path

The browser utility stays free. Planned paid capabilities are a CLI, reusable
team redaction policies, and support-desk intake integrations.
