"use client";

import {
  type Analysis,
  analyzeHar,
  buildDemoHar,
  formatBytes,
  formatDuration,
  parseHar,
} from "./trace-engine";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type View = "landing" | "report";
type RequestFilter = "failures" | "slow" | "all";

const MAX_FILE_BYTES = 80 * 1024 * 1024;
const TEAM_PILOT_MAILTO =
  "mailto:devhanna661@gmail.com?subject=ReqRescue%20founding%20team%20pilot&body=Team%20or%20product%3A%0AApprox.%20HARs%20per%20month%3A%0AWhere%20the%20handoff%20happens%20today%3A%0A";

function track(event: string, detail?: string) {
  try {
    const storageKey = "reqrescue-session";
    const session =
      localStorage.getItem(storageKey) ??
      (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);
    localStorage.setItem(storageKey, session);
    void fetch("/api/event", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        event,
        session,
        detail: detail?.slice(0, 60),
      }),
      keepalive: true,
    });
  } catch {
    // Analytics must never block the local-first tool.
  }
}

function acquisitionSource() {
  const params = new URLSearchParams(window.location.search);
  const source = params.get("utm_source");
  const medium = params.get("utm_medium");
  if (source) {
    return [source, medium].filter(Boolean).join("/");
  }

  try {
    const referrer = document.referrer ? new URL(document.referrer).hostname : "";
    return referrer || "direct";
  } catch {
    return "direct";
  }
}

function downloadText(name: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function safeBaseName(name: string) {
  return (
    name
      .replace(/\.(har|json)$/i, "")
      .replace(/[^a-z0-9-_]+/gi, "-")
      .replace(/^-+|-+$/g, "")
      .toLowerCase() || "network-trace"
  );
}

function Logo() {
  return (
    <a className="brand" href="#" aria-label="ReqRescue home">
      <span className="brand-mark" aria-hidden="true">
        R<span>R</span>
      </span>
      <span>ReqRescue</span>
    </a>
  );
}

function Header({ report }: { report: boolean }) {
  const links = report
    ? [
        ["Evidence", "#evidence"],
        ["Handoff", "#handoff"],
        ["Feedback", "#feedback"],
      ]
    : [
        ["How it works", "#how-it-works"],
        ["Privacy", "#privacy"],
        ["FAQ", "#faq"],
        ["For teams", "#roadmap"],
      ];

  return (
    <header className="site-header">
      <Logo />
      <nav aria-label="Primary navigation">
        {links.map(([label, href]) => (
          <a href={href} key={href}>
            {label}
          </a>
        ))}
      </nav>
      <details className="mobile-menu">
        <summary>Menu</summary>
        <div>
          {links.map(([label, href]) => (
            <a href={href} key={href}>
              {label}
            </a>
          ))}
        </div>
      </details>
      <a
        className="github-link"
        href={TEAM_PILOT_MAILTO}
        onClick={() => track("team_pilot_click", "header")}
      >
        Founding pilot · $19/mo <span aria-hidden="true">↗</span>
      </a>
    </header>
  );
}

function LoadingMark() {
  return (
    <span className="loading-mark" aria-hidden="true">
      <i />
      <i />
      <i />
    </span>
  );
}

function UploadPanel({
  busy,
  error,
  onFile,
  onDemo,
}: {
  busy: boolean;
  error: string;
  onFile: (file: File) => void;
  onDemo: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const acceptFile = (file?: File) => {
    if (file) onFile(file);
  };

  return (
    <div
      className={`upload-panel ${dragging ? "is-dragging" : ""}`}
      onDragEnter={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragOver={(event) => event.preventDefault()}
      onDragLeave={(event) => {
        if (event.currentTarget === event.target) setDragging(false);
      }}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        acceptFile(event.dataTransfer.files[0]);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".har,.json,application/json"
        hidden
        onChange={(event) => acceptFile(event.target.files?.[0])}
      />
      <div className="drop-symbol" aria-hidden="true">
        <span>HAR</span>
        <i />
      </div>
      <h2>{busy ? "Reading the trace…" : "Drop a HAR. Get the case."}</h2>
      <p>
        Nothing is uploaded. Your browser performs the entire analysis and
        redaction locally.
      </p>
      <div className="upload-actions">
        <button className="button button-demo" disabled={busy} onClick={onDemo}>
          Run a 15-second demo — no HAR needed
        </button>
        <button
          className="button button-outline"
          disabled={busy}
          onClick={() => inputRef.current?.click()}
        >
          {busy ? (
            <>
              <LoadingMark /> Inspecting
            </>
          ) : (
            "Choose HAR file"
          )}
        </button>
      </div>
      <p className="file-note">Chrome, Firefox, Edge, Safari · up to 80 MB</p>
      {error && (
        <div className="upload-error" role="alert">
          <b>Couldn’t inspect that file.</b> {error}
        </div>
      )}
    </div>
  );
}

function Hero({
  busy,
  error,
  onFile,
  onDemo,
}: {
  busy: boolean;
  error: string;
  onFile: (file: File) => void;
  onDemo: () => void;
}) {
  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">
            <span>Free HAR analyzer + sanitizer</span>
            <i />
          </p>
          <h1>
            Stop sending raw traces.
            <br />
            Send <em>the case.</em>
          </h1>
          <p className="hero-lede">
            ReqRescue turns a browser HAR into a ranked incident brief, a
            scrubbed evidence file, and a bug report your engineer can act on—
            without uploading the trace.
          </p>
          <div className="proof-strip">
            <div>
              <strong>0</strong>
              <span>bytes uploaded</span>
            </div>
            <div>
              <strong>&lt; 10s</strong>
              <span>to first diagnosis</span>
            </div>
            <div>
              <strong>3</strong>
              <span>export formats</span>
            </div>
          </div>
        </div>
        <UploadPanel busy={busy} error={error} onFile={onFile} onDemo={onDemo} />
      </section>

      <section className="signal-band" aria-label="Product outcomes">
        <span>AUTH FAILURES</span>
        <i />
        <span>TIMEOUTS</span>
        <i />
        <span>REDIRECT LOOPS</span>
        <i />
        <span>LEAKED SECRETS</span>
        <i />
        <span>SLOW REQUESTS</span>
      </section>
    </>
  );
}

function HowItWorks() {
  return (
    <section className="section method-section" id="how-it-works">
      <div className="section-kicker">
        <span>01</span>
        <p>The support ritual, compressed</p>
      </div>
      <div className="method-grid">
        <div className="method-intro">
          <h2>
            Sanitizing is step one.
            <br />
            Explaining is step two.
          </h2>
          <p>
            A viewer hands you hundreds of rows. A sanitizer removes risk.
            ReqRescue does both, then performs the first triage pass an
            experienced support engineer would do—and shows its work.
          </p>
        </div>
        <div className="method-list" id="method">
          <article>
            <span>01</span>
            <div>
              <h3>Reconstruct the failure</h3>
              <p>
                Group repeated failures, trace status patterns, isolate slow-tail
                requests, and flag redirect churn.
              </p>
            </div>
          </article>
          <article>
            <span>02</span>
            <div>
              <h3>Separate fact from hypothesis</h3>
              <p>
                Every suspect carries a confidence level and the exact requests
                that support it. No invented root cause.
              </p>
            </div>
          </article>
          <article>
            <span>03</span>
            <div>
              <h3>Make the evidence shareable</h3>
              <p>
                Strip cookies, auth headers, tokens, passwords, emails, IPs,
                private hosts, and sensitive body fields.
              </p>
            </div>
          </article>
        </div>
      </div>
    </section>
  );
}

function BeforeAfter() {
  return (
    <section className="section before-after">
      <div className="section-kicker">
        <span>02</span>
        <p>What changes</p>
      </div>
      <div className="comparison">
        <article className="before-card">
          <header>
            <span>Before</span>
            <small>checkout.har · 18.4 MB</small>
          </header>
          <pre>
            <code>
              {`POST /v1/checkout   401   462ms
Authorization: Bearer eyJhbGc…
Cookie: session=sess_live_9f8…

POST /v1/auth/refresh  401  390ms
Set-Cookie: refresh=rf_2ba…

… 184 more requests`}
            </code>
          </pre>
          <p>Risky to share. Slow to understand.</p>
        </article>
        <div className="comparison-arrow" aria-hidden="true">
          <span>→</span>
        </div>
        <article className="after-card">
          <header>
            <span>After</span>
            <small>ReqRescue case #local</small>
          </header>
          <div className="mini-verdict">
            <b>Likely auth refresh failure</b>
            <span>High confidence</span>
          </div>
          <ul>
            <li>3 matching 401 responses</li>
            <li>First failure: POST /v1/checkout</li>
            <li>Session + 12 secrets redacted</li>
          </ul>
          <p>Ready for Jira, GitHub, Slack, or an AI debugger.</p>
        </article>
      </div>
    </section>
  );
}

function Privacy() {
  return (
    <section className="privacy-section" id="privacy">
      <div>
        <p className="eyebrow light">
          <span>Privacy architecture</span>
          <i />
        </p>
        <h2>Your trace never takes a network trip.</h2>
      </div>
      <div className="privacy-copy">
        <p>
          Parsing, triage, and file generation run in this tab. We record only
          anonymous product events such as “demo analyzed” or “report exported”—
          never file names, URLs, headers, bodies, or HAR contents.
        </p>
        <div className="privacy-flow" aria-label="Data flow">
          <span>Your HAR</span>
          <b>→</b>
          <span>Your browser</span>
          <b>→</b>
          <span>Your exports</span>
        </div>
      </div>
    </section>
  );
}

function Faq() {
  const questions = [
    {
      question: "Does ReqRescue upload my HAR file?",
      answer:
        "No. Parsing, ranking, redaction, and export generation happen in your browser tab. The server never receives the HAR, its file name, request URLs, headers, or bodies.",
    },
    {
      question: "What sensitive data does it remove?",
      answer:
        "ReqRescue strips cookies, authorization headers, API keys, access and refresh tokens, passwords, emails, IP addresses, private hosts, and sensitive request or response body fields. You should still review any exported evidence before sharing it.",
    },
    {
      question: "How is this different from a HAR viewer or sanitizer?",
      answer:
        "A viewer helps you inspect requests. A sanitizer removes secrets. ReqRescue also groups failures, ranks evidence-backed suspects, and produces a Markdown incident report plus a clean HAR for engineering or support.",
    },
    {
      question: "Does it claim to know the root cause?",
      answer:
        "No. ReqRescue separates observed facts from hypotheses. Each suspect has a confidence level and the exact requests that support it, so an engineer can verify the diagnosis instead of trusting a black box.",
    },
    {
      question: "Can I try it without a real trace?",
      answer:
        "Yes. Run the 15-second broken-checkout demo above. It uses a synthetic HAR with repeated authentication failures and fake secrets, so you can inspect the complete report safely.",
    },
  ];

  return (
    <section className="section faq-section" id="faq">
      <div className="section-kicker">
        <span>03</span>
        <p>Trust, before upload</p>
      </div>
      <div className="faq-grid">
        <div>
          <h2>
            The questions a sensitive
            <br />
            trace deserves.
          </h2>
          <p>
            ReqRescue is deliberately local, deterministic, and explicit about
            uncertainty. No account is required.
          </p>
        </div>
        <div className="faq-list">
          {questions.map((item, index) => (
            <details key={item.question} open={index === 0}>
              <summary>{item.question}</summary>
              <p>{item.answer}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}

function Roadmap({ onDemo }: { onDemo: () => void }) {
  return (
    <section className="section roadmap" id="roadmap">
      <div className="roadmap-copy">
        <p className="eyebrow">
          <span>Founding team pilot · 5 spots</span>
          <i />
        </p>
        <h2>The missing layer between HAR export and support escalation.</h2>
        <p>
          The web tool stays free. The paid path is a CLI, company redaction
          policies, and one-click intake for support desks—not a subscription
          wall around the basic rescue.
        </p>
        <div className="roadmap-actions">
          <a
            className="button button-primary"
            href={TEAM_PILOT_MAILTO}
            onClick={() => track("team_pilot_click", "landing")}
          >
            Request a 2-week pilot
          </a>
          <button className="button button-outline" onClick={onDemo}>
            Open the demo case
          </button>
        </div>
        <small className="pilot-fineprint">
          No card today. Keep it after the pilot for $19/month, or walk away.
        </small>
      </div>
      <div className="pilot-offer">
        <header>
          <span>Founding price</span>
          <strong>$19<small>/month</small></strong>
        </header>
        <p>We build the workflow around one real support queue with you.</p>
        <ul>
          <li>Custom secrets and redaction rules</li>
          <li>Repeatable CLI or batch workflow</li>
          <li>Jira, GitHub, or support-desk handoff template</li>
          <li>Direct fixes during the two-week pilot</li>
        </ul>
        <small>Five teams only while the workflow is still founder-led.</small>
      </div>
    </section>
  );
}

function Landing({
  busy,
  error,
  onFile,
  onDemo,
}: {
  busy: boolean;
  error: string;
  onFile: (file: File) => void;
  onDemo: () => void;
}) {
  const structuredData = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "SoftwareApplication",
        name: "ReqRescue",
        applicationCategory: "DeveloperApplication",
        operatingSystem: "Any modern web browser",
        url: "https://reqrescue.funt1k.chatgpt.site/",
        description:
          "A free local-first HAR analyzer and sanitizer that creates ranked incident briefs, clean evidence files, and developer-ready bug reports.",
        offers: {
          "@type": "Offer",
          price: "0",
          priceCurrency: "USD",
        },
        featureList: [
          "Local HAR analysis",
          "Sensitive data redaction",
          "Evidence-backed failure ranking",
          "Sanitized HAR export",
          "Markdown incident report",
        ],
      },
      {
        "@type": "FAQPage",
        mainEntity: [
          {
            "@type": "Question",
            name: "Does ReqRescue upload my HAR file?",
            acceptedAnswer: {
              "@type": "Answer",
              text: "No. Parsing, ranking, redaction, and exports run locally in the browser.",
            },
          },
          {
            "@type": "Question",
            name: "How is ReqRescue different from a HAR viewer or sanitizer?",
            acceptedAnswer: {
              "@type": "Answer",
              text: "ReqRescue sanitizes the trace, ranks evidence-backed suspects, and generates a developer-ready incident report.",
            },
          },
        ],
      },
    ],
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
      />
      <Header report={false} />
      <main>
        <Hero busy={busy} error={error} onFile={onFile} onDemo={onDemo} />
        <HowItWorks />
        <BeforeAfter />
        <Privacy />
        <Faq />
        <Roadmap onDemo={onDemo} />
      </main>
      <Footer />
    </>
  );
}

function Metric({
  value,
  label,
  accent,
}: {
  value: string;
  label: string;
  accent?: "danger" | "safe";
}) {
  return (
    <div className={`metric ${accent ? `metric-${accent}` : ""}`}>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function Confidence({ value }: { value: "high" | "medium" | "low" }) {
  return <span className={`confidence confidence-${value}`}>{value} confidence</span>;
}

function Report({
  analysis,
  onReset,
}: {
  analysis: Analysis;
  onReset: () => void;
}) {
  const [filter, setFilter] = useState<RequestFilter>("failures");
  const [copied, setCopied] = useState("");
  const [feedback, setFeedback] = useState<"yes" | "no" | "">("");
  const [note, setNote] = useState("");
  const [noteSent, setNoteSent] = useState(false);

  const rows = useMemo(() => {
    if (filter === "failures") return analysis.requests.filter((row) => row.failure);
    if (filter === "slow") {
      return [...analysis.requests]
        .sort((a, b) => b.duration - a.duration)
        .slice(0, 15);
    }
    return analysis.requests.slice(0, 100);
  }, [analysis.requests, filter]);

  const copy = async (kind: "report" | "ai") => {
    await navigator.clipboard.writeText(
      kind === "report" ? analysis.markdown : analysis.aiPrompt,
    );
    setCopied(kind);
    track(kind === "report" ? "copy_report" : "copy_ai_prompt");
    window.setTimeout(() => setCopied(""), 1600);
  };

  const exportSanitized = () => {
    downloadText(
      `${safeBaseName(analysis.sourceName)}-sanitized.har`,
      JSON.stringify(analysis.sanitized, null, 2),
      "application/json",
    );
    track("export_sanitized_har");
  };

  const exportReport = () => {
    downloadText(
      `${safeBaseName(analysis.sourceName)}-incident.md`,
      analysis.markdown,
      "text/markdown",
    );
    track("export_markdown");
  };

  const answerFeedback = (answer: "yes" | "no") => {
    setFeedback(answer);
    track("report_helpful", answer);
  };

  const sendNote = () => {
    if (!note.trim()) return;
    track("feedback_note", note.trim());
    setNoteSent(true);
    setNote("");
  };

  return (
    <>
      <Header report />
      <main className="report-shell">
        <section className="report-heading">
          <div>
            <button className="back-button" onClick={onReset}>
              ← Analyze another trace
            </button>
            <p className="eyebrow">
              <span>Incident brief · generated locally</span>
              <i />
            </p>
            <h1>{analysis.title}</h1>
            <p>
              ReqRescue found {analysis.failedRequests} failed request
              {analysis.failedRequests === 1 ? "" : "s"} and removed{" "}
              {analysis.findingCount} sensitive value
              {analysis.findingCount === 1 ? "" : "s"} from the shareable copy.
            </p>
          </div>
          <div className="report-actions">
            <button className="button button-primary" onClick={exportSanitized}>
              Download clean HAR
            </button>
            <button className="button button-outline" onClick={exportReport}>
              Download report
            </button>
          </div>
        </section>

        <section className="metrics-bar" aria-label="Trace summary">
          <Metric value={String(analysis.totalRequests)} label="requests" />
          <Metric
            value={String(analysis.failedRequests)}
            label="failed"
            accent={analysis.failedRequests ? "danger" : "safe"}
          />
          <Metric value={String(analysis.domainCount)} label="domains" />
          <Metric value={formatDuration(analysis.p95Duration)} label="p95 latency" />
          <Metric value={formatBytes(analysis.totalBytes)} label="transferred" />
          <Metric
            value={`${analysis.safetyScore}/100`}
            label="raw share-safety"
            accent={analysis.safetyScore > 75 ? "safe" : "danger"}
          />
        </section>

        <section className="report-grid" id="evidence">
          <div className="report-main">
            <section className="report-card suspects-card">
              <header className="card-header">
                <div>
                  <span className="card-index">01</span>
                  <h2>Ranked suspects</h2>
                </div>
                <small>Evidence-backed heuristics</small>
              </header>
              <div className="suspects">
                {analysis.suspects.map((suspect) => (
                  <article className="suspect" key={`${suspect.rank}-${suspect.title}`}>
                    <span className="suspect-rank">{String(suspect.rank).padStart(2, "0")}</span>
                    <div>
                      <div className="suspect-title">
                        <h3>{suspect.title}</h3>
                        <Confidence value={suspect.confidence} />
                      </div>
                      <p>{suspect.explanation}</p>
                      <ul>
                        {suspect.evidence.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  </article>
                ))}
              </div>
            </section>

            <section className="report-card">
              <header className="card-header request-header">
                <div>
                  <span className="card-index">02</span>
                  <h2>Request evidence</h2>
                </div>
                <div className="filters" aria-label="Filter requests">
                  {(["failures", "slow", "all"] as RequestFilter[]).map((item) => (
                    <button
                      key={item}
                      className={filter === item ? "active" : ""}
                      onClick={() => setFilter(item)}
                    >
                      {item}
                    </button>
                  ))}
                </div>
              </header>
              <div className="request-table-wrap">
                <table className="request-table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Request</th>
                      <th>Time</th>
                      <th>Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.length ? (
                      rows.map((row) => (
                        <tr key={row.id}>
                          <td>
                            <span
                              className={`status-pill ${
                                row.failure ? "status-failed" : "status-ok"
                              }`}
                            >
                              {row.status || "NET"}
                            </span>
                          </td>
                          <td>
                            <b>{row.method}</b>
                            <span>{row.host}</span>
                            <code>{row.path.split("?")[0]}</code>
                          </td>
                          <td>{formatDuration(row.duration)}</td>
                          <td>{formatBytes(row.size)}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={4} className="empty-cell">
                          No requests match this filter.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {filter === "all" && analysis.totalRequests > 100 && (
                <p className="table-note">
                  Showing the first 100 requests. The exports retain all{" "}
                  {analysis.totalRequests}.
                </p>
              )}
            </section>
          </div>

          <aside className="report-side">
            <section className="report-card privacy-card">
              <header className="card-header compact">
                <div>
                  <span className="card-index">03</span>
                  <h2>Privacy sweep</h2>
                </div>
              </header>
              <div className="privacy-score">
                <div className="score-ring">
                  <span>{analysis.safetyScore}</span>
                </div>
                <div>
                  <b>Raw file risk</b>
                  <p>
                    {analysis.findingCount
                      ? "Use the sanitized export, then review it once."
                      : "No known secret pattern was detected."}
                  </p>
                </div>
              </div>
              <ul className="findings-list">
                {analysis.findings.length ? (
                  analysis.findings.map((finding) => (
                    <li key={finding.kind}>
                      <span className={`severity severity-${finding.severity}`} />
                      <b>{finding.label}</b>
                      <em>{finding.count}</em>
                    </li>
                  ))
                ) : (
                  <li>
                    <span className="severity severity-safe" />
                    <b>No known patterns found</b>
                    <em>0</em>
                  </li>
                )}
              </ul>
              <p className="privacy-warning">
                Automated redaction cannot recognize every product-specific
                secret. Always review before sending.
              </p>
            </section>

            <section className="report-card export-card" id="handoff">
              <header className="card-header compact">
                <div>
                  <span className="card-index">04</span>
                  <h2>Hand it off</h2>
                </div>
              </header>
              <button onClick={() => copy("report")}>
                <span>
                  <b>Copy bug report</b>
                  <small>Markdown · evidence + context</small>
                </span>
                <em>{copied === "report" ? "Copied" : "Copy"}</em>
              </button>
              <button onClick={() => copy("ai")}>
                <span>
                  <b>Copy for an AI debugger</b>
                  <small>Facts, constraints, explicit task</small>
                </span>
                <em>{copied === "ai" ? "Copied" : "Copy"}</em>
              </button>
              <button onClick={exportSanitized}>
                <span>
                  <b>Download sanitized HAR</b>
                  <small>Same structure · secrets removed</small>
                </span>
                <em>HAR</em>
              </button>
            </section>

            <section className="report-card feedback-card" id="feedback">
              <p>Did this point you in the right direction?</p>
              <div>
                <button
                  className={feedback === "yes" ? "selected" : ""}
                  onClick={() => answerFeedback("yes")}
                >
                  Yes
                </button>
                <button
                  className={feedback === "no" ? "selected" : ""}
                  onClick={() => answerFeedback("no")}
                >
                  Not yet
                </button>
              </div>
              {feedback && !noteSent && (
                <div className="note-box">
                  <textarea
                    value={note}
                    maxLength={220}
                    onChange={(event) => setNote(event.target.value)}
                    placeholder="One sentence would help us improve…"
                  />
                  <button disabled={!note.trim()} onClick={sendNote}>
                    Send
                  </button>
                </div>
              )}
              {noteSent && <small>Received. Thank you.</small>}
            </section>

            <section className="report-card pilot-card">
              <span>For support teams · founding pilot</span>
              <h2>Make every trace arrive ready to act on.</h2>
              <p>
                We will fit ReqRescue to one real intake queue for two weeks.
                No card; $19/month only if your team keeps it.
              </p>
              <a
                className="button button-primary"
                href={TEAM_PILOT_MAILTO}
                onClick={() => track("team_pilot_click", "report")}
              >
                Ask for the pilot
              </a>
            </section>
          </aside>
        </section>

        <section className="report-disclaimer">
          <b>What this report is:</b> deterministic network triage based on the
          captured evidence. <b>What it is not:</b> proof of a server-side root
          cause without the corresponding application logs.
        </section>
      </main>
      <Footer />
    </>
  );
}

function Footer() {
  return (
    <footer className="site-footer">
      <Logo />
      <p>Local-first evidence triage for web incidents.</p>
      <span>Built for useful bug reports, not data collection.</span>
    </footer>
  );
}

export default function Home() {
  const [view, setView] = useState<View>("landing");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    track("page_view", acquisitionSource());
  }, []);

  const finish = useCallback((next: Analysis, source: "file" | "demo") => {
    setAnalysis(next);
    setView("report");
    setBusy(false);
    setError("");
    window.scrollTo({ top: 0, behavior: "instant" });
    track("analysis_complete", source);
  }, []);

  const handleFile = useCallback(
    async (file: File) => {
      setError("");
      if (file.size > MAX_FILE_BYTES) {
        setError("The current browser build accepts files up to 80 MB.");
        return;
      }
      setBusy(true);
      try {
        const text = await file.text();
        const har = parseHar(text);
        const next = analyzeHar(har, file.name);
        finish(next, "file");
      } catch (reason) {
        setBusy(false);
        setError(reason instanceof Error ? reason.message : "Unknown parsing error.");
        track("analysis_error");
      }
    },
    [finish],
  );

  const handleDemo = useCallback(() => {
    setBusy(true);
    setError("");
    window.setTimeout(() => {
      try {
        finish(analyzeHar(buildDemoHar(), "broken-checkout-demo.har"), "demo");
      } catch (reason) {
        setBusy(false);
        setError(reason instanceof Error ? reason.message : "Demo failed to load.");
      }
    }, 380);
  }, [finish]);

  const reset = () => {
    setView("landing");
    setAnalysis(null);
    setError("");
    window.scrollTo({ top: 0, behavior: "instant" });
  };

  return view === "report" && analysis ? (
    <Report analysis={analysis} onReset={reset} />
  ) : (
    <Landing busy={busy} error={error} onFile={handleFile} onDemo={handleDemo} />
  );
}
