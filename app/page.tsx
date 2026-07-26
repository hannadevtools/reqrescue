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
type StoredCase = {
  id: string;
  savedAt: string;
  title: string;
  sourceName: string;
  markdown: string;
};

const FREE_MAX_FILE_BYTES = 80 * 1024 * 1024;
const PRO_MAX_FILE_BYTES = 250 * 1024 * 1024;
const GUMROAD_PRODUCT_URL = "https://hannadev.gumroad.com/l/reqrescue-pro";
const GUMROAD_PRODUCT_ID = "JMi_OpMKayarptn0vFkQtg==";
const GITHUB_URL = "https://github.com/hannadevtools/reqrescue";
const PRO_STORAGE_KEY = "reqrescue-pro-unlocked";
const HISTORY_STORAGE_KEY = "reqrescue-case-history";

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

function loadHistory(): StoredCase[] {
  if (typeof window === "undefined") return [];

  try {
    const parsed = JSON.parse(localStorage.getItem(HISTORY_STORAGE_KEY) ?? "[]");
    return Array.isArray(parsed) ? parsed.slice(0, 10) : [];
  } catch {
    return [];
  }
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

function ProModal({
  open,
  unlocked,
  history,
  onClose,
  onUnlock,
}: {
  open: boolean;
  unlocked: boolean;
  history: StoredCase[];
  onClose: () => void;
  onUnlock: (licenseKey: string) => Promise<void>;
}) {
  const [licenseKey, setLicenseKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState("");

  if (!open) return null;

  const activate = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!licenseKey.trim()) return;
    setBusy(true);
    setError("");
    try {
      await onUnlock(licenseKey);
      setLicenseKey("");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "That key could not be verified. Check it and try again.",
      );
    } finally {
      setBusy(false);
    }
  };

  const copySavedCase = async (item: StoredCase) => {
    await navigator.clipboard.writeText(item.markdown);
    setCopied(item.id);
    track("pro_history_copy");
    window.setTimeout(() => setCopied(""), 1400);
  };

  return (
    <div className="pro-modal-backdrop" role="presentation">
      <section
        className="pro-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="pro-modal-title"
      >
        <button className="pro-modal-close" onClick={onClose} aria-label="Close">
          ×
        </button>
        <p className="eyebrow">
          <span>{unlocked ? "Pro active on this browser" : "One payment · lifetime unlock"}</span>
          <i />
        </p>
        <h2 id="pro-modal-title">
          {unlocked ? "Your local workflow is unlocked." : "ReqRescue Pro · $12 once"}
        </h2>

        {unlocked ? (
          <>
            <ul className="pro-feature-list">
              <li>Print or save complete incident briefs as PDF</li>
              <li>Analyze local HAR files up to 250 MB</li>
              <li>Keep up to 10 incident briefs on this device</li>
            </ul>
            <div className="case-history">
              <header>
                <b>Saved on this device</b>
                <span>{history.length}/10</span>
              </header>
              {history.length ? (
                history.map((item) => (
                  <article key={item.id}>
                    <div>
                      <b>{item.title}</b>
                      <small>
                        {item.sourceName} ·{" "}
                        {new Date(item.savedAt).toLocaleDateString()}
                      </small>
                    </div>
                    <button onClick={() => copySavedCase(item)}>
                      {copied === item.id ? "Copied" : "Copy report"}
                    </button>
                  </article>
                ))
              ) : (
                <p>Save a generated report and it will appear here.</p>
              )}
            </div>
          </>
        ) : (
          <>
            <p className="pro-modal-copy">
              The analyzer, sanitizer, Markdown report, and clean HAR stay free.
              Pro adds convenience exports and local workflow features—without
              an account or subscription.
            </p>
            <ul className="pro-feature-list">
              <li>Print-ready PDF incident brief</li>
              <li>250 MB local file limit</li>
              <li>On-device history for 10 cases</li>
            </ul>
            <a
              className="button button-primary pro-buy-button"
              href={GUMROAD_PRODUCT_URL}
              target="_blank"
              rel="noreferrer"
              onClick={() => track("pro_checkout_click", "modal")}
            >
              Buy lifetime Pro · $12
            </a>
            <form className="license-form" onSubmit={activate}>
              <label htmlFor="license-key">Already bought it? Paste your license key</label>
              <div>
                <input
                  id="license-key"
                  value={licenseKey}
                  onChange={(event) => {
                    setLicenseKey(event.target.value);
                    if (error) setError("");
                  }}
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  autoComplete="off"
                  spellCheck={false}
                />
                <button disabled={busy || !licenseKey.trim()}>
                  {busy ? "Checking…" : "Unlock"}
                </button>
              </div>
              {error && <p role="alert">{error}</p>}
            </form>
            <small className="license-privacy">
              Verification sends only this key to Gumroad. It never sends your
              HAR, file name, URLs, headers, or bodies.
            </small>
          </>
        )}
      </section>
    </div>
  );
}

function Header({
  report,
  proUnlocked,
  onOpenPro,
}: {
  report: boolean;
  proUnlocked: boolean;
  onOpenPro: () => void;
}) {
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
      <div className="header-actions">
        <a className="github-link" href={GITHUB_URL} target="_blank" rel="noreferrer">
          Open source <span aria-hidden="true">↗</span>
        </a>
        <button className="pro-link" onClick={onOpenPro}>
          {proUnlocked ? "Pro unlocked" : "Get Pro · $12"}
        </button>
      </div>
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
  maxFileBytes,
}: {
  busy: boolean;
  error: string;
  onFile: (file: File) => void;
  onDemo: () => void;
  maxFileBytes: number;
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
      <p className="file-note">
        Chrome, Firefox, Edge, Safari · up to {Math.round(maxFileBytes / 1024 / 1024)} MB
      </p>
      <details className="har-help">
        <summary>What is a HAR — and how do I get one?</summary>
        <div>
          <p>
            A HAR is a browser recording of the network requests made while a
            page loads or a problem happens. It helps support and engineering
            see failed API calls, slow requests, redirects, and status codes.
          </p>
          <ol>
            <li>Open the broken page, then open Developer Tools.</li>
            <li>Select <b>Network</b>, reload the page, and reproduce the issue.</li>
            <li>
              Export or save all requests as <b>HAR</b>, then open that file here.
            </li>
          </ol>
          <small>
            Chrome / Edge: F12 → Network → Export HAR. Firefox: F12 → Network →
            Save all as HAR.
          </small>
        </div>
      </details>
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
  maxFileBytes,
}: {
  busy: boolean;
  error: string;
  onFile: (file: File) => void;
  onDemo: () => void;
  maxFileBytes: number;
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
        <UploadPanel
          busy={busy}
          error={error}
          onFile={onFile}
          onDemo={onDemo}
          maxFileBytes={maxFileBytes}
        />
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

function PlainEnglish() {
  return (
    <section className="section plain-english" aria-labelledby="plain-english-title">
      <div className="section-kicker">
        <span>00</span>
        <p>ReqRescue, in plain English</p>
      </div>
      <div className="plain-english-head">
        <h2 id="plain-english-title">A safer, faster handoff when a website breaks.</h2>
        <p>
          ReqRescue reads a browser network recording, finds the requests most
          likely connected to the failure, removes common secrets, and packages
          the useful evidence for the person who has to fix it.
        </p>
      </div>
      <div className="plain-english-grid">
        <article>
          <span>WHAT GOES IN</span>
          <h3>A HAR network recording</h3>
          <p>
            A standard file exported from your browser after you reproduce a
            broken checkout, login, upload, dashboard, or other web flow.
          </p>
        </article>
        <article>
          <span>WHO IT IS FOR</span>
          <h3>Support, QA, developers, and technical founders</h3>
          <p>
            Anyone who needs to turn “it does not work” into evidence an
            engineer can inspect without another round of questions.
          </p>
        </article>
        <article>
          <span>WHAT COMES OUT</span>
          <h3>A diagnosis, clean HAR, and ready-to-send report</h3>
          <p>
            Ranked suspects with confidence, cited request evidence, detected
            privacy risks, and a Markdown handoff for Jira, GitHub, Slack, or AI.
          </p>
        </article>
      </div>
    </section>
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

function Roadmap({
  onDemo,
  onOpenPro,
  proUnlocked,
}: {
  onDemo: () => void;
  onOpenPro: () => void;
  proUnlocked: boolean;
}) {
  return (
    <section className="section roadmap" id="roadmap">
      <div className="roadmap-copy">
        <p className="eyebrow">
          <span>ReqRescue Pro · one-time unlock</span>
          <i />
        </p>
        <h2>Keep the rescue free. Pay once for the workflow.</h2>
        <p>
          Analysis, redaction, clean HAR, and Markdown export stay free and open
          source. Pro is a lifetime convenience unlock for PDF handoff, larger
          local files, and case history on this device.
        </p>
        <div className="roadmap-actions">
          <button className="button button-primary" onClick={onOpenPro}>
            {proUnlocked ? "View your Pro history" : "Get lifetime Pro · $12"}
          </button>
          <button className="button button-outline" onClick={onDemo}>
            Open the demo case
          </button>
        </div>
        <small className="pilot-fineprint">
          One payment. No ReqRescue account. 30-day money-back guarantee.
        </small>
      </div>
      <div className="pilot-offer">
        <header>
          <span>Lifetime price</span>
          <strong>$12<small> once</small></strong>
        </header>
        <p>For people who use HARs often enough to want a faster handoff.</p>
        <ul>
          <li>Print or save the full incident brief as PDF</li>
          <li>Analyze files up to 250 MB, locally</li>
          <li>Save 10 case reports on this device</li>
          <li>Future Pro convenience exports included</li>
        </ul>
        <small>The free core is not crippled, timed, or account-gated.</small>
      </div>
    </section>
  );
}

function Landing({
  busy,
  error,
  onFile,
  onDemo,
  maxFileBytes,
  proUnlocked,
  onOpenPro,
}: {
  busy: boolean;
  error: string;
  onFile: (file: File) => void;
  onDemo: () => void;
  maxFileBytes: number;
  proUnlocked: boolean;
  onOpenPro: () => void;
}) {
  const structuredData = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "SoftwareApplication",
        name: "ReqRescue",
        applicationCategory: "DeveloperApplication",
        operatingSystem: "Any modern web browser",
        url: "https://app.reqrescue.workers.dev/",
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
      <Header report={false} proUnlocked={proUnlocked} onOpenPro={onOpenPro} />
      <main>
        <Hero
          busy={busy}
          error={error}
          onFile={onFile}
          onDemo={onDemo}
          maxFileBytes={maxFileBytes}
        />
        <PlainEnglish />
        <HowItWorks />
        <BeforeAfter />
        <Privacy />
        <Faq />
        <Roadmap
          onDemo={onDemo}
          onOpenPro={onOpenPro}
          proUnlocked={proUnlocked}
        />
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

function sanitizedPreview(analysis: Analysis) {
  const entries = analysis.sanitized.log.entries;
  const selected = [...entries]
    .sort((a, b) => {
      const aFailed = (a.response?.status ?? 0) >= 400 || Boolean(a._error);
      const bFailed = (b.response?.status ?? 0) >= 400 || Boolean(b._error);
      return Number(bFailed) - Number(aFailed);
    })
    .slice(0, 2)
    .map((entry) => ({
      request: {
        method: entry.request?.method ?? "GET",
        url: entry.request?.url ?? "",
        headers: entry.request?.headers?.slice(0, 8) ?? [],
        cookies: entry.request?.cookies?.slice(0, 4) ?? [],
        query: entry.request?.queryString?.slice(0, 6) ?? [],
        body: entry.request?.postData?.text?.slice(0, 500) || undefined,
      },
      response: {
        status: entry.response?.status ?? 0,
        headers: entry.response?.headers?.slice(0, 8) ?? [],
        cookies: entry.response?.cookies?.slice(0, 4) ?? [],
        body: entry.response?.content?.text?.slice(0, 500) || undefined,
      },
    }));

  return JSON.stringify({ preview: "sanitized locally", requests: selected }, null, 2);
}

function Report({
  analysis,
  onReset,
  proUnlocked,
  onOpenPro,
  onSaveCase,
}: {
  analysis: Analysis;
  onReset: () => void;
  proUnlocked: boolean;
  onOpenPro: () => void;
  onSaveCase: (analysis: Analysis) => void;
}) {
  const [filter, setFilter] = useState<RequestFilter>("failures");
  const [copied, setCopied] = useState("");
  const [feedback, setFeedback] = useState<"yes" | "no" | "">("");
  const [note, setNote] = useState("");
  const [noteSent, setNoteSent] = useState(false);
  const [caseSaved, setCaseSaved] = useState(false);
  const preview = useMemo(() => sanitizedPreview(analysis), [analysis]);

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

  const printReport = () => {
    if (!proUnlocked) {
      onOpenPro();
      return;
    }
    track("pro_pdf_print");
    window.print();
  };

  const saveCase = () => {
    if (!proUnlocked) {
      onOpenPro();
      return;
    }
    onSaveCase(analysis);
    setCaseSaved(true);
  };

  return (
    <>
      <Header report proUnlocked={proUnlocked} onOpenPro={onOpenPro} />
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
            <button className="button button-outline" onClick={printReport}>
              {proUnlocked ? "Print / save PDF" : "PDF · Pro"}
            </button>
            <button className="button button-outline" onClick={saveCase}>
              {caseSaved ? "Saved locally" : proUnlocked ? "Save case" : "History · Pro"}
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

            <details className="report-card sanitized-preview">
              <summary>
                <span>
                  <i className="card-index">04</i>
                  <b>Preview sanitized data</b>
                </span>
                <em>Inspect before export</em>
              </summary>
              <div>
                <p>
                  This is a small preview of the cleaned copy generated in your
                  browser. Search for <code>[REDACTED]</code> and review any
                  product-specific values before sharing the full export.
                </p>
                <pre>
                  <code>{preview}</code>
                </pre>
              </div>
            </details>

            <section className="report-card export-card" id="handoff">
              <header className="card-header compact">
                <div>
                  <span className="card-index">05</span>
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
              <span>Lifetime Pro · $12 once</span>
              <h2>Save the brief, not another subscription.</h2>
              <p>
                Add PDF handoff, larger local files, and on-device history. The
                analyzer and sanitizer stay free and open source.
              </p>
              <button
                className="button button-primary"
                onClick={onOpenPro}
              >
                {proUnlocked ? "Open Pro history" : "Unlock lifetime Pro"}
              </button>
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
  const [proUnlocked, setProUnlocked] = useState(false);
  const [proOpen, setProOpen] = useState(false);
  const [history, setHistory] = useState<StoredCase[]>([]);

  useEffect(() => {
    track("page_view", acquisitionSource());
    const initialization = window.setTimeout(() => {
      setProUnlocked(localStorage.getItem(PRO_STORAGE_KEY) === "true");
      setHistory(loadHistory());
    }, 0);
    return () => window.clearTimeout(initialization);
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
      const maxBytes = proUnlocked ? PRO_MAX_FILE_BYTES : FREE_MAX_FILE_BYTES;
      if (file.size > maxBytes) {
        setError(
          proUnlocked
            ? "This browser accepts Pro files up to 250 MB."
            : "The free build accepts up to 80 MB. Lifetime Pro raises the local limit to 250 MB.",
        );
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
    [finish, proUnlocked],
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

  const unlockPro = async (rawKey: string) => {
    const licenseKey = rawKey.trim();
    const body = new URLSearchParams({
      product_id: GUMROAD_PRODUCT_ID,
      license_key: licenseKey,
      increment_uses_count: "false",
    });
    const response = await fetch("https://api.gumroad.com/v2/licenses/verify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });

    if (!response.ok) {
      track("pro_activation_error", "invalid");
      throw new Error("That license key was not accepted. Copy it from your Gumroad receipt.");
    }

    const result = (await response.json()) as {
      success?: boolean;
      purchase?: {
        product_id?: string;
        refunded?: boolean;
        disputed?: boolean;
        chargebacked?: boolean;
      };
    };
    const purchase = result.purchase;
    if (
      !result.success ||
      purchase?.product_id !== GUMROAD_PRODUCT_ID ||
      purchase.refunded ||
      purchase.disputed ||
      purchase.chargebacked
    ) {
      track("pro_activation_error", "inactive");
      throw new Error("This purchase is not active. Check the key or the Gumroad receipt.");
    }

    localStorage.setItem(PRO_STORAGE_KEY, "true");
    setProUnlocked(true);
    track("pro_activation_success");
  };

  const saveCaseToHistory = (item: Analysis) => {
    const stored: StoredCase = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      savedAt: new Date().toISOString(),
      title: item.title,
      sourceName: item.sourceName,
      markdown: item.markdown,
    };
    const next = [stored, ...loadHistory()].slice(0, 10);
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(next));
    setHistory(next);
    track("pro_case_saved");
  };

  return (
    <>
      {view === "report" && analysis ? (
        <Report
          analysis={analysis}
          onReset={reset}
          proUnlocked={proUnlocked}
          onOpenPro={() => setProOpen(true)}
          onSaveCase={saveCaseToHistory}
        />
      ) : (
        <Landing
          busy={busy}
          error={error}
          onFile={handleFile}
          onDemo={handleDemo}
          maxFileBytes={proUnlocked ? PRO_MAX_FILE_BYTES : FREE_MAX_FILE_BYTES}
          proUnlocked={proUnlocked}
          onOpenPro={() => setProOpen(true)}
        />
      )}
      <ProModal
        open={proOpen}
        unlocked={proUnlocked}
        history={history}
        onClose={() => setProOpen(false)}
        onUnlock={unlockPro}
      />
    </>
  );
}
