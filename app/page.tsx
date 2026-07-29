"use client";

import {
  type Analysis,
  analyzeHar,
  buildDemoHar,
  buildSanitizedPreview,
  formatBytes,
  formatDuration,
  MAX_HAR_FILE_BYTES,
} from "./trace-engine";
import { type HarComparison } from "./trace-compare";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type View = "landing" | "report" | "comparison";
type RequestFilter = "failures" | "slow" | "all";
const SLOW_REQUEST_THRESHOLD_MS = 1_000;
type StoredCase = {
  id: string;
  savedAt: string;
  title: string;
  sourceName: string;
  markdown: string;
};
type ActiveJob = {
  cancelled: boolean;
  worker?: Worker;
  timer?: number;
  cancelPromise?: () => void;
};
type HarWorkerMessage =
  | { type: "progress"; message: string }
  | { type: "complete"; analysis: Analysis }
  | { type: "comparison-complete"; comparison: HarComparison }
  | { type: "error"; message: string };

const GITHUB_URL = "https://github.com/hannadevtools/reqrescue";
const HISTORY_STORAGE_KEY = "reqrescue-case-history";
const MAX_FILE_BYTES = MAX_HAR_FILE_BYTES;

function storageGet(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key: string, value: string): boolean {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

async function track(event: string, detail?: string): Promise<boolean> {
  try {
    const storageKey = "reqrescue-session";
    const session =
      storageGet(storageKey) ??
      (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);
    storageSet(storageKey, session);
    const response = await fetch("/api/event", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        event,
        session,
        detail: detail?.slice(0, 220),
      }),
      keepalive: true,
    });
    return response.ok;
  } catch {
    // Analytics must never block the local-first tool.
    return false;
  }
}

function acquisitionSource() {
  const params = new URLSearchParams(window.location.search);
  const source = params.get("utm_source");
  const medium = params.get("utm_medium");
  if (source) {
    return [source, medium]
      .filter(Boolean)
      .map((value) => value!.replace(/[^a-z0-9_-]/gi, "").slice(0, 40))
      .filter(Boolean)
      .join("/");
  }

  try {
    const referrer = document.referrer ? new URL(document.referrer).hostname : "";
    if (!referrer) return "direct";
    const knownSource = [
      "reddit.com",
      "github.com",
      "news.ycombinator.com",
      "x.com",
      "twitter.com",
      "google.",
      "bing.com",
    ].find((candidate) => referrer === candidate || referrer.endsWith(`.${candidate}`));
    return knownSource ? referrer : "referral";
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
    const parsed = JSON.parse(storageGet(HISTORY_STORAGE_KEY) ?? "[]");
    return Array.isArray(parsed) ? parsed.slice(0, 10) : [];
  } catch {
    return [];
  }
}

function Logo() {
  return (
    <a className="brand" href="/" aria-label="ReqRescue home">
      <span className="brand-mark" aria-hidden="true">
        R<span>R</span>
      </span>
      <span>ReqRescue</span>
    </a>
  );
}

function HistoryModal({
  open,
  history,
  onClose,
}: {
  open: boolean;
  history: StoredCase[];
  onClose: () => void;
}) {
  const [copied, setCopied] = useState("");
  const modalRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) return;

    const previousFocus =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || !modalRef.current) return;

      const focusable = [
        ...modalRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ].filter((element) => !element.hasAttribute("hidden"));
      if (!focusable.length) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [open]);

  if (!open) return null;

  const copySavedCase = async (item: StoredCase) => {
    try {
      await navigator.clipboard.writeText(item.markdown);
      setCopied(item.id);
      void track("history_copy");
    } catch {
      setCopied("error");
    }
    window.setTimeout(() => setCopied(""), 1400);
  };

  return (
    <div
      className="pro-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.currentTarget === event.target) onClose();
      }}
    >
      <section
        ref={modalRef}
        className="pro-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="history-modal-title"
      >
        <button
          ref={closeRef}
          className="pro-modal-close"
          onClick={onClose}
          aria-label="Close"
        >
          ×
        </button>
        <p className="eyebrow">
          <span>Free local workspace · this browser only</span>
          <i />
        </p>
        <h2 id="history-modal-title">Saved incident briefs</h2>
        <p className="pro-modal-copy">
          Keep up to 10 reports on this device. No account, payment, or cloud
          storage is involved.
        </p>
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
                  {copied === item.id
                    ? "Copied"
                    : copied === "error"
                      ? "Copy failed"
                      : "Copy report"}
                </button>
              </article>
            ))
          ) : (
            <p>Save a generated report and it will appear here.</p>
          )}
        </div>
      </section>
    </div>
  );
}

function Header({ onOpenHistory }: { onOpenHistory: () => void }) {
  const links = [
    ["How it works", "/#how-it-works"],
    ["Privacy", "/#privacy"],
    ["FAQ", "/#faq"],
    ["Help cats", "/#help-cats"],
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
        <button className="pro-link" onClick={onOpenHistory}>
          Saved cases
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
  busyMessage,
  error,
  onFile,
  onCompare,
  onDemo,
  onCancel,
  maxFileBytes,
}: {
  busy: boolean;
  busyMessage: string;
  error: string;
  onFile: (file: File) => void;
  onCompare: (files: File[]) => void;
  onDemo: () => void;
  onCancel: () => void;
  maxFileBytes: number;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const compareInputRef = useRef<HTMLInputElement>(null);
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
        const files = [...event.dataTransfer.files];
        if (files.length === 2) {
          onCompare(files);
        } else {
          acceptFile(files[0]);
        }
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".har,.json,application/json"
        hidden
        onClick={(event) => {
          event.currentTarget.value = "";
        }}
        onChange={(event) => {
          const file = event.target.files?.[0];
          event.currentTarget.value = "";
          acceptFile(file);
        }}
      />
      <input
        ref={compareInputRef}
        type="file"
        accept=".har,.json,application/json"
        multiple
        hidden
        onClick={(event) => {
          event.currentTarget.value = "";
        }}
        onChange={(event) => {
          const files = [...(event.target.files ?? [])];
          event.currentTarget.value = "";
          onCompare(files);
        }}
      />
      <div className="drop-symbol" aria-hidden="true">
        <span>HAR</span>
        <i />
      </div>
      <h2>
        {busy
          ? busyMessage || "Reading the trace…"
          : "Drop the browser recording (HAR)."}
      </h2>
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
        <button
          className="button button-outline button-compare"
          disabled={busy}
          onClick={() => compareInputRef.current?.click()}
        >
          Compare two HARs (A/B)
        </button>
        {busy && (
          <button className="button button-quiet" onClick={onCancel}>
            Cancel local analysis
          </button>
        )}
      </div>
      <p className="file-note">
        Chrome, Firefox, Edge, Safari · protected local limit{" "}
        {Math.round(maxFileBytes / 1024 / 1024)} MB per file · for A/B, choose
        baseline first and changed capture second
      </p>
      <details className="har-help">
        <summary>Need a HAR? Export one in 3 steps.</summary>
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
  busyMessage,
  error,
  onFile,
  onCompare,
  onDemo,
  onCancel,
  maxFileBytes,
}: {
  busy: boolean;
  busyMessage: string;
  error: string;
  onFile: (file: File) => void;
  onCompare: (files: File[]) => void;
  onDemo: () => void;
  onCancel: () => void;
  maxFileBytes: number;
}) {
  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">
            <span>Free browser-error analyzer · 0 bytes uploaded</span>
            <i />
          </p>
          <h1>
            A website broke.
            <br />
            Send <em>evidence, not guesswork.</em>
          </h1>
          <p className="hero-lede">
            A HAR is the browser&apos;s recording of what happened while a page
            failed. ReqRescue finds the likely failure points, removes common
            secrets, and turns that recording into a ready-to-send bug report.
            The file never leaves this tab.
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
          busyMessage={busyMessage}
          error={error}
          onFile={onFile}
          onCompare={onCompare}
          onDemo={onDemo}
          onCancel={onCancel}
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
                requests, and spot redirect loops that keep the browser in circles.
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
          pseudonymous product events such as “demo analyzed” or “report exported,”
          using a random identifier stored in this browser—never file names, URLs,
          headers, bodies, or HAR contents.
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
        "ReqRescue strips request and response bodies, cookies, authorization headers, API keys, access and refresh tokens, passwords, emails, IP addresses, private hosts, URL credentials and likely identifiers in paths. It also drops unknown vendor fields. Automated redaction cannot guarantee recognition of every product-specific secret, so review every export before sharing it.",
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

function CatSupport() {
  return (
    <section className="section roadmap" id="help-cats">
      <div className="roadmap-copy">
        <p className="eyebrow">
          <span>ReqRescue is free · pass the help forward</span>
          <i />
        </p>
        <h2>Saved an hour? Help a cat instead.</h2>
        <p>
          ReqRescue does not accept donations. Analysis, comparison, redaction,
          PDF, local history, and exports are free. If the tool saved you time,
          consider donating directly to one of these independent Israeli animal
          organizations.
        </p>
        <div className="roadmap-actions">
          <a
            className="button button-primary"
            href="https://isracats.org.il/donation/"
            target="_blank"
            rel="noreferrer"
            onClick={() => void track("cat_charity_click", "israel_cat_lovers")}
          >
            Help Israel Cat Lovers&apos; Society ↗
          </a>
          <a
            className="button button-outline"
            href="https://www.sospets.co.il/donationen"
            target="_blank"
            rel="noreferrer"
            onClick={() => void track("cat_charity_click", "sos_pets_israel")}
          >
            Help S.O.S Pets Israel ↗
          </a>
        </div>
        <small className="pilot-fineprint">
          These links go straight to the organizations&apos; official donation
          pages. ReqRescue is not affiliated with them and receives nothing.
        </small>
      </div>
      <div className="pilot-offer">
        <header>
          <span>What remains free</span>
          <strong>100<small>%</small></strong>
        </header>
        <p>No paywall, license key, account, subscription, or donation to us.</p>
        <ul>
          <li>Analyze or compare local HAR files up to 75 MB each</li>
          <li>Download clean HAR and Markdown reports</li>
          <li>Print or save full incident briefs as PDF</li>
          <li>Save 10 case reports locally on this device</li>
        </ul>
        <small>
          The two organizations above independently help homeless, injured, and
          abandoned cats in Israel.
        </small>
      </div>
    </section>
  );
}

function Landing({
  busy,
  busyMessage,
  error,
  onFile,
  onCompare,
  onDemo,
  onCancel,
  maxFileBytes,
  onOpenHistory,
}: {
  busy: boolean;
  busyMessage: string;
  error: string;
  onFile: (file: File) => void;
  onCompare: (files: File[]) => void;
  onDemo: () => void;
  onCancel: () => void;
  maxFileBytes: number;
  onOpenHistory: () => void;
}) {
  return (
    <>
      <Header onOpenHistory={onOpenHistory} />
      <main>
        <Hero
          busy={busy}
          busyMessage={busyMessage}
          error={error}
          onFile={onFile}
          onCompare={onCompare}
          onDemo={onDemo}
          onCancel={onCancel}
          maxFileBytes={maxFileBytes}
        />
        <PlainEnglish />
        <HowItWorks />
        <BeforeAfter />
        <Privacy />
        <Faq />
        <CatSupport />
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
  return (
    <span className={`confidence confidence-${value}`}>
      {value} evidence confidence
    </span>
  );
}

function BreakableTitle({ value }: { value: string }) {
  return value.split(/([/.])/).map((part, index) =>
    part === "/" || part === "." ? (
      <span key={`${part}-${index}`}>
        {part}
        <wbr />
      </span>
    ) : (
      part
    ),
  );
}

function Report({
  analysis,
  onReset,
  onOpenHistory,
  onSaveCase,
}: {
  analysis: Analysis;
  onReset: () => void;
  onOpenHistory: () => void;
  onSaveCase: (analysis: Analysis) => void;
}) {
  const [filter, setFilter] = useState<RequestFilter>("failures");
  const [copied, setCopied] = useState("");
  const [feedback, setFeedback] = useState<"yes" | "no" | "">("");
  const [note, setNote] = useState("");
  const [noteSent, setNoteSent] = useState(false);
  const [noteSending, setNoteSending] = useState(false);
  const [noteError, setNoteError] = useState("");
  const [caseSaved, setCaseSaved] = useState(false);
  const [actionError, setActionError] = useState("");
  const preview = useMemo(() => buildSanitizedPreview(analysis), [analysis]);

  const rows = useMemo(() => {
    if (filter === "failures") return analysis.requests.filter((row) => row.failure);
    if (filter === "slow") {
      return [...analysis.requests]
        .filter((row) => row.duration >= SLOW_REQUEST_THRESHOLD_MS)
        .sort((a, b) => b.duration - a.duration)
        .slice(0, 50);
    }
    return analysis.requests.slice(0, 100);
  }, [analysis.requests, filter]);

  const copy = async (kind: "report" | "ai") => {
    setActionError("");
    try {
      await navigator.clipboard.writeText(
        kind === "report" ? analysis.markdown : analysis.aiPrompt,
      );
      setCopied(kind);
      void track(kind === "report" ? "copy_report" : "copy_ai_prompt");
      window.setTimeout(() => setCopied(""), 1600);
    } catch {
      setActionError("Clipboard access was blocked. Download the report instead.");
    }
  };

  const exportSanitized = () => {
    downloadText(
      `${safeBaseName(analysis.sourceName)}-sanitized.har`,
      JSON.stringify(analysis.sanitized, null, 2),
      "application/json",
    );
    void track("export_sanitized_har");
  };

  const exportReport = () => {
    downloadText(
      `${safeBaseName(analysis.sourceName)}-incident.md`,
      analysis.markdown,
      "text/markdown",
    );
    void track("export_markdown");
  };

  const answerFeedback = (answer: "yes" | "no") => {
    setFeedback(answer);
    void track("report_helpful", answer);
  };

  const sendNote = async () => {
    if (!note.trim()) return;
    setNoteSending(true);
    setNoteError("");
    const sent = await track("feedback_note", note.trim());
    setNoteSending(false);
    if (sent) {
      setNoteSent(true);
      setNote("");
    } else {
      setNoteError("The note could not be sent. Your report and HAR were not affected.");
    }
  };

  const printReport = () => {
    void track("pdf_print");
    window.print();
  };

  const saveCase = () => {
    setActionError("");
    try {
      onSaveCase(analysis);
      setCaseSaved(true);
    } catch (reason) {
      setActionError(
        reason instanceof Error ? reason.message : "This case could not be saved locally.",
      );
    }
  };

  return (
    <>
      <Header onOpenHistory={onOpenHistory} />
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
            <h1>
              <BreakableTitle value={analysis.title} />
            </h1>
            <p>
              ReqRescue found {analysis.failedRequests} failed request
              {analysis.failedRequests === 1 ? "" : "s"}, detected{" "}
              {analysis.findingCount} sensitive exposure
              {analysis.findingCount === 1 ? "" : "s"}, and rebuilt every
              shareable output from sanitized evidence.
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
              Print / save PDF
            </button>
            <button className="button button-outline" onClick={saveCase}>
              {caseSaved ? "Saved locally" : "Save case"}
            </button>
          </div>
          {actionError && (
            <p className="action-error" role="alert">
              {actionError}
            </p>
          )}
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
                      <div className="suspect-next">
                        <span>Recommended next check</span>
                        <p>{suspect.nextStep}</p>
                      </div>
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
                      {item === "slow" ? "slow ≥ 1 s" : item}
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
              {filter === "slow" && (
                <p className="table-note">
                  Showing requests that took at least 1 second, slowest first.
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
                  <span>
                    {analysis.safetyScore}
                    <small>/100</small>
                  </span>
                </div>
                <div>
                  <b>Raw share-safety</b>
                  <p>
                    Higher is safer.{" "}
                    {analysis.findingCount
                      ? "The raw trace contains sensitive locations."
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
                Bodies, page titles, URL credentials, opaque path identifiers,
                private hosts, and unknown extension fields are stripped by
                default. Always review before sending.
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
                  browser. Request and response bodies are removed rather than
                  guessed. Search for <code>[REDACTED]</code> and review any
                  remaining product-specific values before sharing the full export.
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
                  <small>Markdown · evidence + next checks · ReqRescue footer</small>
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
                  <button disabled={!note.trim() || noteSending} onClick={sendNote}>
                    {noteSending ? "Sending…" : "Send"}
                  </button>
                  {noteError && <small role="alert">{noteError}</small>}
                </div>
              )}
              {noteSent && <small>Received. Thank you.</small>}
            </section>

            <section className="report-card pilot-card">
              <span>Everything here is free</span>
              <h2>Saved time? Help a cat instead.</h2>
              <p>
                ReqRescue accepts no donations. If this report helped, consider
                donating directly to an independent animal organization.
              </p>
              <a
                className="button button-primary"
                href="https://isracats.org.il/donation/"
                target="_blank"
                rel="noreferrer"
                onClick={() => void track("cat_charity_click", "report")}
              >
                Help cats in Israel ↗
              </a>
            </section>
          </aside>
        </section>

        <section className="report-disclaimer">
          <b>What this report is:</b> deterministic network triage based on the
          captured evidence. <b>What it is not:</b> proof of a server-side root
          cause without the corresponding application logs.
        </section>

        <section className="report-signature" aria-label="ReqRescue report attribution">
          <span className="report-signature-mark" aria-hidden="true">
            R
          </span>
          <div>
            <small>Report generated locally by</small>
            <b>ReqRescue</b>
          </div>
          <a href="https://app.reqrescue.workers.dev">
            Analyze another HAR ↗
          </a>
        </section>
      </main>
      <Footer />
    </>
  );
}

function ComparisonReport({
  comparison,
  onReset,
  onOpenHistory,
}: {
  comparison: HarComparison;
  onReset: () => void;
  onOpenHistory: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [actionError, setActionError] = useState("");
  const { baseline, changed } = comparison;
  const failureDelta = changed.failedRequests - baseline.failedRequests;
  const latencyDelta = changed.p95Duration - baseline.p95Duration;
  const latencyDeltaLabel = `${latencyDelta > 0 ? "+" : latencyDelta < 0 ? "−" : ""}${formatDuration(
    Math.abs(latencyDelta),
  )}`;

  const copyReport = async () => {
    setActionError("");
    try {
      await navigator.clipboard.writeText(comparison.markdown);
      setCopied(true);
      void track("comparison_copy_report");
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setActionError("Clipboard access was blocked. Download the report instead.");
    }
  };

  const exportReport = () => {
    downloadText(
      `${safeBaseName(baseline.sourceName)}-vs-${safeBaseName(changed.sourceName)}.md`,
      comparison.markdown,
      "text/markdown",
    );
    void track("comparison_export_markdown");
  };

  const exportSanitized = (analysis: Analysis, label: "a" | "b") => {
    downloadText(
      `${label}-${safeBaseName(analysis.sourceName)}-sanitized.har`,
      JSON.stringify(analysis.sanitized, null, 2),
      "application/json",
    );
    void track("comparison_export_sanitized", label);
  };

  return (
    <>
      <Header onOpenHistory={onOpenHistory} />
      <main className="report-shell comparison-shell">
        <section className="report-heading">
          <div>
            <button className="back-button" onClick={onReset}>
              ← Compare another pair
            </button>
            <p className="eyebrow">
              <span>A/B HAR diff · generated locally</span>
              <i />
            </p>
            <h1>
              <BreakableTitle value={comparison.title} />
            </h1>
            <p>
              Capture A is the baseline. Capture B is the changed or broken run.
              ReqRescue compared only sanitized structure—never secret values.
            </p>
          </div>
          <div className="report-actions">
            <button className="button button-primary" onClick={copyReport}>
              {copied ? "Copied" : "Copy comparison"}
            </button>
            <button className="button button-outline" onClick={exportReport}>
              Download Markdown
            </button>
            <button className="button button-outline" onClick={() => window.print()}>
              Print / save PDF
            </button>
          </div>
          {actionError && (
            <p className="action-error" role="alert">
              {actionError}
            </p>
          )}
        </section>

        <section className="capture-pair" aria-label="Compared captures">
          <article>
            <span>A · BASELINE</span>
            <b>{baseline.sourceName}</b>
            <small>
              {baseline.totalRequests} requests · {baseline.failedRequests} failed ·{" "}
              {formatDuration(baseline.p95Duration)} p95
            </small>
          </article>
          <div aria-hidden="true">→</div>
          <article>
            <span>B · CHANGED</span>
            <b>{changed.sourceName}</b>
            <small>
              {changed.totalRequests} requests · {changed.failedRequests} failed ·{" "}
              {formatDuration(changed.p95Duration)} p95
            </small>
          </article>
        </section>

        <section className="metrics-bar comparison-metrics" aria-label="Comparison summary">
          <Metric value={String(comparison.changes.length)} label="ranked differences" />
          <Metric
            value={`${failureDelta > 0 ? "+" : ""}${failureDelta}`}
            label="failed requests in B"
            accent={failureDelta > 0 ? "danger" : "safe"}
          />
          <Metric
            value={`${changed.totalRequests - baseline.totalRequests > 0 ? "+" : ""}${
              changed.totalRequests - baseline.totalRequests
            }`}
            label="request-count delta"
          />
          <Metric
            value={latencyDeltaLabel}
            label="p95 latency delta"
            accent={latencyDelta > 500 ? "danger" : undefined}
          />
          <Metric value={String(comparison.findingCount)} label="sensitive locations" />
          <Metric
            value={`${comparison.safetyScore}/100`}
            label="lowest raw share-safety"
            accent={comparison.safetyScore > 75 ? "safe" : "danger"}
          />
        </section>

        <section className="report-grid">
          <div className="report-main">
            <section className="report-card suspects-card">
              <header className="card-header">
                <div>
                  <span className="card-index">01</span>
                  <h2>Ranked structural differences</h2>
                </div>
                <small>Facts first · causality requires confirmation</small>
              </header>
              <div className="suspects">
                {comparison.changes.length ? (
                  comparison.changes.map((change) => (
                    <article className="suspect" key={`${change.rank}-${change.title}`}>
                      <span className="suspect-rank">
                        {String(change.rank).padStart(2, "0")}
                      </span>
                      <div>
                        <div className="suspect-title">
                          <h3>{change.title}</h3>
                          <Confidence value={change.confidence} />
                        </div>
                        <p>{change.explanation}</p>
                        <div className="suspect-next">
                          <span>Recommended next check</span>
                          <p>{change.nextStep}</p>
                        </div>
                        <ul>
                          {change.evidence.map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                    </article>
                  ))
                ) : (
                  <article className="suspect comparison-empty">
                    <span className="suspect-rank">00</span>
                    <div>
                      <h3>No material structural difference detected</h3>
                      <p>
                        Compare console, WebSocket, DRM/EME, DOM, or private
                        response semantics next; those signals can sit outside HAR.
                      </p>
                    </div>
                  </article>
                )}
              </div>
            </section>
          </div>

          <aside className="report-side">
            <section className="report-card privacy-card">
              <header className="card-header compact">
                <div>
                  <span className="card-index">02</span>
                  <h2>Privacy sweep</h2>
                </div>
              </header>
              <p className="comparison-side-copy">
                The two raw traces contain {comparison.findingCount} detected
                sensitive location{comparison.findingCount === 1 ? "" : "s"}.
                ReqRescue compared redacted URLs and query-key names—not their
                values.
              </p>
              <div className="comparison-downloads">
                <button onClick={() => exportSanitized(baseline, "a")}>
                  Download clean capture A
                </button>
                <button onClick={() => exportSanitized(changed, "b")}>
                  Download clean capture B
                </button>
              </div>
              <p className="privacy-warning">
                Always review exports for product-specific identifiers before
                sharing.
              </p>
            </section>

            <section className="report-card export-card">
              <header className="card-header compact">
                <div>
                  <span className="card-index">03</span>
                  <h2>Hand it off</h2>
                </div>
              </header>
              <button onClick={copyReport}>
                <span>
                  <b>Copy A/B bug report</b>
                  <small>Markdown · ranked differences · ReqRescue footer</small>
                </span>
                <em>{copied ? "Copied" : "Copy"}</em>
              </button>
              <button onClick={exportReport}>
                <span>
                  <b>Download comparison</b>
                  <small>Ready for GitHub, Jira, Slack, or email</small>
                </span>
                <em>MD</em>
              </button>
            </section>

            <section className="report-card pilot-card">
              <span>ReqRescue accepts no donations</span>
              <h2>Saved time? Help a cat instead.</h2>
              <p>
                Donate directly to a real animal organization. We receive
                nothing.
              </p>
              <a
                className="button button-primary"
                href="https://isracats.org.il/donation/"
                target="_blank"
                rel="noreferrer"
                onClick={() => void track("cat_charity_click", "comparison")}
              >
                Help cats in Israel ↗
              </a>
            </section>
          </aside>
        </section>

        <section className="report-disclaimer">
          <b>What this comparison is:</b> deterministic structural diff of two
          sanitized HARs. <b>What it is not:</b> proof that the highest-ranked
          difference caused the symptom.
        </section>

        <section className="report-signature" aria-label="ReqRescue report attribution">
          <span className="report-signature-mark" aria-hidden="true">
            R
          </span>
          <div>
            <small>Comparison generated locally by</small>
            <b>ReqRescue</b>
          </div>
          <a href="https://app.reqrescue.workers.dev">
            Compare another pair ↗
          </a>
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
      <nav aria-label="Legal and project links">
        <a href="/privacy">Privacy</a>
        <a href="/terms">Terms</a>
        <a href={GITHUB_URL} target="_blank" rel="noreferrer">
          Source
        </a>
      </nav>
    </footer>
  );
}

export default function Home() {
  const [view, setView] = useState<View>("landing");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [comparison, setComparison] = useState<HarComparison | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyMessage, setBusyMessage] = useState("");
  const [error, setError] = useState("");
  const [historyOpen, setHistoryOpen] = useState(false);
  const [history, setHistory] = useState<StoredCase[]>([]);
  const activeJobRef = useRef<ActiveJob | null>(null);

  useEffect(() => {
    document.documentElement.dataset.reqrescueReady = "true";
    void track("page_view", acquisitionSource());
    const initialization = window.setTimeout(() => {
      setHistory(loadHistory());
    }, 0);
    return () => {
      delete document.documentElement.dataset.reqrescueReady;
      window.clearTimeout(initialization);
      const job = activeJobRef.current;
      if (job?.timer) window.clearTimeout(job.timer);
      job?.worker?.terminate();
    };
  }, []);

  const finish = useCallback((next: Analysis, source: "file" | "demo") => {
    setAnalysis(next);
    setComparison(null);
    setView("report");
    setBusy(false);
    setBusyMessage("");
    setError("");
    window.scrollTo({ top: 0, behavior: "instant" });
    void track("analysis_complete", source);
  }, []);

  const finishComparison = useCallback((next: HarComparison) => {
    setComparison(next);
    setAnalysis(null);
    setView("comparison");
    setBusy(false);
    setBusyMessage("");
    setError("");
    window.scrollTo({ top: 0, behavior: "instant" });
    void track("comparison_complete", "file");
  }, []);

  const handleFile = useCallback(
    async (file: File) => {
      setError("");
      if (file.size > MAX_FILE_BYTES) {
        setError(
          "The protected local limit is 75 MB. Larger files need a future streaming parser.",
        );
        return;
      }
      const job: ActiveJob = { cancelled: false };
      activeJobRef.current?.worker?.terminate();
      activeJobRef.current = job;
      setBusy(true);
      setBusyMessage("Reading the HAR locally…");
      try {
        const buffer = await file.arrayBuffer();
        if (job.cancelled) return;

        const worker = new Worker(new URL("./har.worker.ts", import.meta.url), {
          type: "module",
        });
        job.worker = worker;
        const next = await new Promise<Analysis>((resolve, reject) => {
          job.cancelPromise = () => reject(new Error("Local analysis canceled."));
          worker.onmessage = (event: MessageEvent<HarWorkerMessage>) => {
            if (job.cancelled) return;
            if (event.data.type === "progress") {
              setBusyMessage(event.data.message);
            } else if (event.data.type === "complete") {
              resolve(event.data.analysis);
            } else if (event.data.type === "error") {
              reject(new Error(event.data.message));
            }
          };
          worker.onerror = () => {
            reject(new Error("The local analysis worker stopped unexpectedly."));
          };
          worker.postMessage(
            {
              type: "analyze",
              buffer,
              sourceName: file.name,
            },
            [buffer],
          );
        });
        worker.terminate();
        if (job.cancelled) return;
        activeJobRef.current = null;
        finish(next, "file");
      } catch (reason) {
        job.worker?.terminate();
        if (job.cancelled) return;
        activeJobRef.current = null;
        setBusy(false);
        setBusyMessage("");
        setError(reason instanceof Error ? reason.message : "Unknown parsing error.");
        void track("analysis_error");
      }
    },
    [finish],
  );

  const handleCompare = useCallback(
    async (files: File[]) => {
      setError("");
      if (files.length !== 2) {
        setError(
          "Choose exactly two HAR files: capture A (baseline) first, then capture B (changed or broken).",
        );
        return;
      }
      if (files.some((file) => file.size > MAX_FILE_BYTES)) {
        setError(
          "Each HAR must stay within the protected 75 MB local limit.",
        );
        return;
      }

      const [baselineFile, changedFile] = files;
      const job: ActiveJob = { cancelled: false };
      activeJobRef.current?.worker?.terminate();
      activeJobRef.current = job;
      setBusy(true);
      setBusyMessage("Reading capture A locally…");

      try {
        const [baselineBuffer, changedBuffer] = await Promise.all([
          baselineFile.arrayBuffer(),
          changedFile.arrayBuffer(),
        ]);
        if (job.cancelled) return;

        const worker = new Worker(new URL("./har.worker.ts", import.meta.url), {
          type: "module",
        });
        job.worker = worker;
        const next = await new Promise<HarComparison>((resolve, reject) => {
          job.cancelPromise = () => reject(new Error("Local comparison canceled."));
          worker.onmessage = (event: MessageEvent<HarWorkerMessage>) => {
            if (job.cancelled) return;
            if (event.data.type === "progress") {
              setBusyMessage(event.data.message);
            } else if (event.data.type === "comparison-complete") {
              resolve(event.data.comparison);
            } else if (event.data.type === "error") {
              reject(new Error(event.data.message));
            }
          };
          worker.onerror = () => {
            reject(new Error("The local comparison worker stopped unexpectedly."));
          };
          worker.postMessage(
            {
              type: "compare",
              baselineBuffer,
              baselineName: baselineFile.name,
              changedBuffer,
              changedName: changedFile.name,
            },
            [baselineBuffer, changedBuffer],
          );
        });
        worker.terminate();
        if (job.cancelled) return;
        activeJobRef.current = null;
        finishComparison(next);
      } catch (reason) {
        job.worker?.terminate();
        if (job.cancelled) return;
        activeJobRef.current = null;
        setBusy(false);
        setBusyMessage("");
        setError(
          reason instanceof Error ? reason.message : "Unknown comparison error.",
        );
        void track("comparison_error");
      }
    },
    [finishComparison],
  );

  const handleDemo = useCallback(() => {
    const job: ActiveJob = { cancelled: false };
    activeJobRef.current?.worker?.terminate();
    activeJobRef.current = job;
    setBusy(true);
    setBusyMessage("Building the synthetic local demo…");
    setError("");
    job.timer = window.setTimeout(() => {
      if (job.cancelled) return;
      try {
        activeJobRef.current = null;
        finish(analyzeHar(buildDemoHar(), "broken-checkout-demo.har"), "demo");
      } catch (reason) {
        activeJobRef.current = null;
        setBusy(false);
        setBusyMessage("");
        setError(reason instanceof Error ? reason.message : "Demo failed to load.");
      }
    }, 380);
  }, [finish]);

  const cancelAnalysis = useCallback(() => {
    const job = activeJobRef.current;
    if (!job) return;
    job.cancelled = true;
    if (job.timer) window.clearTimeout(job.timer);
    job.worker?.terminate();
    job.cancelPromise?.();
    activeJobRef.current = null;
    setBusy(false);
    setBusyMessage("");
    setError("Local analysis canceled. No trace data left this browser.");
    void track("analysis_cancelled");
  }, []);

  const reset = () => {
    setView("landing");
    setAnalysis(null);
    setComparison(null);
    setBusy(false);
    setBusyMessage("");
    setError("");
    window.scrollTo({ top: 0, behavior: "instant" });
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
    if (!storageSet(HISTORY_STORAGE_KEY, JSON.stringify(next))) {
      throw new Error("This browser could not save the case locally.");
    }
    setHistory(next);
    void track("case_saved");
  };

  return (
    <>
      {view === "report" && analysis ? (
        <Report
          analysis={analysis}
          onReset={reset}
          onOpenHistory={() => setHistoryOpen(true)}
          onSaveCase={saveCaseToHistory}
        />
      ) : view === "comparison" && comparison ? (
        <ComparisonReport
          comparison={comparison}
          onReset={reset}
          onOpenHistory={() => setHistoryOpen(true)}
        />
      ) : (
        <Landing
          busy={busy}
          busyMessage={busyMessage}
          error={error}
          onFile={handleFile}
          onCompare={handleCompare}
          onDemo={handleDemo}
          onCancel={cancelAnalysis}
          maxFileBytes={MAX_FILE_BYTES}
          onOpenHistory={() => setHistoryOpen(true)}
        />
      )}
      <HistoryModal
        open={historyOpen}
        history={history}
        onClose={() => setHistoryOpen(false)}
      />
    </>
  );
}
