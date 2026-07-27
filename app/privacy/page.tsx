import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Privacy — ReqRescue",
  description: "What ReqRescue processes locally and what its hosted service records.",
};

export default function PrivacyPage() {
  return (
    <main className="legal-shell">
      <nav>
        <Link href="/" aria-label="Back to ReqRescue">
          ← ReqRescue
        </Link>
      </nav>
      <article>
        <p className="eyebrow">
          <span>Privacy</span>
          <i />
        </p>
        <h1>Your HAR stays in your browser.</h1>
        <p className="legal-lead">
          ReqRescue is designed so its hosted server does not need your trace in
          order to analyze it.
        </p>

        <h2>Local trace processing</h2>
        <p>
          HAR reading, validation, triage, redaction, previews, reports, and
          exports run locally in a browser worker. ReqRescue does not send HAR
          contents, file names, URLs, headers, cookies, bodies, or generated
          reports to its application server.
        </p>

        <h2>Product events</h2>
        <p>
          The hosted build records a small allowlist of product events, such as
          opening the page, completing the demo, or exporting a report. Each
          event may contain a random pseudonymous session identifier stored in
          your browser, an acquisition source, or optional feedback you choose
          to type. Feedback is limited to 220 characters. Do not place secrets
          or personal data in feedback.
        </p>

        <h2>Supporter verification and local storage</h2>
        <p>
          If you verify an honorware purchase, your entered license key is sent
          directly from your browser to Gumroad. ReqRescue does not receive the
          key. The unlock flag, pseudonymous session identifier, and any saved
          incident briefs remain in this browser&apos;s local storage until you
          clear site data.
        </p>

        <h2>Hosting records</h2>
        <p>
          Cloudflare may process ordinary technical request data needed to
          serve and protect the website, such as IP address, user agent, and
          request timing, under its own infrastructure policies. That is
          separate from HAR processing, which remains local.
        </p>

        <h2>Redaction limitations</h2>
        <p>
          No automated sanitizer can recognize every private value or
          product-specific identifier. ReqRescue removes bodies, credentials,
          common secrets, private hosts, IP addresses, and unknown vendor
          fields, but you must review a sanitized export before sharing it.
        </p>

        <p className="legal-updated">Last updated: July 27, 2026.</p>
      </article>
    </main>
  );
}
