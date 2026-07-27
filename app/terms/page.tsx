import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Terms — ReqRescue",
  description: "Terms for using the ReqRescue hosted HAR analysis tool.",
};

export default function TermsPage() {
  return (
    <main className="legal-shell">
      <nav>
        <Link href="/" aria-label="Back to ReqRescue">
          ← ReqRescue
        </Link>
      </nav>
      <article>
        <p className="eyebrow">
          <span>Terms</span>
          <i />
        </p>
        <h1>Use the evidence. Verify the conclusion.</h1>
        <p className="legal-lead">
          ReqRescue is a debugging aid, not proof of a production root cause or
          a guarantee that an export is risk-free.
        </p>

        <h2>Service</h2>
        <p>
          ReqRescue provides deterministic HAR validation, triage, redaction,
          and report generation. It may identify likely causes from captured
          network evidence, but application and server logs are often required
          to establish the actual root cause.
        </p>

        <h2>Your responsibilities</h2>
        <p>
          Only analyze traces you are authorized to inspect. Review every
          sanitized export before sharing it, comply with your organization&apos;s
          data-handling rules, and do not paste secrets or personal information
          into the feedback field.
        </p>

        <h2>Honorware support</h2>
        <p>
          Core analysis, sanitization, clean HAR export, Markdown export, and
          source code remain free. A voluntary one-time $12 purchase supports
          the hosted service and unlocks local convenience features. It is not
          a subscription. Refund requests are handled through Gumroad and are
          eligible within 30 days of purchase.
        </p>

        <h2>Local data</h2>
        <p>
          Saved cases and the Supporter unlock live in browser storage. Clearing
          site data, changing browser profiles, or using private browsing can
          remove them. Keep your Gumroad receipt if you need to reactivate.
        </p>

        <h2>No warranty</h2>
        <p>
          The service and open-source software are provided as-is, without
          warranties of accuracy, availability, fitness for a particular
          purpose, or complete removal of sensitive data. To the extent
          permitted by law, the maintainers are not liable for indirect or
          consequential losses arising from its use.
        </p>

        <p className="legal-updated">Last updated: July 27, 2026.</p>
      </article>
    </main>
  );
}
