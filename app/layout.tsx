import type { Metadata, Viewport } from "next";
import "./globals.css";

const siteUrl = "https://app.reqrescue.workers.dev";
const structuredData = {
  "@context": "https://schema.org",
  "@type": ["SoftwareApplication", "WebApplication"],
  name: "ReqRescue",
  url: siteUrl,
  applicationCategory: "DeveloperApplication",
  applicationSubCategory: "Web debugging and incident response",
  operatingSystem: "Any",
  browserRequirements: "Requires a modern browser with Web Worker support",
  isAccessibleForFree: true,
  description:
    "A browser-local tool that turns a failed web session into ranked evidence, removes common secrets, and creates a clean HAR plus a developer-ready bug report.",
  featureList: [
    "Local browser-only HAR analysis",
    "Cookie, token, email, IP address, and request-body redaction",
    "Evidence-backed failure ranking",
    "Sanitized HAR export",
    "Markdown incident report export",
  ],
  offers: {
    "@type": "Offer",
    price: "0",
    priceCurrency: "USD",
  },
  codeRepository: "https://github.com/hannadevtools/reqrescue",
  license: "https://opensource.org/license/mit",
};
const structuredDataJson = JSON.stringify(structuredData).replace(
  /</g,
  "\\u003c",
);

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: "ReqRescue — Turn browser failures into safe bug reports",
  description:
    "A website broke? Drop its browser network recording (HAR), find likely failure points, remove common secrets, and create a ready-to-send bug report. Free and local.",
  applicationName: "ReqRescue",
  keywords: [
    "HAR analyzer",
    "HAR file analyzer",
    "network debugging",
    "HAR sanitizer",
    "sanitize HAR file",
    "safe HAR sharing",
    "bug report generator",
    "incident brief",
    "web support",
  ],
  alternates: {
    canonical: "/",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
      "max-video-preview": -1,
    },
  },
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "32x32" },
      { url: "/favicon.svg", type: "image/svg+xml" },
    ],
    shortcut: "/favicon.svg",
  },
  openGraph: {
    title: "ReqRescue — Turn browser failures into safe bug reports",
    description:
      "Find likely failure points, remove common secrets, and create a ready-to-send bug report. The browser recording never leaves your tab.",
    url: siteUrl,
    siteName: "ReqRescue",
    type: "website",
    images: ["/social-card.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "ReqRescue — Turn browser failures into safe bug reports",
    description:
      "Turn a failed web session into clean evidence and a bug report your engineer can use.",
    images: ["/social-card.png"],
  },
};

export const viewport: Viewport = {
  themeColor: "#f3f0e8",
  colorScheme: "light",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        {children}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: structuredDataJson }}
        />
      </body>
    </html>
  );
}
