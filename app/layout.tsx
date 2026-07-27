import type { Metadata, Viewport } from "next";
import "./globals.css";

const siteUrl = "https://app.reqrescue.workers.dev";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: "ReqRescue — Free local HAR analyzer, sanitizer & incident brief",
  description:
    "Analyze and sanitize HAR files locally. Rank likely failures, remove tokens and cookies, export a clean HAR, and create a developer-ready bug report. Free, no upload, no account.",
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
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "32x32" },
      { url: "/favicon.svg", type: "image/svg+xml" },
    ],
    shortcut: "/favicon.svg",
  },
  openGraph: {
    title: "ReqRescue — Stop sending raw traces",
    description:
      "Analyze and sanitize a browser HAR locally, then turn it into ranked evidence and a developer-ready incident report.",
    url: siteUrl,
    siteName: "ReqRescue",
    type: "website",
    images: ["/social-card.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "ReqRescue — Stop sending raw traces",
    description:
      "Local-first HAR triage, secret scrubbing, and evidence-backed bug reports.",
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
      <body>{children}</body>
    </html>
  );
}
