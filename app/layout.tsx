import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ReqRescue — Turn a HAR into an actionable incident brief",
  description:
    "Local-first HAR triage that ranks likely causes, scrubs secrets, and generates a developer-ready bug report. No upload and no account.",
  applicationName: "ReqRescue",
  keywords: [
    "HAR analyzer",
    "network debugging",
    "HAR sanitizer",
    "bug report generator",
    "web support",
  ],
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
  openGraph: {
    title: "ReqRescue — Stop sending raw traces",
    description:
      "Turn a browser HAR into a ranked diagnosis, a scrubbed evidence file, and an actionable bug report—in your browser.",
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
