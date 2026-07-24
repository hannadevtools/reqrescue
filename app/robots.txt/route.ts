const ROBOTS = `User-agent: *
Allow: /

Sitemap: https://app.reqrescue.workers.dev/sitemap.xml
`;

export async function GET() {
  return new Response(ROBOTS, {
    headers: {
      "cache-control": "public, max-age=3600",
      "content-type": "text/plain; charset=utf-8",
    },
  });
}
