const ROBOTS = `User-agent: *
Allow: /

Sitemap: https://reqrescue.funt1k.chatgpt.site/sitemap.xml
`;

export async function GET() {
  return new Response(ROBOTS, {
    headers: {
      "cache-control": "public, max-age=3600",
      "content-type": "text/plain; charset=utf-8",
    },
  });
}
