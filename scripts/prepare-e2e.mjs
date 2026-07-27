import { spawnSync } from "node:child_process";

if (process.env.CI) {
  const command = process.platform === "win32" ? "npx.cmd" : "npx";
  const result = spawnSync(
    command,
    ["playwright", "install", "--with-deps", "chromium"],
    { stdio: "inherit" },
  );

  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
