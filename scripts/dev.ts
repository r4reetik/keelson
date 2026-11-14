// One command for local development: the API server (real or mocked
// provider data) plus the Vite dev server with hot reload.
//   npm run dev            real accounts, data in ./.keelson
//   npm run dev -- --mock  mocked provider APIs, nothing written to disk
//   npm run dev -- --mock --signup  the same, starting at the admin sign-up instead of with mock users

import { spawn, type ChildProcess } from "node:child_process";

const mock = process.argv.includes("--mock");
const dataDir = ".keelson";
const server = mock
  ? ["--watch", "dev/mock/server.ts", ...process.argv.slice(2).filter((a) => a === "--signup")]
  : ["--watch", "src/bin.ts", "--no-open", "--data-dir", dataDir];
const children: ChildProcess[] = [
  spawn(process.execPath, server, { stdio: "inherit" }),
  spawn(process.execPath, ["node_modules/vite/bin/vite.js", "--config", "web/vite.config.ts"], { stdio: "inherit" }),
];
const stop = () => {
  for (const c of children) c.kill("SIGTERM");
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
for (const c of children)
  c.on("exit", (code) => {
    stop();
    process.exitCode ||= code ?? 0;
  });
