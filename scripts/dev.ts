// One command for local development: the API server (real or mocked
// provider data) plus the Vite dev server with hot reload.
//   npm run dev            real accounts, data in ./.keelson
//   npm run dev -- --mock  mocked provider APIs, nothing written to disk
//   npm run dev -- --mock --signup  the same, starting at the admin sign-up instead of with mock users
//   npm run dev -- --host  either of them, reachable from other machines on your network (--host <addr> for one address)

import { spawn, type ChildProcess } from "node:child_process";
import { devHost } from "./dev-host.ts";

const mock = process.argv.includes("--mock");
const dataDir = ".keelson";
const server = mock
  ? ["--watch", "dev/mock/server.ts", ...process.argv.slice(2).filter((a) => a === "--signup")]
  : ["--watch", "src/bin.ts", "--no-open", "--data-dir", dataDir];
// Both servers read the address from KEELSON_HOST, so the API and the page that proxies to it are shared together or not at all.
const host = devHost(process.argv.slice(2));
const env = host ? { ...process.env, KEELSON_HOST: host } : process.env;
const children: ChildProcess[] = [
  spawn(process.execPath, server, { stdio: "inherit", env }),
  spawn(process.execPath, ["node_modules/vite/bin/vite.js", "--config", "web/vite.config.ts"], { stdio: "inherit", env }),
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
