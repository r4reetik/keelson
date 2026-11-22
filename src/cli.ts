// The command line: starts the server, and opens the browser when run from a
// clone on your own machine. Started by bin.ts once it has checked the Node.js version.

import "./warnings.ts";
import { parseArgs, type ParseArgsConfig } from "node:util";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

const { start, isLoopback, networkUrls, webMissing, VERSION } = await import("./main.ts");
const { defaultDataDir, defaultHost, env } = await import("./env.ts");
const { providerList } = await import("./shared/providers.ts");

const HELP = `Keelson ${VERSION}: security posture tracker for ${providerList()}

Usage: keelson [options]

Options:
  --port <n>            Port to listen on (default 4317, env KEELSON_PORT)
  --host <addr>         Address to bind (default 127.0.0.1, 0.0.0.0 in the image, env KEELSON_HOST);
                        0.0.0.0 lets everyone on your network open it
  --data-dir <path>     Where the database and credentials live (default ~/.keelson, /data in the image, env KEELSON_DATA_DIR)
  --reset-password <u>  Give user <u> a one-time password and exit, for someone locked out
  --trust-proxy         Trust X-Forwarded-* headers from a reverse proxy (env KEELSON_TRUST_PROXY=1)
  --no-open             Don't open the browser
  -v, --version         Print the version
  -h, --help            Show this help

Environment only:
  KEELSON_AUTH=none          No sign-in at all, because an authenticating proxy (for example
                             Cloudflare Access) sits in front; everyone who gets through is an admin
  KEELSON_ALLOWED_HOSTS=a,b  Extra hostnames accepted in local mode
  KEELSON_LOG=json           Log one JSON object per line
  KEELSON_UPDATE_CHECK=off   Never check GitHub for new releases

The first time you open Keelson you create the admin account; off this machine that needs the setup
code Keelson prints when it starts. The admin adds everyone else on the Users page. Accounts on every
platform are added in the browser. Credentials are stored in <data-dir>/credentials.json, readable by
your user only.

Docs: https://github.com/r4reetik/keelson#readme`;

const { values: args } = parseOptions({
  options: {
    port: { type: "string" },
    host: { type: "string" },
    "data-dir": { type: "string" },
    "reset-password": { type: "string" },
    "trust-proxy": { type: "boolean" },
    "no-open": { type: "boolean" },
    version: { type: "boolean", short: "v" },
    help: { type: "boolean", short: "h" },
  },
  strict: true,
});

/** parseArgs, with a one-line message instead of a stack trace for a mistyped flag. */
function parseOptions<T extends ParseArgsConfig>(config: T): ReturnType<typeof parseArgs<T>> {
  try {
    return parseArgs(config);
  } catch (e) {
    fail(`${(e as Error).message.replace(/\. To specify.*/s, "")}. Run keelson --help for the options.`);
  }
}

if (args.help) {
  console.log(HELP);
  process.exit(0);
}
if (args.version) {
  console.log(VERSION);
  process.exit(0);
}

const host = args.host || defaultHost();
const portText = String(args.port || env("PORT") || process.env.PORT || 4317);
const port = Number(portText);
const dataDir = resolve(args["data-dir"] || defaultDataDir());
const loopback = isLoopback(host);
const insecureNoAuth = env("AUTH") === "none";

if (args["reset-password"] !== undefined) await resetPassword(String(args["reset-password"]));
if (!Number.isInteger(port) || port < 1 || port > 65535) fail(`Invalid port: ${portText}`);

const running = await start({
  host,
  port,
  dataDir,
  insecureNoAuth,
  trustProxy: !!args["trust-proxy"] || env("TRUST_PROXY") === "1",
  allowedHosts: (env("ALLOWED_HOSTS") || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
}).catch((e: NodeJS.ErrnoException) =>
  fail(e.code === "EACCES" || e.code === "EROFS" || e.code === "EPERM" ? `${e.message}. Choose a writable directory with --data-dir.` : e.message),
);

const accounts = running.repo.accounts.list(),
  entities = running.repo.entities.list();
const users = running.repo.users.count();
// In the image these would be the container's own addresses, which nobody outside it can open.
const shared = env("INSTALL") === "docker" ? [] : networkUrls(host, port);
const label = (name: string) => `  ${`${name}:`.padEnd(shared.length ? 10 : 7)}`;
console.log(
  `\n  Keelson ${VERSION}\n\n${label("Open")}${running.url}\n${shared.map((url) => `${label("Network")}${url}\n`).join("")}${label("Data")}${dataDir}\n${label("Auth")}${insecureNoAuth ? "none (sign-in is off: your proxy decides who gets in)" : users ? `sign-in, ${users} user${users === 1 ? "" : "s"}` : "sign-in, no users yet"}\n`,
);
const code = running.auth.setupCode;
if (code) {
  // Off loopback (and always in the container) the browser isn't on this machine as far as Keelson can tell.
  console.log(
    loopback
      ? "  No admin yet: open the URL to create the admin account.\n"
      : `  No admin yet: open the URL to create the admin account, with this setup code:\n\n      ${code}\n\n  It works once, until the admin exists.\n`,
  );
} else if (!accounts.length) console.log(`  No accounts yet: sign in to connect ${providerList(undefined, "or")}.\n`);
else
  console.log(`  Watching ${accounts.length} account${accounts.length === 1 ? "" : "s"} in ${entities.length} entit${entities.length === 1 ? "y" : "ies"}.\n`);
if (env("PASSWORD")) console.log("  Note: KEELSON_PASSWORD is no longer read. Keelson has user accounts now: sign in as the admin, who adds everyone else.\n");
if (process.env.CLOUDFLARE_API_TOKEN) console.log("  Note: CLOUDFLARE_API_TOKEN is no longer read. Add accounts in the browser instead.\n");
if (webMissing()) console.log("  Warning: web UI not found. Run `npm run build:web`.\n");
if (!args["no-open"] && loopback && process.stdout.isTTY) openBrowser(running.url);

let stopping = false;
for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    if (stopping) process.exit(1);
    stopping = true;
    void running.close().then(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  });
}

function openBrowser(url: string) {
  const [cmd, argv] = process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  try {
    spawn(cmd, argv as string[], { stdio: "ignore", detached: true })
      .on("error", () => {})
      .unref();
  } catch {
    /* no browser available */
  }
}

/** For someone locked out, the last admin included: a one-time password they replace when they sign in. */
async function resetPassword(name: string): Promise<never> {
  const { Store } = await import("./store/db.ts");
  const { Repo } = await import("./store/repo.ts");
  const { hashPassword, oneTimePassword } = await import("./server/passwords.ts");
  const file = join(dataDir, "keelson.db");
  if (!existsSync(file)) fail(`No Keelson data in ${dataDir}. Pass the data folder with --data-dir.`);
  const repo = new Repo(new Store(file));
  const user = repo.users.byUsername(name.trim());
  if (!user) {
    const known = repo.users.list().map((u) => u.username);
    fail(known.length ? `No user named ${name}. Users: ${known.join(", ")}.` : "Nobody has an account yet: open Keelson to create the admin.");
  }
  const password = oneTimePassword();
  repo.users.setPassword(user.id, await hashPassword(password), true);
  repo.store.close();
  console.log(`One-time password for ${user.username}:\n\n    ${password}\n\nThey choose a new password when they sign in with it.`);
  process.exit(0);
}

function fail(msg: string): never {
  console.error(`keelson: ${msg}`);
  process.exit(1);
}
