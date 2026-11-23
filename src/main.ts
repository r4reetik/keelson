// Starts Keelson: store, scanner, scheduler and HTTP server. The CLI parses
// options and calls this; the mock dev server calls it with seeded accounts.

import { existsSync } from "node:fs";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { serve } from "@hono/node-server";
import { Store } from "./store/db.ts";
import { Repo } from "./store/repo.ts";
import { Scanner } from "./scanner.ts";
import { startScheduler } from "./scheduler.ts";
import { createApp } from "./server/app.ts";
import { Auth } from "./server/security.ts";
import { TokenVault } from "./config.ts";
import { importLegacy } from "./store/legacy.ts";
import { log } from "./log.ts";
import { REPOSITORY, VERSION } from "./meta.ts";
import { UpdateChecker } from "./updates.ts";
import { env, installKind } from "./env.ts";
import { net } from "./core/net.ts";
import { routeFor } from "./networks.ts";

export { VERSION } from "./meta.ts";

export interface StartOptions {
  host: string;
  port: number;
  /** Where the database and credentials live; null keeps everything in memory. */
  dataDir: string | null;
  /** No sign-in: an authenticating proxy sits in front and decides who gets in (KEELSON_AUTH=none). */
  insecureNoAuth: boolean;
  trustProxy: boolean;
  allowedHosts: string[];
  /** Run the daily scan schedule (off for the mock dev server). */
  schedule?: boolean;
  /** Check GitHub for newer releases, if Settings allow (off for the mock dev server). */
  updateCheck?: boolean;
  /** Called with the URL once the server is listening. */
  onListening?: (url: string, ctx: Running) => void;
}

export interface Running {
  url: string;
  repo: Repo;
  vault: TokenVault;
  scanner: Scanner;
  auth: Auth;
  close: () => Promise<void>;
}

export const isLoopback = (host: string) => ["127.0.0.1", "localhost", "::1"].includes(host);

const everyInterface = (host: string) => host === "0.0.0.0" || host === "::";

/**
 * Where other machines on the network open a server that listens on every interface: one URL per IPv4
 * address of this machine. IPv6 addresses are left out: the ones a laptop has are mostly link-local,
 * which a browser can't open. Empty for a server bound to one address, whose own URL already says it.
 */
export function networkUrls(host: string, port: number, interfaces: ReturnType<typeof networkInterfaces> = networkInterfaces()): string[] {
  if (!everyInterface(host)) return [];
  const addresses = Object.values(interfaces)
    .flatMap((list) => list || [])
    .filter((a) => a.family === "IPv4" && !a.internal)
    .map((a) => a.address);
  return [...new Set(addresses)].map((a) => `http://${a}:${port}`);
}

/** The built web UI, next to the compiled server or in dist/ when running from source. */
function findWebDir(): string | null {
  const here = fileURLToPath(new URL(".", import.meta.url));
  return [join(here, "web"), join(here, "..", "dist", "web")].find((d) => existsSync(join(d, "index.html"))) || null;
}

export async function start(o: StartOptions): Promise<Running> {
  const vault = new TokenVault(o.dataDir);
  const store = new Store(o.dataDir ? join(o.dataDir, "keelson.db") : ":memory:", { log: log.info });
  const repo = new Repo(store);
  repo.scans.recoverInterrupted();
  if (o.dataDir) importLegacy(o.dataDir, repo, vault, log.info);

  // Outside a scan (update checks, alerts, vulnerability catalogs) requests take the Networks page's default route.
  net.defaultRoute = () => routeFor(repo, vault, null);
  const scanner = new Scanner(repo, vault, log.info, { toolDir: o.dataDir ? join(o.dataDir, "tools") : null });
  const auth = new Auth(
    {
      insecureNoAuth: o.insecureNoAuth,
      loopback: isLoopback(o.host),
      trustProxy: o.trustProxy,
      allowedHosts: o.allowedHosts,
    },
    repo.users,
  );
  const updates =
    o.updateCheck === false
      ? undefined
      : new UpdateChecker({
          version: VERSION,
          repository: REPOSITORY,
          install: installKind(),
          lockedOff: env("UPDATE_CHECK") === "off",
          enabled: () => repo.settings.get().updates.check,
          log: log.info,
        });
  const app = createApp({ repo, scanner, auth, vault, webDir: findWebDir(), version: VERSION, updates });
  const stopScheduler = o.schedule === false ? () => {} : startScheduler(repo, scanner, log.info);
  const stopUpdates = updates ? updates.start() : () => {};

  return new Promise((resolve, reject) => {
    const server = serve({ fetch: app.fetch, hostname: o.host, port: o.port }, () => {
      const shown = everyInterface(o.host) ? "localhost" : o.host.includes(":") ? `[${o.host}]` : o.host;
      const running: Running = {
        url: `http://${shown}:${o.port}`,
        repo,
        vault,
        scanner,
        auth,
        close: () =>
          new Promise<void>((done) => {
            stopScheduler();
            stopUpdates();
            server.close(() => {
              net.defaultRoute = () => null;
              store.close();
              done();
            });
          }),
      };
      o.onListening?.(running.url, running);
      resolve(running);
    });
    server.on("error", (e: NodeJS.ErrnoException) => {
      stopScheduler();
      stopUpdates();
      reject(e.code === "EADDRINUSE" ? new Error(`Port ${o.port} is already in use. Pick another with --port.`) : e);
    });
  });
}

/** True when the web UI build is missing (shown as a startup warning). */
export const webMissing = () => !findWebDir();
