// An app instance over an in-memory store and a temporary data directory, with
// helpers to call it like the browser does. By default an admin is signed in;
// `as(role)` gives helpers signed in as a user with another role, and
// `{ user: null }` starts with nobody, for creating the first admin.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../../src/store/db.ts";
import { Repo } from "../../src/store/repo.ts";
import { Scanner } from "../../src/scanner.ts";
import { createApp } from "../../src/server/app.ts";
import { Auth } from "../../src/server/security.ts";
import { hashPasswordSync } from "../../src/server/passwords.ts";
import { TokenVault } from "../../src/config.ts";
import type { Role } from "../../src/shared/roles.ts";
import { seedAccount } from "../../dev/mock/accounts.ts";

export const PASSWORD = "correct horse battery staple";
const HASH = hashPasswordSync(PASSWORD);

type Init = RequestInit & { host?: string; anonymous?: boolean };

export function makeApp({ configured = false, trustProxy = false, user = "admin" as Role | null, loopback = true, insecureNoAuth = false } = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), "keelson-test-"));
  const webDir = join(dataDir, "web");
  mkdirSync(join(webDir, "assets"), { recursive: true });
  writeFileSync(join(webDir, "index.html"), "<!doctype html><title>Keelson</title>");
  writeFileSync(join(webDir, "assets", "app.js"), "console.log(1)");
  writeFileSync(join(dataDir, "secret.txt"), "do not serve");
  const repo = new Repo(new Store(":memory:"));
  repo.settings.save({ ...repo.settings.get(), probes: { takeover: false } });
  const vault = new TokenVault(dataDir);
  if (configured) seedAccount(repo, vault);
  const scanner = new Scanner(repo, vault, () => {});
  const auth = new Auth({ insecureNoAuth, loopback, trustProxy, allowedHosts: [] }, repo.users);
  const app = createApp({ repo, scanner, auth, vault, webDir, version: "test" });

  /** A session cookie for a user with this role, named after it (created the first time). */
  const sessionFor = (role: Role) => {
    const u =
      repo.users.byUsername(role) ?? repo.users.create({ username: role, name: null, role, passwordHash: HASH, mustChangePassword: false, createdBy: null });
    return `keelson_session=${auth.startSession(u.id)}`;
  };
  const helpers = (cookie: string | null) => {
    const call = (path: string, init: Init = {}) =>
      app.request(path, {
        ...init,
        headers: {
          host: init.host || "127.0.0.1:4317",
          ...(init.body ? { "content-type": "application/json" } : {}),
          ...(cookie && !init.anonymous ? { cookie } : {}),
          ...(init.headers || {}),
        },
      });
    const json = async (path: string, method = "GET", body?: unknown) =>
      (await call(path, { method, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) })).json() as Promise<any>;
    return { call, json };
  };
  const { call, json } = helpers(user ? sessionFor(user) : null);
  return {
    app,
    call,
    json,
    /** call and json, signed in as a user with this role. */
    as: (role: Role) => helpers(sessionFor(role)),
    repo,
    vault,
    scanner,
    auth,
    dataDir,
    cleanup: () => rmSync(dataDir, { recursive: true, force: true }),
  };
}
