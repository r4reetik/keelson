// Users and roles: creating the first admin (with the setup code off this
// machine), what each role may change, user management, one-time passwords,
// and sign-in turned off behind a proxy.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { Hono } from "hono";
import { installMockCloudflare, MOCK_ACCOUNT } from "../dev/mock/cloudflare.ts";
import { makeApp, PASSWORD } from "./helpers/app.ts";
import { routes } from "../src/server/router.ts";
import { anyone, requirePermission } from "../src/server/middleware.ts";
import { can, PERMISSION_ROLE, ROLES, type Permission, type Role } from "../src/shared/roles.ts";
import type { AppEnv } from "../src/server/env.ts";

let restore: () => void;
before(() => {
  restore = installMockCloudflare();
});
after(() => restore());

const NEW_PASSWORD = "a brand new passphrase";
const body = (b: unknown) => ({ method: "POST", body: JSON.stringify(b) });

describe("the first admin", () => {
  test("on this machine, the first person to open Keelson creates the admin and is signed in", async () => {
    const { call, repo, cleanup } = makeApp({ user: null });
    const s = (await (await call("/api/session")).json()) as any;
    assert.equal(s.setupRequired, true);
    assert.equal(s.setupCodeRequired, false, "no code on loopback");

    const res = await call("/api/setup", body({ username: "Alex", name: "Alex Doe", password: PASSWORD }));
    assert.equal(res.status, 200);
    const cookie = (res.headers.get("set-cookie") || "").split(";")[0];
    const me = (await (await call("/api/session", { headers: { cookie } })).json()) as any;
    assert.equal(me.setupRequired, false);
    assert.deepEqual([me.user.username, me.user.role, me.user.name], ["alex", "admin", "Alex Doe"]);

    const again = await call("/api/setup", body({ username: "mallory", password: PASSWORD }));
    assert.equal(again.status, 409, "only while nobody exists");
    assert.equal(repo.users.count(), 1);
    cleanup();
  });

  test("off this machine it needs the setup code from the log, and a wrong code counts as a failed sign-in", async () => {
    const { call, auth, cleanup } = makeApp({ user: null, loopback: false });
    const s = (await (await call("/api/session")).json()) as any;
    assert.equal(s.setupCodeRequired, true);
    const code = auth.setupCode!;
    assert.match(code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);

    assert.equal((await call("/api/setup", body({ username: "alex", password: PASSWORD }))).status, 401);
    assert.equal((await call("/api/setup", body({ username: "alex", password: PASSWORD, code: "AAAA-BBBB-CCCC" }))).status, 401);
    const ok = await call("/api/setup", body({ username: "alex", password: PASSWORD, code: ` ${code.toLowerCase().replace(/-/g, "")} ` }));
    assert.equal(ok.status, 200, "case, spaces and dashes don't matter");
    assert.equal(auth.setupCode, null, "the code is spent");
    cleanup();
  });

  test("a web page that rebinds its name to this machine still needs the code", async () => {
    const { call, cleanup } = makeApp({ user: null });
    const s = (await (await call("/api/session", { host: "evil.example:4317" })).json()) as any;
    assert.equal(s.setupCodeRequired, true);
    assert.equal((await call("/api/setup", { ...body({ username: "evil", password: PASSWORD }), host: "evil.example:4317" })).status, 401);
    cleanup();
  });

  test("passwords need 12 characters, and usernames a plain shape", async () => {
    const { json, cleanup } = makeApp({ user: null });
    assert.match((await json("/api/setup", "POST", { username: "alex", password: "short" })).error, /12 characters/);
    assert.match((await json("/api/setup", "POST", { username: "a b", password: PASSWORD })).error, /Usernames use/);
    cleanup();
  });
});

describe("roles", () => {
  test("each role can do what it says, and nothing more", async () => {
    const t = makeApp({ configured: true });
    // One change per permission, each one harmless to repeat.
    const fp = (await t.json(`/api/findings?scope=a:${MOCK_ACCOUNT}`)).findings?.[0]?.fingerprint ?? "0".repeat(20);
    const changes: Record<Permission, [string, string, unknown]> = {
      triage: [`/api/triage/${fp}`, "PUT", { status: "in_progress" }],
      scan: ["/api/scan", "POST", { scope: `a:${MOCK_ACCOUNT}` }],
      accounts: ["/api/entities", "POST", { name: "Another Co" }],
      checks: ["/api/checks/CF-001", "PUT", { disabled: false, severity: null }],
      settings: ["/api/settings", "PUT", { retentionDays: 90 }],
      users: ["/api/users", "POST", { username: `new-${Math.random().toString(36).slice(2, 8)}`, role: "viewer" }],
    };
    for (const role of ROLES) {
      const as = t.as(role);
      for (const [perm, [path, method, b]] of Object.entries(changes) as [Permission, [string, string, unknown]][]) {
        const res = await as.call(path, { method, body: JSON.stringify(b) });
        if (can(role, perm)) assert.ok(res.status < 400 || res.status === 404, `${role} may ${perm}: ${res.status} ${await res.text()}`);
        else {
          assert.equal(res.status, 403, `${role} may not ${perm}`);
          const err = (await res.json()) as any;
          assert.equal(err.code, "role");
          assert.match(err.error, /Ask an admin/);
        }
      }
      // Every role reads every page and exports.
      for (const path of ["/api/overview", "/api/findings", "/api/checks", "/api/settings", "/api/accounts", "/api/export/findings.csv"])
        assert.equal((await as.call(path)).status, 200, `${role} reads ${path}`);
      assert.equal((await as.call("/api/users")).status, can(role, "users") ? 200 : 403, "only admins list users");
    }
    t.cleanup();
  });

  test("roles build on each other", () => {
    for (const [perm, min] of Object.entries(PERMISSION_ROLE) as [Permission, Role][])
      for (const role of ROLES) assert.equal(can(role, perm), ROLES.indexOf(role) >= ROLES.indexOf(min));
    assert.equal(can("viewer", "triage"), false);
    assert.equal(can("admin", "users"), true);
  });

  test("a route that changes something can't be registered without saying who may call it", () => {
    const app = new Hono<AppEnv>();
    const r = routes(app);
    assert.throws(() => r.post("/api/x", (c) => c.json({})), /doesn't say who may/);
    assert.throws(() => r.on(["GET", "PUT"], ["/api/y"], (c) => c.json({})), /doesn't say who may/);
    assert.doesNotThrow(() => r.get("/api/z", (c) => c.json({})));
    assert.doesNotThrow(() => r.with(requirePermission("triage")).put("/api/x", (c) => c.json({})));
    assert.doesNotThrow(() => r.with(anyone).post("/api/login2", (c) => c.json({})));
  });

  test("a triage change records who made it", async () => {
    const t = makeApp({ configured: true });
    await t.scanner.start("manual").done;
    const fp = (await t.json(`/api/findings?scope=a:${MOCK_ACCOUNT}`)).findings[0].fingerprint;
    await t.as("analyst").json(`/api/triage/${fp}`, "PUT", { status: "in_progress" });
    const f = await t.json(`/api/finding/${fp}`);
    assert.equal(f.finding.triage.updatedBy, "analyst");
    assert.equal(f.events.at(-1).by, "analyst");
    t.cleanup();
  });
});

describe("managing users", () => {
  test("an admin adds someone with a one-time password, which they must replace before anything else", async () => {
    const t = makeApp({ configured: true });
    const added = await t.json("/api/users", "POST", { username: "Sam", name: "Sam Roe", role: "analyst" });
    assert.equal(added.user.username, "sam");
    assert.equal(added.user.mustChangePassword, true);
    assert.equal(added.user.createdBy, "admin");
    assert.ok(added.password.length >= 20);
    assert.equal((await t.call("/api/users", body({ username: "sam", role: "viewer" }))).status, 409, "usernames are unique");

    const signIn = await t.call("/api/login", { ...body({ username: "sam", password: added.password }), anonymous: true });
    const cookie = (signIn.headers.get("set-cookie") || "").split(";")[0];
    const as = (path: string, init: RequestInit = {}) => t.call(path, { ...init, anonymous: true, headers: { cookie } });
    const blocked = await as("/api/overview");
    assert.equal(blocked.status, 403);
    assert.equal(((await blocked.json()) as any).code, "password");
    const s = (await (await as("/api/session")).json()) as any;
    assert.equal(s.user.mustChangePassword, true);
    assert.equal(s.accounts, undefined, "nothing else until the password is replaced");

    assert.equal((await as("/api/me/password", { method: "PUT", body: JSON.stringify({ current: "wrong", password: NEW_PASSWORD }) })).status, 400);
    assert.equal((await as("/api/me/password", { method: "PUT", body: JSON.stringify({ current: added.password, password: NEW_PASSWORD }) })).status, 200);
    assert.equal((await as("/api/overview")).status, 200);
    assert.equal((await as("/api/me", { method: "PATCH", body: JSON.stringify({ name: "Samantha Roe" }) })).status, 200);
    assert.equal(t.repo.users.byUsername("sam")!.name, "Samantha Roe");
    t.cleanup();
  });

  test("role changes and removals apply to sessions already open", async () => {
    const t = makeApp({ configured: true });
    const viewer = t.as("viewer");
    const id = t.repo.users.byUsername("viewer")!.id;
    assert.equal((await viewer.call("/api/scan", body({ scope: "all" }))).status, 403);
    await t.json(`/api/users/${id}`, "PATCH", { role: "analyst" });
    assert.equal((await viewer.call("/api/scan", body({ scope: "all" }))).status, 202, "the new role applies at once");

    const reset = await t.json(`/api/users/${id}/password`, "POST", {});
    assert.ok(reset.password);
    assert.equal((await viewer.call("/api/overview")).status, 401, "a reset signs them out");

    const other = t.as("manager");
    const managerId = t.repo.users.byUsername("manager")!.id;
    assert.equal((await t.call(`/api/users/${managerId}`, { method: "DELETE", body: "{}" })).status, 200);
    assert.equal((await other.call("/api/overview")).status, 401, "a removed user is signed out");
    t.cleanup();
  });

  test("Keelson always keeps an admin, and admins can't remove themselves", async () => {
    const t = makeApp();
    const me = t.repo.users.byUsername("admin")!.id;
    assert.equal((await t.call(`/api/users/${me}`, { method: "PATCH", body: JSON.stringify({ role: "manager" }) })).status, 409);
    assert.equal((await t.call(`/api/users/${me}`, { method: "DELETE", body: "{}" })).status, 400);
    assert.equal((await t.call(`/api/users/${me}/password`, body({}))).status, 400, "your own password is changed from your menu");
    const second = await t.json("/api/users", "POST", { username: "blair", role: "admin" });
    assert.equal((await t.call(`/api/users/${me}`, { method: "PATCH", body: JSON.stringify({ role: "manager" }) })).status, 200, "with another admin, yes");
    assert.equal((await t.as("admin").call(`/api/users/${second.user.id}`, { method: "DELETE", body: "{}" })).status, 403, "now a manager");
    t.cleanup();
  });

  test("no response carries a password hash", async () => {
    const t = makeApp({ configured: true });
    await t.json("/api/users", "POST", { username: "sam", role: "viewer" });
    for (const path of ["/api/users", "/api/session", "/api/accounts"])
      assert.doesNotMatch(await (await t.call(path)).text(), /scrypt|password_hash|passwordHash/);
    t.cleanup();
  });
});

describe("sign-in turned off behind a proxy", () => {
  test("everyone is an admin, nobody signs in, and on loopback the Host header must name this machine", async () => {
    const { call, cleanup } = makeApp({ insecureNoAuth: true, user: null, configured: true });
    const s = (await (await call("/api/session")).json()) as any;
    assert.equal(s.authRequired, false);
    assert.equal(s.setupRequired, false);
    assert.equal(s.user.role, "admin");
    assert.equal((await call("/api/settings", { method: "PUT", body: JSON.stringify({ retentionDays: 90 }) })).status, 200);
    assert.equal((await call("/api/session", { host: "evil.example:4317" })).status, 403, "DNS rebinding");
    assert.equal((await call("/api/session", { host: "localhost:4317" })).status, 200);
    cleanup();
  });
});
