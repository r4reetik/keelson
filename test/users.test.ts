// Users and roles: creating the first admin (with the setup code off this
// machine), what each role may change, user management, one-time passwords,
// users limited to some entities, and sign-in turned off behind a proxy.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { Hono } from "hono";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_ACCOUNT_2, MOCK_ACCOUNT_3, MOCK_TOKEN, MOCK_TOKEN_2 } from "../dev/mock/cloudflare.ts";
import { seedAccount } from "../dev/mock/accounts.ts";
import { makeApp, PASSWORD } from "./helpers/app.ts";
import { routes } from "../src/server/router.ts";
import { anyone, requirePermission } from "../src/server/middleware.ts";
import { allowed, can, INSTANCE_WIDE, PERMISSION_ROLE, ROLES, type Permission, type Role } from "../src/shared/roles.ts";
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

describe("before any account is connected", () => {
  test("the app opens straight after sign-up: what it reads without an account answers, and nothing needs one", async () => {
    const { call, cleanup } = makeApp({ user: null });
    const res = await call("/api/setup", body({ username: "alex", password: PASSWORD }));
    const cookie = (res.headers.get("set-cookie") || "").split(";")[0];
    const get = (path: string) => call(path, { headers: { cookie } });
    const s = (await (await get("/api/session")).json()) as any;
    assert.equal(s.configured, false);
    assert.deepEqual([s.accounts, s.entities], [[], []], "an empty list, so the app shell can open");
    // The shell and the pages it shows before an account exists: Accounts (where the first one is added), Checks, Users, Settings.
    for (const path of ["/api/accounts", "/api/accounts/template?provider=cloudflare", "/api/checks?scope=all", "/api/users", "/api/settings"])
      assert.equal((await get(path)).status, 200, path);
    assert.equal((await get("/api/overview?scope=all")).status, 409, "pages that need an account wait for one");
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

/** Two companies: Mock Group (MOCK_ACCOUNT) and Other Ltd (MOCK_ACCOUNT_2), both scanned. */
async function twoEntities() {
  const t = makeApp({ configured: true });
  const other = seedAccount(t.repo, t.vault, { id: MOCK_ACCOUNT_2, token: MOCK_TOKEN_2, name: "Other Ltd", entity: "Other Ltd" });
  const own = t.repo.accounts.get(MOCK_ACCOUNT)!.entityId;
  await t.scanner.start("manual").done;
  const fps = async (account: string) => ((await t.json(`/api/findings?scope=a:${account}`)).findings as { fingerprint: string }[]).map((f) => f.fingerprint);
  return { t, own, other: other.entityId, ownFps: await fps(MOCK_ACCOUNT), otherFps: await fps(MOCK_ACCOUNT_2) };
}

describe("users limited to some entities", () => {
  test("they see only their entities' accounts, findings and scans, and another entity is unknown to them", async () => {
    const { t, own, other, ownFps, otherFps } = await twoEntities();
    assert.ok(ownFps.length && otherFps.length);
    const as = t.limitedAs("analyst", [own]);

    const s = await as.json("/api/session");
    assert.deepEqual(s.user.entities, [own]);
    assert.deepEqual(
      s.accounts.map((a: any) => a.id),
      [MOCK_ACCOUNT],
    );
    assert.deepEqual(
      s.entities.map((e: any) => e.id),
      [own],
    );
    assert.deepEqual(
      (await as.json("/api/accounts")).entities.map((e: any) => e.id),
      [own],
    );

    // "All accounts" is their entities only.
    const all = await as.json("/api/findings?scope=all");
    assert.ok(all.findings.length);
    assert.ok(all.findings.every((f: any) => f.accountId === MOCK_ACCOUNT));

    // Every way of naming the other entity is unknown.
    for (const path of [
      `/api/overview?scope=e:${other}`,
      `/api/findings?scope=a:${MOCK_ACCOUNT_2}`,
      `/api/report?scope=e:${other}`,
      `/api/scans?scope=a:${MOCK_ACCOUNT_2}`,
      `/api/triaged?scope=e:${other}`,
      `/api/export/findings.csv?scope=e:${other}`,
      `/api/export/findings.json?scope=a:${MOCK_ACCOUNT_2}`,
      `/api/scan/status?scope=e:${other}`,
      `/api/compliance?scope=e:${other}`,
      `/api/export/compliance.csv?framework=pci-dss&scope=a:${MOCK_ACCOUNT_2}`,
      `/api/finding/${otherFps[0]}`,
    ])
      assert.equal((await as.call(path)).status, 404, path);
    // A hand-picked set keeps only the accounts they may see.
    const picked = await as.json(`/api/findings?scope=s:${MOCK_ACCOUNT},${MOCK_ACCOUNT_2}`);
    assert.ok(picked.findings.every((f: any) => f.accountId === MOCK_ACCOUNT));
    assert.equal((await as.call(`/api/finding/${ownFps[0]}`)).status, 200);

    // Nothing of the other entity appears anywhere they can read.
    for (const path of [
      "/api/overview?scope=all",
      "/api/findings?scope=all",
      "/api/report?scope=all",
      "/api/scans?scope=all",
      "/api/triaged?scope=all",
      "/api/export/findings.csv?scope=all",
      "/api/export/findings.json?scope=all",
      "/api/scan/status?scope=all",
      "/api/checks?scope=all",
      "/api/compliance?scope=all",
      "/api/export/compliance.csv?scope=all",
      "/api/accounts",
      "/api/session",
      `/api/owners?accounts=${MOCK_ACCOUNT_2}`,
    ]) {
      const text = await (await as.call(path)).text();
      assert.doesNotMatch(text, new RegExp(`${MOCK_ACCOUNT_2}|Other Ltd|other\\.example`), path);
      for (const fp of otherFps) assert.ok(!text.includes(fp), `${path} shows another entity's finding`);
    }
    assert.equal((await as.json(`/api/checks?scope=e:${other}`)).scan, null);
    t.cleanup();
  });

  test("they can't triage, scan or see owners in another entity", async () => {
    const { t, own, ownFps, otherFps } = await twoEntities();
    await t.json(`/api/triage/${otherFps[0]}`, "PUT", { status: "accepted", owner: "secret-owner@other.example" });
    const as = t.limitedAs("analyst", [own]);

    assert.equal((await as.call(`/api/triage/${otherFps[0]}`, { method: "PUT", body: JSON.stringify({ status: "open" }) })).status, 404);
    // A batch with one finding outside their entities changes nothing at all.
    const batch = await as.call("/api/triage", body({ fingerprints: [ownFps[0], otherFps[1]], status: "in_progress" }));
    assert.equal(batch.status, 404);
    const findings = (await t.json(`/api/findings?scope=all`)).findings as any[];
    assert.equal(findings.find((f) => f.fingerprint === ownFps[0]).status, "open");
    assert.equal(findings.find((f) => f.fingerprint === otherFps[1]).status, "open");
    assert.equal(findings.find((f) => f.fingerprint === otherFps[0]).status, "accepted");
    assert.equal((await as.call("/api/triage", body({ fingerprints: [ownFps[0]], status: "in_progress" }))).status, 200);

    assert.deepEqual((await as.json(`/api/owners?accounts=${MOCK_ACCOUNT_2}`)).owners, []);
    assert.deepEqual((await as.json(`/api/owners?accounts=${MOCK_ACCOUNT}`)).owners, []);

    // Scanning "every entity" scans theirs.
    const run = await as.call("/api/scan", body({ every: true }));
    assert.equal(run.status, 202);
    assert.deepEqual(((await run.json()) as any).queued, [MOCK_ACCOUNT]);
    assert.equal((await as.call("/api/scan", body({ scope: `a:${MOCK_ACCOUNT_2}` }))).status, 404);
    await t.scanner.start("manual", [MOCK_ACCOUNT]).done;
    t.cleanup();
  });

  test("a limited manager changes only their own entity and its accounts, and nothing that applies to every entity", async () => {
    const { t, own, other } = await twoEntities();
    const as = t.limitedAs("manager", [own]);
    const send = (path: string, method: string, b: unknown) => as.call(path, { method, body: JSON.stringify(b) });

    // Another entity and its account are unknown.
    assert.equal((await send(`/api/entities/${other}`, "PATCH", { name: "Taken" })).status, 404);
    assert.equal((await send(`/api/entities/${other}`, "DELETE", {})).status, 404);
    assert.equal((await send(`/api/entities/${other}/test-notification`, "POST", {})).status, 404);
    assert.equal((await send(`/api/accounts/${MOCK_ACCOUNT_2}`, "PATCH", { alias: "Taken" })).status, 404);
    assert.equal((await send(`/api/accounts/${MOCK_ACCOUNT_2}/token`, "PUT", { token: MOCK_TOKEN_2 })).status, 404);
    assert.equal((await send(`/api/accounts/${MOCK_ACCOUNT_2}`, "DELETE", {})).status, 404);
    assert.equal((await send(`/api/accounts/${MOCK_ACCOUNT}`, "PATCH", { entityId: other })).status, 400, "can't move an account out to another entity");
    // Connecting an account that is in another entity would replace its credential there.
    const steal = await send("/api/accounts", "POST", { token: MOCK_TOKEN_2, accountIds: [MOCK_ACCOUNT_2], entityId: own });
    assert.equal(steal.status, 403);
    assert.equal(t.repo.accounts.get(MOCK_ACCOUNT_2)!.entityId, other);
    assert.equal((await send("/api/accounts", "POST", { token: MOCK_TOKEN, accountIds: [MOCK_ACCOUNT_3], entityId: other })).status, 400);
    // What verifying a credential says about an account in another entity: that it's added, not where.
    const verify = await send("/api/accounts/verify", "POST", { token: MOCK_TOKEN_2, accountIds: [] });
    assert.deepEqual(
      ((await verify.json()) as any).accounts.map((a: any) => [a.id, a.added, a.entityId]),
      [[MOCK_ACCOUNT_2, true, null]],
    );

    // Entities are created, removed and arranged by someone who sees them all; checks and settings apply to every entity.
    for (const [path, method, b] of [
      ["/api/entities", "POST", { name: "Mine Too" }],
      [`/api/entities/${own}`, "DELETE", {}],
      [`/api/entities/${own}`, "PATCH", { includeInAll: false }],
      [`/api/entities/${own}`, "PATCH", { move: "down" }],
      ["/api/checks/CF-001", "PUT", { disabled: true, severity: null }],
      ["/api/settings", "PUT", { retentionDays: 30 }],
    ] as const) {
      const res = await send(path, method, b);
      assert.equal(res.status, 403, `${method} ${path}`);
      assert.equal(((await res.json()) as any).code, "role");
    }
    assert.equal(t.repo.entities.list().length, 2);
    assert.equal(t.repo.settings.overrides().disabled.size, 0);

    // Their own entity and accounts, yes.
    assert.equal((await send(`/api/entities/${own}`, "PATCH", { name: "Mock Group Renamed" })).status, 200);
    assert.equal((await send(`/api/accounts/${MOCK_ACCOUNT}`, "PATCH", { alias: "Main" })).status, 200);
    // Without naming an entity, new accounts go to their only one.
    const added = await send("/api/accounts", "POST", { token: MOCK_TOKEN, accountIds: [MOCK_ACCOUNT_3] });
    assert.equal(added.status, 200, await added.clone().text());
    assert.equal(t.repo.accounts.get(MOCK_ACCOUNT_3)!.entityId, own);
    await t.scanner.start("manual", [MOCK_ACCOUNT_3]).done;
    t.cleanup();
  });

  test('"All accounts" is their entities, still without the ones kept separate', async () => {
    const { t, own, other } = await twoEntities();
    t.repo.entities.update(other, { ...t.repo.entities.get(other)!, includeInAll: false });
    const as = t.limitedAs("viewer", [own, other]);
    assert.ok((await as.json("/api/findings?scope=all")).findings.every((f: any) => f.accountId === MOCK_ACCOUNT));
    assert.ok((await as.json(`/api/findings?scope=e:${other}`)).findings.length > 0, "the separate entity on its own");
    assert.equal((await as.call(`/api/findings?scope=s:${MOCK_ACCOUNT},${MOCK_ACCOUNT_2}`)).status, 404, "never combined with another");
    t.cleanup();
  });

  test("an admin limits users, changes the limit, and admins always see everything", async () => {
    const { t, own, other } = await twoEntities();
    const added = await t.json("/api/users", "POST", { username: "client", role: "analyst", entities: [other] });
    assert.deepEqual(added.user.entities, [other]);
    const id = added.user.id;
    assert.deepEqual((await t.json("/api/users")).users.find((u: any) => u.id === id).entities, [other]);

    assert.match((await t.json("/api/users", "POST", { username: "nobody", role: "viewer", entities: [] })).error, /at least one entity/);
    assert.match((await t.json("/api/users", "POST", { username: "ghost", role: "viewer", entities: [9999] })).error, /no longer exists/);
    assert.equal((await t.json("/api/users", "POST", { username: "boss", role: "admin", entities: [other] })).user.entities, null, "admins see everything");

    await t.json(`/api/users/${id}`, "PATCH", { entities: [own, other] });
    assert.deepEqual(t.repo.users.get(id)!.entities, [own, other]);
    await t.json(`/api/users/${id}`, "PATCH", { name: "Client" });
    assert.deepEqual(t.repo.users.get(id)!.entities, [own, other], "a change that doesn't mention entities keeps them");
    await t.json(`/api/users/${id}`, "PATCH", { entities: null });
    assert.equal(t.repo.users.get(id)!.entities, null);
    await t.json(`/api/users/${id}`, "PATCH", { entities: [other] });
    await t.json(`/api/users/${id}`, "PATCH", { role: "admin" });
    assert.equal(t.repo.users.get(id)!.entities, null, "becoming an admin lifts the limit");
    await t.json(`/api/users/${id}`, "PATCH", { role: "viewer" });
    assert.equal(t.repo.users.get(id)!.entities, null, "and it isn't restored");
    t.cleanup();
  });

  test("a limit applies to sessions already open, and removing their last entity leaves them seeing nothing", async () => {
    const { t, own, other } = await twoEntities();
    const as = t.limitedAs("manager", [other]);
    assert.equal((await as.call(`/api/findings?scope=e:${own}`)).status, 404);
    await t.json(`/api/users/${as.id}`, "PATCH", { entities: [own] });
    assert.equal((await as.call(`/api/findings?scope=e:${own}`)).status, 200, "the new limit applies at once");

    // Their only entity goes away: they see no entity, never every entity.
    t.repo.accounts.remove(MOCK_ACCOUNT);
    assert.equal((await t.call(`/api/entities/${own}`, { method: "DELETE", body: "{}" })).status, 200);
    assert.deepEqual(t.repo.users.get(as.id)!.entities, []);
    const s = await as.json("/api/session");
    assert.deepEqual([s.accounts, s.entities, s.configured], [[], [], false]);
    assert.deepEqual((await as.json("/api/accounts")).entities, []);
    t.cleanup();
  });

  test("only changes that reach every entity are out of a limited user's reach", () => {
    for (const role of ROLES)
      for (const perm of Object.keys(PERMISSION_ROLE) as Permission[]) {
        assert.equal(allowed({ role, entities: null }, perm), can(role, perm));
        assert.equal(allowed({ role, entities: [1] }, perm), can(role, perm) && !INSTANCE_WIDE.includes(perm));
      }
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
