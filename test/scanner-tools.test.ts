// Settings' Scanners card: which scanners are installed, when Grype's and Trivy's
// databases were built, and updating one on request. Only admins can update, an
// update runs in the background, and a failure is reported, not thrown away.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { installMockAnchore, mockDatabases } from "../dev/mock/anchore.ts";
import { installMockTrivy } from "../dev/mock/trivy.ts";
import { amass } from "../src/providers/internet/amass.ts";
import { grypeBuilt } from "../src/core/anchore.ts";
import { makeApp } from "./helpers/app.ts";

const until = async (done: () => Promise<boolean>) => {
  for (let i = 0; i < 100; i++) {
    if (await done()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.fail("timed out");
};

describe("scanners in Settings", () => {
  const restore: (() => void)[] = [];
  const realAmass = amass.path;
  before(() => {
    restore.push(installMockTrivy());
    amass.path = () => "/mock/amass";
  });
  after(() => {
    for (const r of restore) r();
    amass.path = realAmass;
  });

  test("lists every scanner, and when the databases were built", async () => {
    const undo = installMockAnchore();
    const t = makeApp({ configured: true });
    const s = await t.as("viewer").json("/api/scanners");
    assert.deepEqual(
      s.scanners.map((r: any) => r.key),
      ["syft", "grype", "grant", "trivy", "amass"],
    );
    assert.ok(s.scanners.every((r: any) => r.installed));
    const by = Object.fromEntries(s.scanners.map((r: any) => [r.key, r]));
    assert.equal(by.syft.database, null, "Syft has no database");
    assert.equal(by.grype.version, "0.0.0-mock-grype");
    for (const key of ["grype", "trivy"]) {
      assert.ok(by[key].database.builtAt, `${key}'s database has a build date`);
      assert.equal(by[key].database.updating, false);
    }
    t.cleanup();
    undo();
  });

  test("only an admin updates a database; it runs in the background and the build date moves", async () => {
    const undo = installMockAnchore();
    mockDatabases.updateMs = 40;
    const t = makeApp({ configured: true });
    try {
      for (const role of ["viewer", "analyst", "manager"] as const)
        assert.equal((await t.as(role).call("/api/scanners/grype/database", { method: "POST", body: "{}" })).status, 403, role);
      const before = (await t.json("/api/scanners")).scanners.find((r: any) => r.key === "grype").database.builtAt;
      const started = await t.as("admin").json("/api/scanners/grype/database", "POST", {});
      assert.equal(started.scanners.find((r: any) => r.key === "grype").database.updating, true);
      // Asking again while it runs starts nothing new.
      await t.as("admin").json("/api/scanners/grype/database", "POST", {});
      const grype = async () => (await t.json("/api/scanners")).scanners.find((r: any) => r.key === "grype").database;
      await until(async () => !(await grype()).updating);
      const done = await grype();
      assert.ok(done.updatedAt);
      assert.equal(done.error, null);
      assert.notEqual(done.builtAt, before, "the new database's build date is read again");
      assert.equal(mockDatabases.updates, 1);
    } finally {
      mockDatabases.updateMs = 0;
      mockDatabases.updates = 0;
      t.cleanup();
      undo();
    }
  });

  test("a failed update says why; a scanner without a database or not installed is refused", async () => {
    const undo = installMockAnchore({ missing: ["grype"] });
    const t = makeApp({ configured: true });
    const admin = t.as("admin");
    try {
      assert.equal((await admin.call("/api/scanners/syft/database", { method: "POST", body: "{}" })).status, 404);
      const missing = await admin.call("/api/scanners/grype/database", { method: "POST", body: "{}" });
      assert.equal(missing.status, 409);
      assert.match(((await missing.json()) as { error: string }).error, /Grype isn't installed/);

      mockDatabases.fail = true;
      await admin.json("/api/scanners/trivy/database", "POST", {});
      const trivy = async () => (await admin.json("/api/scanners")).scanners.find((r: any) => r.key === "trivy").database;
      await until(async () => !(await trivy()).updating);
      assert.match((await trivy()).error, /connection refused/);
    } finally {
      mockDatabases.fail = false;
      mockDatabases.updates = 0;
      t.cleanup();
      undo();
    }
  });

  test("Grype's build date is read from its status in either schema, and none without a database", () => {
    assert.equal(grypeBuilt('{"schemaVersion":"v6.0.2","built":"2026-11-22T04:12:00Z","valid":true}'), "2026-11-22T04:12:00.000Z");
    assert.equal(grypeBuilt('{"location":"/x","built":"2026-11-21T00:00:00Z","schemaVersion":5}'), "2026-11-21T00:00:00.000Z");
    assert.equal(grypeBuilt('{"schemaVersion":"","valid":false,"error":"database does not exist"}'), null);
    assert.equal(grypeBuilt("not json"), null);
  });
});
