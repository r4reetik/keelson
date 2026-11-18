// Compliance checklists: every check is mapped to a security topic, frameworks
// are complete and name only real checks, statuses follow findings, triage and
// coverage, and the page's API respects the view.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { installMockCloudflare, MOCK_ACCOUNT } from "../dev/mock/cloudflare.ts";
import { makeApp } from "./helpers/app.ts";
import { CHECKS, CHECK_BY_ID, SC_CLASSES } from "../src/providers/catalog.ts";
import { assess, checksOf, controlsOfCheck, FRAMEWORKS, TOPICS } from "../src/compliance/index.ts";
import { NO_TOPIC } from "../src/compliance/topics.ts";
import { CONTROL_STATUSES, FRAMEWORK_IDS, TOPIC_IDS } from "../src/shared/compliance.ts";
import type { Finding } from "../src/shared/api.ts";

const exists = (id: string) => !!CHECK_BY_ID[id] || (id.startsWith("SC:") && !!SC_CLASSES[id.slice(3)]);

describe("mapping", () => {
  test("every check and Security Center insight gives evidence for a topic, or is listed as giving none", () => {
    const mapped = new Set([...Object.values(TOPICS).flatMap((t) => t.checks), ...NO_TOPIC]);
    const missing = [...CHECKS.map((c) => c.id), ...Object.keys(SC_CLASSES).map((k) => `SC:${k}`)].filter((id) => !mapped.has(id));
    assert.deepEqual(missing, [], "add these checks to a topic in src/compliance/topics.ts");
    for (const id of NO_TOPIC) assert.ok(!Object.values(TOPICS).some((t) => t.checks.includes(id)), `${id} is in NO_TOPIC and in a topic`);
  });

  test("topics name only checks that exist, once each, and every topic is used by a framework", () => {
    assert.deepEqual(Object.keys(TOPICS).sort(), [...TOPIC_IDS].sort());
    for (const [id, t] of Object.entries(TOPICS)) {
      for (const c of t.checks) assert.ok(exists(c), `${id} names unknown check ${c}`);
      assert.equal(new Set(t.checks).size, t.checks.length, `${id} lists a check twice`);
    }
    const used = new Set(Object.values(FRAMEWORKS).flatMap((f) => f.controls.flatMap((c) => c.topics ?? [])));
    for (const id of TOPIC_IDS) assert.ok(used.has(id), `topic ${id} isn't used by any control`);
  });

  test("ISO/IEC 27001:2022 lists all 93 Annex A controls in their themes", () => {
    const iso = FRAMEWORKS.iso27001;
    assert.equal(iso.controls.length, 93);
    const per = iso.groups.map((g) => iso.controls.filter((c) => c.group === g).length);
    assert.deepEqual(per, [37, 8, 14, 34]);
    const ids = iso.controls.map((c) => c.id);
    for (const [theme, n] of [
      [5, 37],
      [6, 8],
      [7, 14],
      [8, 34],
    ] as const)
      for (let i = 1; i <= n; i++) assert.ok(ids.includes(`${theme}.${i}`), `${theme}.${i} is missing`);
  });

  test("PCI DSS v4.0.1 lists every section of the twelve requirements", () => {
    const pci = FRAMEWORKS["pci-dss"];
    const sections = pci.controls.map((c) => c.id);
    // prettier-ignore
    const expected = [
      "1.1",
      "1.2",
      "1.3",
      "1.4",
      "1.5",
      "2.1",
      "2.2",
      "2.3",
      "3.1",
      "3.2",
      "3.3",
      "3.4",
      "3.5",
      "3.6",
      "3.7",
      "4.1",
      "4.2",
      "5.1",
      "5.2",
      "5.3",
      "5.4",
      "6.1",
      "6.2",
      "6.3",
      "6.4",
      "6.5",
      "7.1",
      "7.2",
      "7.3",
      "8.1",
      "8.2",
      "8.3",
      "8.4",
      "8.5",
      "8.6",
      "9.1",
      "9.2",
      "9.3",
      "9.4",
      "9.5",
      "10.1",
      "10.2",
      "10.3",
      "10.4",
      "10.5",
      "10.6",
      "10.7",
      "11.1",
      "11.2",
      "11.3",
      "11.4",
      "11.5",
      "11.6",
      "12.1",
      "12.2",
      "12.3",
      "12.4",
      "12.5",
      "12.6",
      "12.7",
      "12.8",
      "12.9",
      "12.10",
    ];
    assert.deepEqual(sections, expected);
    for (const c of pci.controls) assert.ok(c.id.startsWith(`${pci.groups.indexOf(c.group) + 1}.`), `${c.id} is under the wrong requirement`);
  });

  test("controls are unique, in a known group, name real checks, and say what an out-of-scope one is about", () => {
    for (const id of FRAMEWORK_IDS) {
      const fw = FRAMEWORKS[id];
      assert.equal(fw.info.id, id);
      assert.equal(new Set(fw.controls.map((c) => c.id)).size, fw.controls.length, `${id} repeats a control`);
      for (const c of fw.controls) {
        assert.ok(fw.groups.includes(c.group), `${id} ${c.id}: unknown group`);
        for (const k of c.checks ?? []) assert.ok(exists(k), `${id} ${c.id} names unknown check ${k}`);
        if (!checksOf(c).length) assert.ok(c.note, `${id} ${c.id} is out of scope for Keelson, so it needs a note saying what it's about`);
      }
    }
  });

  test("a check knows the controls it gives evidence for", () => {
    const mfa = controlsOfCheck("AID-001");
    assert.ok(mfa.iso27001?.includes("8.5"));
    assert.ok(mfa["pci-dss"]?.includes("8.4"));
    assert.deepEqual(controlsOfCheck("COST-001"), {});
    assert.ok(controlsOfCheck("WAF-009")["pci-dss"]?.includes("11.6"), "Page Shield is evidence for payment page monitoring");
  });
});

describe("statuses", () => {
  const fw = FRAMEWORKS.iso27001;
  const finding = (checkId: string, status: Finding["status"] = "open") =>
    ({ checkId, status, settled: status === "accepted" || status === "false_positive", severity: "high" }) as Finding;
  const base = { providers: new Set(["aws" as const]), stats: {}, coverage: [], findings: [], disabled: new Set<string>() };
  const control = (r: ReturnType<typeof assess>, id: string) => r.controls.find((c) => c.id === id)!;

  test("open findings fail a control; accepted risk doesn't", () => {
    const stats = { "AID-001": { evaluated: 1, failed: 1 }, "AID-003": { evaluated: 4, failed: 0 } };
    const failing = assess(fw, { ...base, stats, findings: [finding("AID-001")] });
    assert.equal(control(failing, "8.5").status, "failing");
    assert.equal(control(failing, "8.5").worst, "high");
    const accepted = assess(fw, { ...base, stats, findings: [finding("AID-001", "accepted")] });
    assert.equal(control(accepted, "8.5").status, "passing");
    assert.equal(control(accepted, "8.5").accepted, 1);
  });

  test("a check without enough permission leaves a control undetermined for that reason, and checks of platforms not in view are left out", () => {
    const stats = { "AID-003": { evaluated: 4, failed: 0 } };
    const coverage = [[{ label: "Credential report", ok: false, skippedChecks: ["AID-001"] }]];
    const r = assess(fw, { ...base, stats, coverage });
    assert.equal(control(r, "8.5").status, "no_permission");
    assert.ok(
      control(r, "8.5").checks.every((c) => c.provider === "aws"),
      "only the platforms in view",
    );
    const off = assess(fw, { ...base, stats, disabled: new Set(["AID-015"]) });
    assert.equal(control(off, "8.5").status, "undetermined", "a check turned off leaves it undetermined");
    const both = assess(fw, { ...base, stats, coverage, findings: [finding("AID-003")] });
    assert.equal(control(both, "8.5").status, "failing", "an open finding is a no, whatever couldn't run");
  });

  test("a control nothing ran for is undetermined, never passed, and one without checks is out of scope", () => {
    const r = assess(fw, base);
    assert.equal(control(r, "8.5").status, "undetermined");
    assert.equal(control(r, "6.1").status, "out_of_scope");
    assert.equal(control(assess(fw, { ...base, providers: new Set() }), "8.23").status, "undetermined");
    assert.equal(
      Object.values(r.counts).reduce((a, b) => a + b, 0),
      fw.controls.length,
    );
    assert.deepEqual(Object.keys(r.counts), [...CONTROL_STATUSES]);
  });
});

describe("API", () => {
  let restore: () => void;
  before(() => {
    restore = installMockCloudflare();
  });
  after(() => restore());

  test("the checklist follows the scanned accounts and current triage, and exports as CSV", async () => {
    const { call, json, scanner, cleanup } = makeApp({ configured: true });
    const empty = await json("/api/compliance");
    assert.equal(empty.scan, null);
    await scanner.start("test").done;

    const iso = await json("/api/compliance");
    assert.equal(iso.framework.id, "iso27001");
    assert.equal(iso.controls.length, 93);
    assert.deepEqual(
      iso.frameworks.map((f: { id: string }) => f.id),
      [...FRAMEWORK_IDS],
    );
    for (const c of iso.controls) for (const k of c.checks) assert.equal(k.provider, "cloudflare", `${c.id} lists ${k.id}, not a Cloudflare check`);
    assert.ok(
      iso.controls.some((c: { status: string }) => c.status === "failing"),
      "the mock account fails something",
    );
    assert.equal(iso.controls.find((c: { id: string }) => c.id === "7.1").status, "out_of_scope");

    // Accepting every finding behind a failing control makes it pass (or partial when something couldn't run).
    const failing = iso.controls.find((c: { status: string; checks: { open: number }[] }) => c.status === "failing");
    const { findings } = await json("/api/findings");
    const ids = new Set(failing.checks.map((k: { id: string }) => k.id));
    const fingerprints = findings.filter((f: Finding) => ids.has(f.checkId)).map((f: Finding) => f.fingerprint);
    assert.equal((await call("/api/triage", { method: "POST", body: JSON.stringify({ fingerprints, status: "accepted" }) })).status, 200);
    const after = (await json("/api/compliance")).controls.find((c: { id: string }) => c.id === failing.id);
    assert.notEqual(after.status, "failing");
    assert.ok(after.accepted > 0);

    const pci = await json(`/api/compliance?framework=pci-dss&scope=a:${MOCK_ACCOUNT}`);
    assert.equal(pci.framework.id, "pci-dss");
    assert.equal((await call("/api/compliance?framework=soc2")).status, 400);

    const csv = await call("/api/export/compliance.csv?framework=pci-dss");
    assert.equal(csv.status, 200);
    assert.match(csv.headers.get("content-disposition") || "", /keelson-pci-dss-/);
    const text = await csv.text();
    assert.match(text, /^﻿?requirement,title,group,status/);
    assert.equal(text.trim().split("\r\n").length, FRAMEWORKS["pci-dss"].controls.length + 1);
    cleanup();
  });
});
