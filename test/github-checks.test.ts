// The rules every GitHub check follows, as for the other providers: each fails on
// its case, the well-configured fixture passes everything, an unreadable source
// skips its checks instead of passing them, and branch protection counts classic
// rules and rulesets alike.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { evaluateGithub } from "../src/providers/github/engine.ts";
import { GITHUB_CHECKS } from "../src/providers/github/catalog.ts";
import { GITHUB_MODULES } from "../src/providers/github/checks/index.ts";
import { branchGuard } from "../src/providers/github/checks/branches.ts";
import { CATEGORIES } from "../src/core/categories.ts";
import { GITHUB_CASE_OPTS, GITHUB_CASES, githubInventory, repo } from "./github-cases.ts";
import { opts } from "./fixtures/inventory.ts";

test("every GitHub check fails on its case", () => {
  const silent = GITHUB_CHECKS.filter(
    (c) => !evaluateGithub(GITHUB_CASES[c.id](), opts(GITHUB_CASE_OPTS[c.id])).findings.some((f) => f.checkId === c.id && !f.pass),
  ).map((c) => c.id);
  assert.deepEqual(silent, [], "these cases don't make their check fail");
});

test("the well-configured GitHub organization passes every check it evaluates", () => {
  const ev = evaluateGithub(githubInventory(), opts());
  assert.deepEqual(
    ev.findings.filter((f) => !f.pass).map((f) => `${f.checkId} ${f.resource}`),
    [],
  );
  const evaluated = new Set(ev.results.map((r) => r.checkId));
  assert.deepEqual(
    GITHUB_CHECKS.filter((c) => !evaluated.has(c.id)).map((c) => c.id),
    [],
    "the fixture gives every check something to pass",
  );
});

test("a GitHub check whose source was unreadable reports nothing, even on its failing case", () => {
  const leaked: string[] = [];
  for (const c of GITHUB_CHECKS)
    for (const source of c.requires ?? []) {
      const inv = { ...GITHUB_CASES[c.id](), unreadable: [source] };
      if (evaluateGithub(inv, opts(GITHUB_CASE_OPTS[c.id])).results.some((r) => r.checkId === c.id)) leaked.push(`${c.id} (${source})`);
    }
  assert.deepEqual(leaked, []);
});

test("GitHub checks use the shared categories, link GitHub's docs, and every module file is registered", () => {
  const ids = GITHUB_CHECKS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const c of GITHUB_CHECKS) {
    assert.match(c.id, /^G[A-Z]{2}-\d{3}$/, "GitHub check IDs start with G");
    assert.ok((CATEGORIES as readonly string[]).includes(c.category), c.id);
    assert.ok(c.title && c.why && c.fix, c.id);
    assert.ok(c.docs?.startsWith("https://docs.github.com/"), `${c.id} links GitHub's docs`);
    assert.ok(c.requires?.length, `${c.id} names the sources it reads`);
  }
  const dir = new URL("../src/providers/github/checks/", import.meta.url);
  const files = readdirSync(dir).filter((f) => /^export default defineChecks\(/m.test(readFileSync(new URL(f, dir), "utf8")));
  assert.equal(files.length, GITHUB_MODULES.length, `modules on disk: ${files.join(", ")}`);
});

test("classic protection and rulesets each protect a branch, and their rules combine", () => {
  const classic = { reviews: 2, enforceAdmins: false, allowForcePushes: false, allowDeletions: true, dismissStale: false, lastPushApproval: false };
  assert.deepEqual(branchGuard(repo({ rules: [], protection: null })), {
    protected: false,
    pullRequests: false,
    reviews: 0,
    blocksForcePush: false,
    blocksDeletion: false,
    freshApproval: false,
    adminsBypass: false,
  });
  const both = branchGuard(repo({ protection: classic, rules: [{ type: "deletion", reviews: null }] }));
  assert.equal(both.pullRequests, true);
  assert.equal(both.reviews, 2);
  assert.equal(both.blocksForcePush, true);
  assert.equal(both.blocksDeletion, true, "the ruleset's deletion rule covers what classic protection allows");
  assert.equal(both.adminsBypass, true);
  assert.equal(
    branchGuard(repo({ protection: classic, rules: [{ type: "pull_request", reviews: 1 }] })).adminsBypass,
    false,
    "a ruleset names its own bypass list",
  );
});

test("archived and empty repositories aren't judged on their branches, and only critical and high alerts count", () => {
  const inv = githubInventory({
    repos: [repo({ name: "old", archived: true, rules: [] }), repo({ name: "new", empty: true, rules: [] })],
    dependabot: [{ repo: "new", severity: "moderate", pkg: "x", advisory: "GHSA-2222-2222-2222", createdAt: null }],
  });
  const failing = evaluateGithub(inv, opts())
    .findings.filter((f) => !f.pass)
    .map((f) => f.checkId);
  assert.ok(!failing.includes("GBR-001"));
  assert.ok(!failing.includes("GSC-004"));
});

test("an inactive leaked secret is still reported, lower; Keelson's own App isn't another App with access", () => {
  const leaked = evaluateGithub(
    githubInventory({ secretScanning: [{ number: 1, repo: "web", kind: "Key", validity: "inactive", pushProtectionBypassed: false, createdAt: null }] }),
    opts(),
  ).findings.find((f) => f.checkId === "GSC-003" && !f.pass);
  assert.equal(leaked?.severity, "medium");
  const own = githubInventory({ apps: [{ slug: "keelson", appId: 42, selection: "all", writes: ["contents"] }] });
  assert.ok(!evaluateGithub(own, opts()).findings.some((f) => f.checkId === "GHK-004" && !f.pass));
});

test("an alert check only passes where its scanner runs, and an idle repository's open branch is rated lower", () => {
  const off = githubInventory({
    repos: [repo({ security: { secretScanning: false, pushProtection: false, dependabotUpdates: false }, dependabotAlerts: false, codeScanning: false })],
    dependabot: [],
    codeScanning: [],
    secretScanning: [],
  });
  const evaluated = new Set(evaluateGithub(off, opts()).results.map((r) => r.checkId));
  for (const id of ["GSC-003", "GSC-004", "GSC-005", "GSC-006"]) assert.ok(!evaluated.has(id), `${id} isn't passed where nothing scans`);

  const idle = githubInventory({ repos: [repo({ rules: [], pushedAt: Date.parse("2024-01-01T00:00:00Z") })] });
  const open = evaluateGithub(idle, opts()).findings.find((f) => f.checkId === "GBR-001" && !f.pass);
  assert.equal(open?.severity, "low");
  assert.match(open?.detail ?? "", /last push 2024-01-01/);
});

test("a public repository's runners are rated by whether they keep state and who must approve outside pull requests", () => {
  const sev = (inv: ReturnType<typeof githubInventory>, zone = "web") =>
    evaluateGithub(inv, opts()).findings.find((f) => f.checkId === "GAC-005" && f.zone === zone && !f.pass)?.severity;
  const persistent = [{ name: "box", os: "Linux", ephemeral: false, groupId: null }];
  const base = githubInventory();
  assert.equal(sev(githubInventory({ repos: [repo({ runners: persistent })] })), "high", "every outside contributor waits for approval");
  assert.equal(
    sev(githubInventory({ forkPrs: { ...base.forkPrs!, approval: "first_time_contributors" }, repos: [repo({ runners: persistent })] })),
    "critical",
    "a contributor with one merged pull request runs code on a machine that keeps state",
  );

  // An organization group open to public repositories reaches the repositories it lists, and only those.
  const group = (extra: object) =>
    githubInventory({
      runnerGroups: [{ id: 2, name: "farm", visibility: "selected", allowsPublic: true, restrictedToWorkflows: false, repos: ["web"], ...extra }],
      runners: [{ name: "farm-1", os: "Linux", ephemeral: true, groupId: 2 }],
    });
  assert.equal(sev(group({})), "high");
  assert.match(evaluateGithub(group({}), opts()).findings.find((f) => f.checkId === "GAC-005")?.detail ?? "", /farm-1; group farm/);
  assert.equal(sev(group({ restrictedToWorkflows: true })), "medium", "only named workflows may use the group");
  assert.equal(sev(group({ repos: ["docs"] })), undefined, "a group that doesn't list the repository doesn't reach it");
  assert.equal(sev(group({ allowsPublic: false, visibility: "all" })), undefined, "a group closed to public repositories doesn't reach it");
  assert.ok(
    !evaluateGithub(group({ repos: null }), opts()).results.some((r) => r.checkId === "GAC-005"),
    "a group whose repositories couldn't be read leaves the check unjudged",
  );
  assert.ok(
    !evaluateGithub(githubInventory({ repos: [repo({ private: true, visibility: "private", runners: null })] }), opts()).results.some(
      (r) => r.checkId === "GAC-005",
    ),
    "private repositories aren't judged",
  );
});

test("fork pull requests that need approval are rated lower; a fresh approval counts from either rule; releases are judged only where they exist", () => {
  const base = githubInventory();
  const fork = evaluateGithub(
    githubInventory({ forkPrs: { ...base.forkPrs!, private: { runs: true, secrets: false, writeTokens: true, needsApproval: true } } }),
    opts(),
  ).findings.find((f) => f.checkId === "GAC-004" && !f.pass);
  assert.equal(fork?.severity, "medium");
  assert.match(fork?.detail ?? "", /a token that can write, after a maintainer approves/);

  const stale = (rule: object) =>
    evaluateGithub(githubInventory({ repos: [repo({ rules: [{ type: "pull_request", reviews: 1, ...rule }] })] }), opts()).findings.some(
      (f) => f.checkId === "GBR-004" && !f.pass,
    );
  assert.equal(stale({ lastPushApproval: true }), false, "the last push must be approved by someone else");
  assert.equal(stale({ dismissStale: true }), false);
  assert.equal(stale({}), true);
  assert.ok(
    !evaluateGithub(githubInventory({ repos: [repo({ rules: [{ type: "pull_request", reviews: 0 }] })] }), opts()).results.some((r) => r.checkId === "GBR-004"),
    "no required approval, nothing to go stale",
  );
  const classic = { reviews: 1, enforceAdmins: true, allowForcePushes: false, allowDeletions: false, dismissStale: true, lastPushApproval: false };
  assert.equal(branchGuard(repo({ rules: [], protection: classic })).freshApproval, true);

  assert.ok(
    !evaluateGithub(githubInventory({ repos: [repo({ releases: false, immutableReleases: null })] }), opts()).results.some((r) => r.checkId === "GRL-001"),
  );
});
