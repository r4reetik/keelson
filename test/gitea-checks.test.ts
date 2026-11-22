// The rules every Gitea check follows, as for the other providers: each fails on
// its case, the well-configured fixture passes everything, and an unreadable
// source skips its checks instead of passing them. Then what Gitea's own rules
// mean: which rule covers a branch, and what an instance that doesn't say is
// taken to mean.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { evaluateGitea } from "../src/providers/gitea/engine.ts";
import { GITEA_CHECKS } from "../src/providers/gitea/catalog.ts";
import { GITEA_MODULES } from "../src/providers/gitea/checks/index.ts";
import { ruleCovers, ruleFor } from "../src/providers/gitea/inventory.ts";
import { repoRows } from "../src/providers/gitea/views.ts";
import { CATEGORIES } from "../src/core/categories.ts";
import { CHECKS } from "../src/providers/catalog.ts";
import { GITEA_CASES, giteaInventory, NOW, repo, rule } from "./gitea-cases.ts";
import { opts } from "./fixtures/inventory.ts";

const failing = (inv: ReturnType<typeof giteaInventory>, id: string) => evaluateGitea(inv, opts()).findings.filter((f) => f.checkId === id && !f.pass);

test("every Gitea check fails on its case", () => {
  const silent = GITEA_CHECKS.filter((c) => !failing(GITEA_CASES[c.id](), c.id).length).map((c) => c.id);
  assert.deepEqual(silent, [], "these cases don't make their check fail");
});

test("the well-configured Gitea organization passes every check it evaluates", () => {
  const ev = evaluateGitea(giteaInventory(), opts());
  assert.deepEqual(
    ev.findings.filter((f) => !f.pass).map((f) => `${f.checkId} ${f.resource}`),
    [],
  );
  const evaluated = new Set(ev.results.map((r) => r.checkId));
  assert.deepEqual(
    GITEA_CHECKS.filter((c) => !evaluated.has(c.id)).map((c) => c.id),
    [],
    "the fixture gives every check something to pass",
  );
});

test("a Gitea check whose source was unreadable reports nothing, even on its failing case", () => {
  const leaked: string[] = [];
  for (const c of GITEA_CHECKS)
    for (const source of c.requires ?? []) {
      const inv = { ...GITEA_CASES[c.id](), unreadable: [source] };
      if (evaluateGitea(inv, opts()).results.some((r) => r.checkId === c.id)) leaked.push(`${c.id} (${source})`);
    }
  assert.deepEqual(leaked, []);
});

test("Gitea checks use the shared categories, link Gitea's docs, and every module file is registered", () => {
  const ids = GITEA_CHECKS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  const others = new Set(CHECKS.filter((c) => c.provider !== "gitea").map((c) => c.id.slice(0, 2)));
  for (const c of GITEA_CHECKS) {
    assert.match(c.id, /^TE[A-Z]-\d{3}$/, "Gitea check IDs start with TE");
    assert.ok(!others.has(c.id.slice(0, 2)), `${c.id}: another platform's checks start the same way`);
    assert.ok((CATEGORIES as readonly string[]).includes(c.category), c.id);
    assert.ok(c.title && c.why && c.fix, c.id);
    // Gitea has no page on advisories or licenses to point at; a check that links anything links Gitea's docs.
    assert.ok(!c.docs || c.docs.startsWith("https://docs.gitea.com/"), `${c.id} links Gitea's docs`);
    assert.ok(c.requires?.length, `${c.id} names the sources it reads`);
  }
  const dir = new URL("../src/providers/gitea/checks/", import.meta.url);
  const files = readdirSync(dir).filter((f) => /^export default defineChecks\(/m.test(readFileSync(new URL(f, dir), "utf8")));
  assert.equal(files.length, GITEA_MODULES.length, `modules on disk: ${files.join(", ")}`);
});

test("the rule that covers a branch is the first whose pattern matches, and * stays within one path segment", () => {
  assert.ok(ruleCovers("main", "main"));
  assert.ok(!ruleCovers("main", "maintenance"));
  assert.ok(ruleCovers("ma*", "main"));
  assert.ok(ruleCovers("release/*", "release/1.2"));
  assert.ok(!ruleCovers("release/*", "release/1.2/hotfix"));
  assert.ok(ruleCovers("release/**", "release/1.2/hotfix"));
  assert.ok(ruleCovers("{main,master}", "master"));
  assert.ok(!ruleCovers("release/*", "main"));

  const rules = [
    { rule_name: "*", priority: 2, enable_push: true },
    { rule_name: "main", priority: 1, enable_push: false, required_approvals: 2, dismiss_stale_approvals: true },
  ];
  assert.deepEqual(ruleFor(rules, "main"), { rule: "main", directPush: "nobody", approvals: 2, freshApproval: true, forcePush: null, adminsBypass: null });
  assert.equal(ruleFor(rules, "feature")!.directPush, "anyone");
  assert.equal(ruleFor([{ rule_name: "release/*" }], "main"), null, "a rule for other branches doesn't protect this one");
  // Before patterns, Gitea named the branch in branch_name.
  assert.equal(ruleFor([{ branch_name: "main", enable_push: true, enable_push_whitelist: true }], "main")!.directPush, "listed");
  // An allowlist limits force pushes to the few on it.
  assert.equal(ruleFor([{ rule_name: "main", enable_force_push: true, enable_force_push_allowlist: true }], "main")!.forcePush, false);
  assert.equal(ruleFor([{ rule_name: "main", enable_force_push: true }], "main")!.forcePush, true);
});

test("what an older Gitea doesn't say is never held against a repository, or counted in its favour where it matters", () => {
  // No word on administrators: not judged at all.
  const unknown = giteaInventory({ repos: [repo({ protection: rule({ adminsBypass: null, forcePush: null }) })] });
  const ev = evaluateGitea(unknown, opts());
  assert.equal(ev.results.filter((r) => r.checkId === "TEB-004").length, 0);
  // No word on force pushes: before the setting existed a protected branch never took one.
  assert.deepEqual(
    ev.results.filter((r) => r.checkId === "TEB-002").map((r) => r.pass),
    [true],
  );
  // Nobody said who has two-factor authentication: nothing is concluded about anyone.
  assert.equal(
    evaluateGitea(giteaInventory({ noTwoFactor: null, unreadable: ["twoFactor"] }), opts()).results.filter((r) => r.checkId === "TEI-001").length,
    0,
  );
});

test("findings are rated by who and what they are about", () => {
  const owner = failing(giteaInventory({ noTwoFactor: ["ana", "chloe"] }), "TEI-001");
  assert.deepEqual(
    owner.map((f) => [f.resource, f.severity]),
    [
      ["ana", "high"],
      ["chloe", "medium"],
    ],
  );
  // Someone outside who can only push is rated below one who administers; someone who only reads isn't reported.
  const outside = failing(
    giteaInventory({
      repos: [
        repo({
          outsiders: [
            { login: "a", permission: "write" },
            { login: "b", permission: "admin" },
            { login: "c", permission: "read" },
          ],
        }),
      ],
    }),
    "TEI-004",
  );
  assert.deepEqual(
    outside.map((f) => [f.resource, f.severity]),
    [
      ["web:a", "low"],
      ["web:b", "medium"],
    ],
  );
  // A repository nobody has touched for over a year is rated lower.
  const idle = failing(giteaInventory({ repos: [repo({ protection: null, updatedAt: NOW - 400 * 86_400_000 })] }), "TEB-001");
  assert.equal(idle[0].severity, "low");
  // A rule that still lets everyone push isn't protection.
  assert.equal(failing(giteaInventory({ repos: [repo({ protection: rule({ directPush: "anyone" }) })] }), "TEB-001").length, 1);
  assert.equal(failing(giteaInventory({ repos: [repo({ protection: rule({ directPush: "listed" }) })] }), "TEB-001").length, 0);
  // A public repository on an instance that asks everyone to sign in isn't open to the world; an internal one never is.
  assert.equal(failing(giteaInventory({ anonymous: true, repos: [repo({ visibility: "internal" })] }), "TER-001").length, 0);
  // A mirror to the same instance stays behind the same sign-in; a public repository's mirror gives nothing away.
  assert.equal(failing(giteaInventory({ repos: [repo({ visibility: "public", pushMirrors: ["github.com"] })] }), "TER-002").length, 0);
  // An archived repository, and a copy the instance pulls from elsewhere, take no pushes: no branch rule is asked of them.
  assert.equal(
    failing(giteaInventory({ repos: [repo({ protection: null, archived: true }), repo({ name: "copy", protection: null, mirror: true })] }), "TEB-001").length,
    0,
  );
  // A webhook that is switched off delivers nothing.
  assert.equal(failing(giteaInventory({ hooks: [{ type: "gitea", endpoint: "http://old.example.com", active: false }] }), "TEH-001").length, 0);
});

test("a repository's row says how its default branch is protected", () => {
  const rows = repoRows(
    giteaInventory({
      repos: [
        repo({ name: "a" }),
        repo({ name: "b", protection: rule({ approvals: 2 }) }),
        repo({ name: "c", protection: rule({ directPush: "anyone" }) }),
        repo({ name: "d", protection: null }),
        repo({ name: "e", protection: undefined }),
        repo({ name: "f", archived: true }),
      ],
    }),
    [],
  );
  assert.deepEqual(
    rows.map((r) => r.protection),
    ["Pull request, 1 approval", "Pull request, 2 approvals", "Protected", "None", null, null],
  );
  assert.deepEqual([rows[0].owner, rows[0].url, rows[0].secretScanning], ["example", "https://git.example.com/example/web", null]);
});
