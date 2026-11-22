// The rules every GitLab check follows, as for the other providers: each fails
// on its case, the well-configured fixture passes everything, and an unreadable
// source skips its checks instead of passing them. Then what GitLab's own rules
// mean: which protected branch rules cover a branch, what a pipeline includes
// from outside, and which projects a cloud role's subjects let in.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { evaluateGitlab } from "../src/providers/gitlab/engine.ts";
import { GITLAB_CHECKS } from "../src/providers/gitlab/catalog.ts";
import { GITLAB_MODULES } from "../src/providers/gitlab/checks/index.ts";
import { ruleCovers, ruleFor } from "../src/providers/gitlab/inventory.ts";
import { gitlabLinks, repoRows } from "../src/providers/gitlab/views.ts";
import { ciIncludes } from "../src/core/sbom/index.ts";
import { judgeGitlabTrust } from "../src/core/gitlab-trust.ts";
import { pointsAtGitlabPages } from "../src/core/links.ts";
import { trustOf as awsTrustOf } from "../src/providers/aws/inventory.ts";
import { trustOf as alibabaTrustOf } from "../src/providers/alibaba/policy.ts";
import { CATEGORIES } from "../src/core/categories.ts";
import { GITLAB_CASES, gitlabInventory, NOW, project, rule } from "./gitlab-cases.ts";
import { opts } from "./fixtures/inventory.ts";

const failing = (inv: ReturnType<typeof gitlabInventory>, id: string) => evaluateGitlab(inv, opts()).findings.filter((f) => f.checkId === id && !f.pass);

test("every GitLab check fails on its case", () => {
  const silent = GITLAB_CHECKS.filter((c) => !failing(GITLAB_CASES[c.id](), c.id).length).map((c) => c.id);
  assert.deepEqual(silent, [], "these cases don't make their check fail");
});

test("the well-configured GitLab group passes every check it evaluates", () => {
  const ev = evaluateGitlab(gitlabInventory(), opts());
  assert.deepEqual(
    ev.findings.filter((f) => !f.pass).map((f) => `${f.checkId} ${f.resource}`),
    [],
  );
  const evaluated = new Set(ev.results.map((r) => r.checkId));
  assert.deepEqual(
    GITLAB_CHECKS.filter((c) => !evaluated.has(c.id)).map((c) => c.id),
    [],
    "the fixture gives every check something to pass",
  );
});

test("a GitLab check whose source was unreadable reports nothing, even on its failing case", () => {
  const leaked: string[] = [];
  for (const c of GITLAB_CHECKS)
    for (const source of c.requires ?? []) {
      const inv = { ...GITLAB_CASES[c.id](), unreadable: [source] };
      if (evaluateGitlab(inv, opts()).results.some((r) => r.checkId === c.id)) leaked.push(`${c.id} (${source})`);
    }
  assert.deepEqual(leaked, []);
});

test("GitLab checks use the shared categories, link GitLab's docs, and every module file is registered", () => {
  const ids = GITLAB_CHECKS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const c of GITLAB_CHECKS) {
    // GL, and never GLI: that one is GitHub's license check, older than GitLab here.
    assert.match(c.id, /^GL[A-HJ-Z]-\d{3}$/, "GitLab check IDs start with GL");
    assert.ok((CATEGORIES as readonly string[]).includes(c.category), c.id);
    assert.ok(c.title && c.why && c.fix, c.id);
    assert.ok(!c.docs || c.docs.startsWith("https://docs.gitlab.com/"), `${c.id} links GitLab's docs`);
    assert.ok(c.requires?.length, `${c.id} names the sources it reads`);
  }
  const dir = new URL("../src/providers/gitlab/checks/", import.meta.url);
  const files = readdirSync(dir).filter((f) => /^export default defineChecks\(/m.test(readFileSync(new URL(f, dir), "utf8")));
  assert.equal(files.length, GITLAB_MODULES.length, `modules on disk: ${files.join(", ")}`);
});

test("every protected branch rule that covers a branch counts, and the loosest of them decides", () => {
  assert.ok(ruleCovers("main", "main") && !ruleCovers("main", "maintenance"));
  assert.ok(ruleCovers("release-*", "release-1.2") && ruleCovers("*", "feature/x") && !ruleCovers("release-*", "main"));
  const level = (n: number) => ({ access_level: n, user_id: null, group_id: null });
  assert.equal(ruleFor([{ name: "release-*", push_access_levels: [level(0)] }], "main"), null, "a rule for other branches doesn't protect this one");
  assert.deepEqual(ruleFor([{ name: "main", push_access_levels: [level(0)], allow_force_push: false }], "main"), {
    rule: "main",
    pushLevel: 0,
    pushNamed: false,
    forcePush: false,
  });
  // "No one" on the exact rule, but a wildcard rule lets developers push and force push: that is what applies.
  const both = ruleFor(
    [
      { name: "main", push_access_levels: [level(0)], allow_force_push: false },
      { name: "ma*", push_access_levels: [level(30), level(40)], allow_force_push: true },
    ],
    "main",
  )!;
  assert.deepEqual([both.rule, both.pushLevel, both.forcePush], ["main", 30, true]);
  // A person named on the rule can push though no role can.
  assert.equal(ruleFor([{ name: "main", push_access_levels: [level(0), { access_level: 40, user_id: 7, group_id: null }] }], "main")!.pushNamed, true);
});

test("findings are rated by what they are about", () => {
  // Developers pushing is the first check; maintainers pushing is only judged once developers can't.
  const open = gitlabInventory({ projects: [project({ protection: rule({ pushLevel: 30 }) })] });
  assert.equal(failing(open, "GLB-001").length, 1);
  assert.equal(evaluateGitlab(open, opts()).results.filter((r) => r.checkId === "GLB-004").length, 0);
  assert.equal(failing(gitlabInventory({ projects: [project({ protection: rule({ pushNamed: true }) })] }), "GLB-004").length, 1);
  // A project nobody has touched for over a year is rated lower.
  assert.equal(failing(gitlabInventory({ projects: [project({ protection: null, updatedAt: NOW - 400 * 86_400_000 })] }), "GLB-001")[0].severity, "low");
  // A plan without approval rules has nothing to judge; a rule that asks for no approval, nothing to weaken.
  for (const approvals of [null, { required: 0, resetOnPush: false, authorApproves: true }])
    assert.equal(evaluateGitlab(gitlabInventory({ projects: [project({ approvals })] }), opts()).results.filter((r) => r.checkId === "GLB-003").length, 0);
  assert.match(
    failing(gitlabInventory({ projects: [project({ approvals: { required: 2, resetOnPush: true, authorApproves: true } })] }), "GLB-003")[0].detail!,
    /the author can approve/,
  );
  // A webhook over plain HTTP has no certificate to check: it is one finding, not two.
  const plain = gitlabInventory({ projects: [project({ hooks: [{ endpoint: "http://chat.example.com", verifiesTls: false }] })] });
  assert.deepEqual([failing(plain, "GLH-001").length, failing(plain, "GLH-002").length], [1, 0]);
  // A write token that expires, and a read token that doesn't, are fine.
  const tokens = [
    { name: "a", scopes: ["write_registry"], expiresAt: "2027-01-01" },
    { name: "b", scopes: ["read_repository"], expiresAt: null },
  ];
  assert.equal(failing(gitlabInventory({ projects: [project({ deployTokens: tokens })] }), "GLH-004").length, 0);
  // An archived project, and a copy pulled from elsewhere, take no pushes.
  assert.equal(
    failing(
      gitlabInventory({ projects: [project({ protection: null, archived: true }), project({ name: "copy", protection: null, mirror: true })] }),
      "GLB-001",
    ).length,
    0,
  );
  // An include from the group's own projects, or pinned to a commit, isn't someone else's moving code.
  const mine = gitlabInventory({
    login: "example/platform",
    dependencies: {
      ...gitlabInventory().dependencies!,
      repos: [
        {
          ...gitlabInventory().dependencies!.repos[0],
          actions: [
            { action: "example/other-subgroup/ci", ref: "main", workflow: ".gitlab-ci.yml" },
            { action: "vendor/ci", ref: "0123456789abcdef0123456789abcdef01234567", workflow: ".gitlab-ci.yml" },
          ],
        },
      ],
    },
  });
  assert.equal(failing(mine, "GLD-004").length, 0);
});

test("a CI configuration's includes from outside its project are read, with the ref each is taken at", () => {
  const ci = [
    "include:",
    "  - project: 'other-group/templates'   # shared",
    "    file: '/build.yml'",
    "    ref: v2",
    "  - project: other-group/no-ref",
    "    file: /x.yml",
    "  - component: gitlab.com/vendor/scanners/sast@1.2.0",
    "  - component: $CI_SERVER_FQDN/vendor/scanners/dast@~latest",
    "  - remote: 'https://ci.example.net/templates/deploy.yml'",
    "  - remote: https://ci.example.net/0123456789abcdef0123456789abcdef01234567/deploy.yml",
    "  - template: Security/SAST.gitlab-ci.yml",
    "  - local: /ci/test.yml",
    "build:",
    "  script: echo project: not-an-include",
  ].join("\n");
  assert.deepEqual(
    ciIncludes(
      new Map([
        [".gitlab-ci.yml", ci],
        ["src/app.yml", "include:\n  - project: ignored/elsewhere\n"],
      ]),
    ).map((a) => `${a.action}@${a.ref}`),
    [
      "other-group/templates@v2",
      "other-group/no-ref@the default branch",
      "vendor/scanners/sast@1.2.0",
      "vendor/scanners/dast@~latest",
      "ci.example.net/templates/deploy.yml@an address that can change",
      "ci.example.net/0123456789abcdef0123456789abcdef01234567/deploy.yml@0123456789abcdef0123456789abcdef01234567",
    ],
  );
});

test("a cloud role's subjects are judged against the entity's groups and projects", () => {
  const groups = [{ host: "gitlab.com", group: "example" }];
  const projects = [
    { host: "gitlab.com", repo: "example/app", defaultBranch: "main", reviewed: true },
    { host: "gitlab.com", repo: "example/tools/cli", defaultBranch: "main", reviewed: false },
  ];
  assert.deepEqual(judgeGitlabTrust([], groups, projects).open, ["no subject condition"]);
  assert.deepEqual(judgeGitlabTrust(["project_path:*"], groups, projects).open, ["project_path:*"]);
  assert.deepEqual(judgeGitlabTrust(["project_path:vendor/app:ref_type:branch:ref:main"], groups, projects).outside, ["vendor"]);
  // The protected default branch of a project that takes merge requests only: trusted, and nothing to report.
  const exact = judgeGitlabTrust(["project_path:example/app:ref_type:branch:ref:main"], groups, projects);
  assert.deepEqual([exact.outside, exact.anyBranch, exact.unreviewed, exact.trusted], [[], [], [], 1]);
  assert.deepEqual(judgeGitlabTrust(["project_path:example/app:*"], groups, projects).anyBranch, ["example/app"]);
  assert.deepEqual(judgeGitlabTrust(["project_path:example/tools/cli:ref_type:branch:ref:main"], groups, projects).unreviewed, ["example/tools/cli (main)"]);
  // Every project of the group, from any branch.
  assert.equal(judgeGitlabTrust(["project_path:example/*"], groups, projects).anyBranch!.length, 2);
  // Without the entity's groups, nothing is said about who is outside.
  assert.equal(judgeGitlabTrust(["project_path:vendor/app:ref_type:branch:ref:main"], null, null).outside, null);
});

test("a cloud role keeps only which GitLab may assume it and from which subjects", () => {
  const subs = ["project_path:Example/App:ref_type:branch:ref:main"];
  // AWS names the provider by its host, and the condition's claim by that host.
  const aws = awsTrustOf([
    {
      Effect: "Allow",
      Principal: { Federated: "arn:aws:iam::111122223333:oidc-provider/gitlab.example.com" },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: {
        StringEquals: { "gitlab.example.com:aud": "https://gitlab.example.com", "gitlab.example.com:sub": subs },
        StringNotLike: { "gitlab.example.com:sub": "project_path:x/*" },
      },
    },
  ]);
  assert.deepEqual(aws[0].oidc, { host: "gitlab.example.com", subjects: ["project_path:example/app:ref_type:branch:ref:main"] });
  assert.equal(aws[0].github, undefined);
  // A SAML provider isn't an OIDC one.
  assert.equal(
    awsTrustOf([{ Effect: "Allow", Principal: { Federated: "arn:aws:iam::111122223333:saml-provider/okta" }, Action: "sts:AssumeRoleWithSAML" }])[0].oidc,
    undefined,
  );

  // Alibaba Cloud names the provider by a name of its own: its issuer comes from the list of providers, or from the condition.
  const arn = "acs:ram::1234567890123456:oidc-provider/ci";
  const statement = (condition: Record<string, Record<string, string | string[]>>) => [
    { Effect: "Allow", Principal: { Federated: [arn] }, Action: "sts:AssumeRoleWithOIDC", Condition: condition },
  ];
  const listed = alibabaTrustOf(statement({ StringLike: { "oidc:sub": subs } }), new Set(), new Map([[arn, "gitlab.com"]]));
  assert.deepEqual(listed[0].oidc, { host: "gitlab.com", subjects: ["project_path:example/app:ref_type:branch:ref:main"] });
  const named = alibabaTrustOf(statement({ StringEquals: { "oidc:iss": "https://gitlab.example.com", "oidc:sub": subs } }), new Set());
  assert.equal(named[0].oidc!.host, "gitlab.example.com");
  // A provider whose issuer nobody says isn't taken for anyone's.
  assert.equal(alibabaTrustOf(statement({ StringLike: { "oidc:sub": subs } }), new Set())[0].oidc, undefined);
  // GitHub's stays GitHub's.
  assert.deepEqual(alibabaTrustOf(statement({ StringLike: { "oidc:sub": "repo:example/*" } }), new Set([arn]))[0].github, ["repo:example/*"]);
});

test("what a group shares with the entity is left out when it couldn't all be read", () => {
  const inv = gitlabInventory({
    projects: [
      project({ pagesDomains: ["docs.example.com"], protection: rule({ pushLevel: 30 }) }),
      project({ id: 2, name: "old", fullPath: "example/old", archived: true }),
    ],
  });
  assert.deepEqual(gitlabLinks(inv), {
    gitlabGroups: [{ host: "gitlab.example.com", group: "example" }],
    gitlabPages: [{ host: "docs.example.com", repo: "example/web" }],
    gitlabProjects: [
      { host: "gitlab.example.com", repo: "example/web", defaultBranch: "main", reviewed: false },
      { host: "gitlab.example.com", repo: "example/old", defaultBranch: "main", reviewed: true },
    ],
  });
  assert.deepEqual(Object.keys(gitlabLinks({ ...inv, unreadable: ["pages", "protection"] })), ["gitlabGroups"]);
  assert.deepEqual(Object.keys(gitlabLinks({ ...inv, unreadable: ["projects"] })), ["gitlabGroups"]);
  assert.ok(
    pointsAtGitlabPages("CNAME", "example.gitlab.io") && pointsAtGitlabPages("A", "35.185.44.232") && !pointsAtGitlabPages("CNAME", "example.github.io"),
  );
});

test("a project's row says how its default branch is protected", () => {
  const rows = repoRows(
    gitlabInventory({
      projects: [
        project({ name: "a" }),
        project({ name: "b", approvals: null }),
        project({ name: "c", protection: rule({ pushLevel: 30 }) }),
        project({ name: "d", protection: null }),
        project({ name: "e", protection: undefined }),
      ],
    }),
    [],
  );
  assert.deepEqual(
    rows.map((r) => r.protection),
    ["Merge request, 1 approval", "Merge request", "Protected", "None", null],
  );
  assert.deepEqual([rows[0].owner, rows[0].url], ["example", "https://gitlab.example.com/example/web"]);
});
