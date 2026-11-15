// GitHub scans end to end against the mocked GitHub API (dev/mock/github.ts): the
// scanner reads only, apart from one request for a read-only installation token;
// secrets never reach storage or an API response; findings land on the right
// organization; and XP-009 compares Cloudflare DNS with the entity's Pages sites.

import { test, describe, after, before } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Scanner } from "../src/scanner.ts";
import { installMockCloudflare, MOCK_ACCOUNT } from "../dev/mock/cloudflare.ts";
import {
  installMockGithub,
  MOCK_GITHUB_ACCOUNT,
  MOCK_GITHUB_APP_ID,
  MOCK_GITHUB_TOKEN,
  MOCK_GITHUB_TOKEN_ONE_LINE,
  MOCK_LEAKED_SECRET,
} from "../dev/mock/github.ts";
import { seedAccount, seedAws, seedGithub, testRepo } from "../dev/mock/accounts.ts";
import { installMockAws, MOCK_AWS_ACCOUNT } from "../dev/mock/aws.ts";
import { appJwt, nextPage, normalizePem, parseCredentials } from "../src/providers/github/client.ts";
import { GITHUB_PERMISSION_KEYS, githubAppTemplate } from "../src/shared/github.ts";
import { makeApp } from "./helpers/app.ts";
import { maskToken } from "../src/config.ts";

const ALLOWED_POST = /^\/app\/installations\/\d+\/access_tokens$/;

function setup(o: { cloudflare?: boolean } = {}) {
  const { repo, vault } = testRepo();
  if (o.cloudflare) seedAccount(repo, vault);
  seedGithub(repo, vault, { entity: "Mock Group" });
  return { repo, vault, scanner: new Scanner(repo, vault, () => {}) };
}

describe("GitHub scan against the mocked API", () => {
  const writes: { path: string; body: string }[] = [];
  const queries: string[] = [];
  let restore: () => void;
  const install = (deny?: RegExp[]) => {
    const cf = installMockCloudflare();
    const gh = installMockGithub({
      deny,
      onRequest: (u, init) => {
        if ((init?.method || "GET") !== "GET") writes.push({ path: u.pathname, body: String(init?.body ?? "") });
        queries.push(u.pathname + u.search);
      },
    });
    restore = () => {
      gh();
      cf();
    };
  };
  before(() => install());
  after(() => restore());

  test("reads only, asks for a read-only token, finds what the mock data holds, and stores no secret", async () => {
    const { repo, scanner } = setup();
    const [result] = await scanner.start("test").done;
    assert.ok(result, "the scan finished");

    // The one write is the installation token, and it asks for read access to Keelson's permissions only.
    assert.ok(writes.length >= 1);
    for (const w of writes) {
      assert.match(w.path, ALLOWED_POST, "the GitHub scanner sends nothing but GET besides the token request");
      const asked = JSON.parse(w.body).permissions as Record<string, string>;
      assert.ok(
        Object.values(asked).every((v) => v === "read"),
        JSON.stringify(asked),
      );
      assert.ok(
        Object.keys(asked).every((k) => (GITHUB_PERMISSION_KEYS as string[]).includes(k)),
        "nothing beyond Keelson's list, though the App has contents: write",
      );
    }
    assert.ok(
      queries.some((q) => q.startsWith("/orgs/mock-org/secret-scanning/alerts") && q.includes("hide_secret=true")),
      "alerts are read without values",
    );
    assert.ok(
      queries.some((q) => q.includes("page=2")),
      "lists follow GitHub's Link header",
    );

    const findings = repo.findings.forScan(result.scanId, repo.settings.get().slaDays);
    const ids = new Set(findings.map((f) => f.checkId));
    for (const id of [
      "GID-001",
      "GID-002",
      "GID-003",
      "GID-004",
      "GID-005",
      "GID-006",
      "GID-007",
      "GBR-001",
      "GBR-002",
      "GBR-003",
      "GBR-004",
      "GRL-001",
      "GSC-001",
      "GSC-002",
      "GSC-003",
      "GSC-004",
      "GSC-005",
      "GSC-006",
      "GSC-007",
      "GSC-008",
      "GAC-001",
      "GAC-002",
      "GAC-003",
      "GAC-004",
      "GAC-005",
      "GHK-001",
      "GHK-002",
      "GHK-003",
      "GHK-004",
      "GPG-001",
    ])
      assert.ok(ids.has(id), `expected ${id}`);
    assert.ok(findings.every((f) => f.provider === "github"));
    const branch = (repoName: string) => findings.filter((f) => f.checkId.startsWith("GBR-") && f.zone === repoName);
    assert.equal(branch("api").length, 0, "an organization ruleset protects api");
    assert.equal(branch("old-site").length + branch("scratch").length, 0, "archived and empty repositories have no branch to protect");
    assert.ok(!findings.some((f) => f.checkId === "GHK-004" && f.resource.startsWith("keelson")), "Keelson's own App isn't reported");
    assert.deepEqual(
      findings.filter((f) => f.checkId === "GBR-004").map((f) => f.zone),
      ["infra"],
      "only the branch whose approvals survive new commits",
    );
    const runnerFindings = Object.fromEntries(findings.filter((f) => f.checkId === "GAC-005").map((f) => [f.zone, f.severity]));
    assert.deepEqual(
      runnerFindings,
      { web: "critical", handbook: "high" },
      "web reaches a group's runner that keeps state; handbook has an ephemeral runner of its own; private api isn't judged",
    );
    assert.deepEqual(
      findings.filter((f) => f.checkId === "GRL-001").map((f) => f.zone),
      ["handbook"],
      "only the repository that publishes releases",
    );
    assert.ok(!findings.some((f) => f.checkId === "GHK-004" && f.resource === "mock-linter"), "an App on selected repositories isn't reported");

    const scan = repo.scans.latest(MOCK_GITHUB_ACCOUNT)!;
    const stored = JSON.stringify({ snapshot: scan.snapshot, findings });
    for (const secret of [MOCK_LEAKED_SECRET, "mock-hook-secret", "/ingest/github", "AAAAmockpublickey", "mock-installation-token", "PRIVATE KEY"])
      assert.ok(!stored.includes(secret), `stored data must not contain ${secret}`);

    const snap = JSON.parse(scan.snapshot as string);
    assert.equal(snap.accountName, "Mock Org");
    assert.deepEqual(
      snap.repos.map((r: { name: string }) => r.name),
      ["api", "handbook", "infra", "old-site", "scratch", "web"],
    );
    assert.equal(snap.repos.find((r: { name: string }) => r.name === "api").protection, "Pull request, 2 approvals");
    assert.equal(snap.repos.find((r: { name: string }) => r.name === "web").protection, "None");
    assert.deepEqual(snap.links.githubPages, [{ host: "docs.mock.example", repo: "web" }]);
    assert.deepEqual(snap.links.githubOrgs, ["mock-org"]);
    assert.deepEqual(
      snap.links.githubRepos.filter((r: { reviewed: boolean }) => r.reviewed).map((r: { repo: string }) => r.repo),
      ["mock-org/api", "mock-org/handbook", "mock-org/infra", "mock-org/old-site"],
    );
    assert.ok(
      !findings.some((f) => f.checkId === "GSC-008" && f.zone !== "web" && f.zone !== "handbook"),
      "only public repositories are asked for code scanning",
    );
    assert.ok(
      snap.coverage.every((c: { ok: boolean }) => c.ok),
      JSON.stringify(snap.coverage),
    );
  });

  test("a permission the App wasn't given is a coverage gap and its checks are skipped, not passed", async () => {
    restore();
    install([/\/hooks$/]);
    const { repo, scanner } = setup();
    const [result] = await scanner.start("test").done;
    const snap = JSON.parse(repo.scans.latest(MOCK_GITHUB_ACCOUNT)!.snapshot as string);
    const gap = snap.coverage.find((c: { key: string }) => c.key === "orgHooks");
    assert.equal(gap.ok, false);
    assert.ok(gap.skippedChecks.includes("GHK-001"));
    assert.equal(snap.checks["GHK-001"], undefined, "no pass is recorded for a skipped check");
    const ids = new Set(repo.findings.forScan(result.scanId, repo.settings.get().slaDays).map((f) => f.checkId));
    assert.ok(!ids.has("GHK-001") && !ids.has("GHK-002") && ids.has("GID-001"));
    restore();
    install();
  });

  test("an App registered before Keelson read self-hosted runners reports the missing permission and skips the runner check", async () => {
    restore();
    install([/\/actions\/runner/]);
    const { repo, scanner } = setup();
    const [result] = await scanner.start("test").done;
    const snap = JSON.parse(repo.scans.latest(MOCK_GITHUB_ACCOUNT)!.snapshot as string);
    const gap = snap.coverage.find((c: { key: string }) => c.key === "runners");
    assert.equal(gap.ok, false);
    assert.match(gap.permission, /Self-hosted runners: Read-only/);
    assert.ok(gap.skippedChecks.includes("GAC-005"));
    const ids = new Set(repo.findings.forScan(result.scanId, repo.settings.get().slaDays).map((f) => f.checkId));
    assert.ok(!ids.has("GAC-005") && ids.has("GAC-004"), "the fork pull request policy is still read");
    restore();
    install();
  });

  test("Cloudflare DNS that points at GitHub Pages is compared with the entity's Pages sites", async () => {
    const { repo, scanner } = setup({ cloudflare: true });
    await scanner.start("setup").done;
    await scanner.start("manual").done;
    const cf = repo.findings.forScan(repo.scans.latest(MOCK_ACCOUNT)!.id, repo.settings.get().slaDays);
    const dangling = cf.filter((f) => f.checkId === "XP-009");
    assert.deepEqual(
      dangling.map((f) => f.resource),
      ["blog.mock.example"],
      "only the record no Pages site uses",
    );
    assert.equal(dangling[0].confidence, "likely");
  });

  test("an AWS role that GitHub Actions can assume is compared with the entity's repositories", async () => {
    const aws = installMockAws();
    try {
      const { repo, vault } = testRepo();
      seedGithub(repo, vault, { entity: "Mock Group" });
      seedAws(repo, vault, { entity: "Mock Group" });
      const scanner = new Scanner(repo, vault, () => {});
      await scanner.start("setup").done;
      await scanner.start("manual").done;
      const found = repo.findings.forScan(repo.scans.latest(MOCK_AWS_ACCOUNT)!.id, repo.settings.get().slaDays);
      const any = found.find((f) => f.checkId === "XP-011");
      assert.equal(any?.resource, "github-deploy");
      assert.match(any?.detail ?? "", /any branch or pull request of mock-org\//);
      assert.ok(!found.some((f) => f.checkId === "XP-010"), "the role names the entity's own organization");
      assert.deepEqual(
        found.filter((f) => f.checkId === "AID-012").map((f) => f.resource),
        ["github-legacy"],
        "a role with no subject condition trusts every repository on GitHub",
      );
    } finally {
      aws();
    }
  });

  test("XP-009 is skipped when the entity has no GitHub organization", async () => {
    const { repo, vault } = testRepo();
    seedAccount(repo, vault);
    await new Scanner(repo, vault, () => {}).start("test").done;
    const snap = JSON.parse(repo.scans.latest(MOCK_ACCOUNT)!.snapshot as string);
    assert.equal(snap.checks["XP-009"], undefined);
  });

  test("an App is verified through the API, its organizations listed and probed, and nothing secret comes back", async () => {
    const { json, call, repo: r, scanner, cleanup } = makeApp();
    try {
      const v = await json("/api/accounts/verify", "POST", { provider: "github", token: MOCK_GITHUB_TOKEN_ONE_LINE, accountIds: [MOCK_GITHUB_ACCOUNT] });
      assert.equal(v.token.valid, true, "a key pasted into a one-line input still works");
      assert.deepEqual(
        v.accounts.map((a: { id: string; name: string }) => [a.id, a.name]),
        [[MOCK_GITHUB_ACCOUNT, "mock-org"]],
        "an installation on a personal account isn't offered",
      );
      assert.ok(v.probes[MOCK_GITHUB_ACCOUNT].every((p: { ok: boolean }) => p.ok));
      assert.match(v.templateUrl, /^https:\/\/github\.com\/settings\/apps\/new\?/);

      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const stranger = `${MOCK_GITHUB_APP_ID}:${privateKey.export({ type: "pkcs1", format: "pem" })}`;
      const wrongKey = await json("/api/accounts/verify", "POST", { provider: "github", token: stranger });
      assert.equal(wrongKey.token.valid, false);
      assert.match(wrongKey.token.message, /private key/);
      const garbage = await json("/api/accounts/verify", "POST", { provider: "github", token: "123:not a key" });
      assert.equal(garbage.token.valid, false);
      assert.match(garbage.token.message, /App's ID/);

      const saved = await json("/api/accounts", "POST", {
        provider: "github",
        token: MOCK_GITHUB_TOKEN,
        accountIds: [MOCK_GITHUB_ACCOUNT],
        entityName: "Code",
      });
      assert.deepEqual(saved.added, [MOCK_GITHUB_ACCOUNT]);
      assert.equal(r.accounts.get(MOCK_GITHUB_ACCOUNT)?.provider, "github");
      await scanner.start("test").done;
      const repos = await json("/api/repos");
      assert.ok(repos.repos.some((x: { name: string }) => x.name === "web"));
      for (const p of ["/api/accounts", "/api/overview", "/api/findings", "/api/repos", "/api/scans", "/api/report", "/api/export/findings.csv"]) {
        const text = await (await call(p)).text();
        for (const secret of ["PRIVATE KEY", MOCK_LEAKED_SECRET, "mock-hook-secret", "mock-installation-token"])
          assert.ok(!text.includes(secret), `${secret} leaked in ${p}`);
      }
    } finally {
      cleanup();
    }
  });
});

test("the private key is accepted however it was pasted, and nothing else is", () => {
  const app = parseCredentials(MOCK_GITHUB_TOKEN)!;
  assert.equal(app.appId, MOCK_GITHUB_APP_ID);
  assert.ok(parseCredentials(MOCK_GITHUB_TOKEN_ONE_LINE));
  assert.ok(parseCredentials(MOCK_GITHUB_TOKEN.replace(/\n/g, "\\n")), "escaped line breaks");
  assert.ok(parseCredentials(MOCK_GITHUB_TOKEN.replace(/\n/g, " ")), "spaces for line breaks");
  assert.equal(parseCredentials(MOCK_GITHUB_TOKEN.replace(MOCK_GITHUB_APP_ID, "not-an-id")), null);
  assert.equal(parseCredentials(`${MOCK_GITHUB_APP_ID}:-----BEGIN RSA PRIVATE KEY-----bm90IGEga2V5-----END RSA PRIVATE KEY-----`), null);
  assert.equal(normalizePem("no key here"), null);

  const [h, p] = appJwt(app, Date.parse("2026-06-01T00:00:00Z")).split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h, "base64url").toString()), { alg: "RS256", typ: "JWT" });
  const claims = JSON.parse(Buffer.from(p, "base64url").toString());
  assert.equal(claims.iss, Number(MOCK_GITHUB_APP_ID));
  assert.ok(claims.exp - claims.iat <= 600, "GitHub allows ten minutes at most");
});

test("a GitHub App is named by its App ID wherever a credential hint is shown", () => {
  assert.equal(maskToken(MOCK_GITHUB_TOKEN), `App ${MOCK_GITHUB_APP_ID}`);
  assert.equal(maskToken(MOCK_GITHUB_TOKEN_ONE_LINE), `App ${MOCK_GITHUB_APP_ID}`);
  assert.equal(maskToken("abcdefghijkl"), "…ijkl", "other credentials keep their last four characters");
});

test("pagination follows only GitHub's own next links", () => {
  assert.equal(
    nextPage('<https://api.github.com/orgs/x/hooks?page=2>; rel="next", <https://api.github.com/orgs/x/hooks?page=3>; rel="last"'),
    "/orgs/x/hooks?page=2",
  );
  assert.equal(nextPage('<https://api.github.com/x?page=3>; rel="last"'), null);
  assert.equal(nextPage('<https://evil.example/x?page=2>; rel="next"'), null, "a next link to another host is never followed");
  assert.equal(nextPage(null), null);
});

test("the App registration link asks for read access only, under the organization when named", () => {
  const u = new URL(githubAppTemplate("mock-org"));
  assert.equal(u.pathname, "/organizations/mock-org/settings/apps/new");
  assert.equal(u.searchParams.get("webhook_active"), "false");
  for (const k of GITHUB_PERMISSION_KEYS) assert.equal(u.searchParams.get(k), "read", k);
  assert.ok(![...u.searchParams.values()].includes("write"));
  assert.ok((u.searchParams.get("name") ?? "").length <= 34);
  assert.equal(new URL(githubAppTemplate(null)).pathname, "/settings/apps/new");
});
