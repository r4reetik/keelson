// A Gitea scan against the mock instance: it only reads, it never follows a
// redirect or keeps a secret, it concludes nothing an instance didn't say, and
// it reaches a self-hosted instance through the network chosen for Gitea.

import { test, describe, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { installMockCloudflare } from "../dev/mock/cloudflare.ts";
import {
  installMockGitea,
  MOCK_GITEA_ACCOUNT,
  MOCK_GITEA_BASE,
  MOCK_GITEA_SECRETS,
  MOCK_GITEA_SOURCE_CONTENT,
  MOCK_GITEA_SOURCE_FILE,
  MOCK_GITEA_TOKEN,
  type MockGiteaOptions,
} from "../dev/mock/gitea.ts";
import { seedGitea } from "../dev/mock/accounts.ts";
import { makeApp } from "./helpers/app.ts";
import { net } from "../src/core/net.ts";
import { accountIdOf, GiteaClient, instanceAddress, parseCredential } from "../src/providers/gitea/client.ts";
import { gitea } from "../src/providers/gitea/index.ts";
import { ACCOUNT_ID_PATTERN, PLATFORMS, PROVIDER_INFO, providerForId, zoneWord } from "../src/shared/providers.ts";
import { PROVIDER } from "../src/providers/index.ts";
import { Store } from "../src/store/db.ts";
import { Repo } from "../src/store/repo.ts";
import type { ScanInput } from "../src/providers/types.ts";

const KEY = MOCK_GITEA_TOKEN.slice(MOCK_GITEA_TOKEN.lastIndexOf(":") + 1);

let restore = () => {};
afterEach(() => restore());
const mock = (o: MockGiteaOptions = {}) => {
  restore = installMockGitea(o);
};

function freshRepo() {
  const repo = new Repo(new Store(":memory:"));
  const entity = repo.entities.create("Mock Group");
  repo.accounts.add({ id: MOCK_GITEA_ACCOUNT, provider: "gitea", name: null, entityId: entity.id, tokenId: "t", tokenKind: "user" });
  return repo;
}

/** One scan. Given the repo of an earlier one, it finds what that scan kept (each repository's SBOM). */
async function scan(repo = freshRepo()) {
  const account = repo.accounts.get(MOCK_GITEA_ACCOUNT)!;
  const input: ScanInput = {
    token: MOCK_GITEA_TOKEN,
    account,
    engine: { orgDomains: [], disabledChecks: new Set(), severityOverrides: {} },
    probeTakeovers: false,
    previous: null,
    cache: repo.cache.for(account.id),
    toolDir: null,
    onProgress: () => {},
  };
  return gitea.scan(input);
}
const failed = (out: Awaited<ReturnType<typeof scan>>) =>
  out.evaluation.findings
    .filter((f) => !f.pass)
    .map((f) => `${f.checkId} ${f.resource}`)
    .sort();

describe("the credential", () => {
  test("is an instance's address and a token, split at the last colon", () => {
    assert.deepEqual(parseCredential(MOCK_GITEA_TOKEN), { base: MOCK_GITEA_BASE, token: KEY });
    assert.deepEqual(parseCredential(`http://gitea.internal:3000/git/:${KEY}`), { base: "http://gitea.internal:3000/git", token: KEY });
    // Pasted from the address bar or the API's page: only where the instance runs counts.
    assert.equal(instanceAddress("https://Git.Example.com/api/v1/user"), "https://git.example.com");
    assert.equal(instanceAddress("https://example.com/gitea/user/settings/applications"), "https://example.com/gitea");
    assert.equal(instanceAddress("https://git.example.com/explore/repos"), "https://git.example.com");
    for (const bad of [
      KEY,
      `git.example.com:${KEY}`,
      `ftp://git.example.com:${KEY}`,
      `https://user:pass@git.example.com:${KEY}`,
      `${MOCK_GITEA_BASE}:short`,
      `${MOCK_GITEA_BASE}:`,
    ])
      assert.equal(parseCredential(bad), null, bad);
    assert.equal(gitea.instanceOf!(`http://gitea.internal:3000/git:${KEY}`), "http://gitea.internal:3000");
    assert.equal(gitea.instanceOf!("nonsense"), null);
  });

  test("an organization's ID says which instance it is on, and is nobody else's", () => {
    assert.match(MOCK_GITEA_ACCOUNT, ACCOUNT_ID_PATTERN.gitea);
    assert.notEqual(accountIdOf("https://git.example.com", 7), accountIdOf("https://git.other.example", 7));
    assert.equal(accountIdOf("https://Git.Example.com", 7), accountIdOf("https://git.example.com", 7));
    assert.equal(providerForId(MOCK_GITEA_ACCOUNT), "gitea");
    assert.equal(providerForId("gh_7"), "github");
    assert.equal(zoneWord(["gitea"]), "Repository");
    assert.ok(PLATFORMS.includes("gitea"));
    // A platform people host has no one API host: the instance comes from each credential.
    assert.equal(PROVIDER_INFO.gitea.checkHost, null);
    assert.ok(PROVIDER_INFO.gitea.selfHosted && PROVIDER.gitea.instanceOf);
  });

  test("is verified, lists the organizations its user belongs to, and says what it can't read", async () => {
    mock({ admin: false });
    assert.equal((await gitea.verify(MOCK_GITEA_TOKEN, [])).valid, true);
    assert.deepEqual(await gitea.listAccounts(MOCK_GITEA_TOKEN), [{ id: MOCK_GITEA_ACCOUNT, name: "Mock Platform" }]);
    const probes = await gitea.probe(MOCK_GITEA_TOKEN, MOCK_GITEA_ACCOUNT);
    const twoFactor = probes.find((p) => /two-factor/.test(p.source))!;
    assert.equal(twoFactor.ok, false);
    assert.match(twoFactor.message!, /read:admin/, "Gitea's own words name the scope that is missing");
    assert.ok(probes.filter((p) => p !== twoFactor).every((p) => p.ok));

    const wrong = await gitea.verify(`${MOCK_GITEA_BASE}:${"x".repeat(40)}`, []);
    assert.equal(wrong.valid, false);
    assert.match(wrong.message!, /didn't accept the token/);
    assert.match((await gitea.verify("https://git.example.com", [])).message!, /starting with https:\/\//);
    await assert.rejects(() => gitea.probe(MOCK_GITEA_TOKEN, accountIdOf(MOCK_GITEA_BASE, 99)), /no longer belongs to this organization/);
  });
});

describe("a scan", () => {
  test("only sends GET, to the instance's API, with the token in a header", async () => {
    const seen: { method: string; path: string; auth: string | null; redirect: string | undefined }[] = [];
    mock({
      onRequest: (url, init) =>
        seen.push({
          method: init?.method || "GET",
          path: url.pathname + url.search,
          auth: new Headers(init?.headers).get("authorization"),
          redirect: init?.redirect,
        }),
    });
    const out = await scan();
    // A few for the organization, about five for each of its seven repositories, and each one's file list and dependency files.
    assert.ok(seen.length > 30 && seen.length < 110, `${seen.length} requests`);
    assert.equal(out.calls, seen.length);
    assert.deepEqual([...new Set(seen.map((s) => s.method))], ["GET"]);
    assert.ok(seen.every((s) => s.path.startsWith("/api/v1/")));
    assert.ok(
      seen.every((s) => s.redirect === "manual"),
      "a redirect is never followed",
    );
    assert.ok(
      seen.every((s) => !s.path.includes(KEY)),
      "the token is never in an address",
    );
    // One request goes without the token, to learn what anyone is shown.
    assert.deepEqual(
      seen.filter((s) => s.auth !== `token ${KEY}`).map((s) => [s.path, s.auth]),
      [["/api/v1/repos/platform/docs", null]],
    );
    // Pages are asked for by number, fifty at a time.
    assert.ok(seen.some((s) => /\/orgs\/platform\/repos\?page=1&limit=50$/.test(s.path)));
  });

  test("finds what is wrong with the mock organization, and nothing that isn't", async () => {
    mock();
    const out = await scan();
    assert.equal(out.accountName, "Mock Platform");
    assert.deepEqual(
      out.coverage.filter((c) => !c.ok),
      [],
    );
    assert.deepEqual(failed(out), [
      "TEB-001 infra:main",
      "TEB-001 web:main",
      "TEB-002 docs:main",
      "TEB-003 docs:main",
      "TEB-004 docs:main",
      "TED-001 mock-xml-parser (npm)",
      "TED-002 mock.example/httpkit (Go)",
      "TED-004 web",
      "TED-005 infra",
      "TED-006 mock-readline (npm)",
      "TEH-001 platform:http://chat.mock-group.example",
      "TEH-002 web:deploy (write)",
      "TEI-001 ben",
      "TEI-001 gus",
      "TEI-002 platform",
      "TEI-003 release",
      "TEI-004 web:contractor-x",
      "TER-001 docs",
      "TER-001 web",
      "TER-002 infra",
    ]);
    const by = (id: string, resource: string) => out.evaluation.findings.find((f) => f.checkId === id && f.resource === resource)!;
    assert.equal(by("TEI-001", "ben").severity, "high", "an owner without a second factor");
    assert.equal(by("TEI-001", "gus").severity, "medium");
    assert.equal(by("TER-001", "web").confidence, "confirmed");
    assert.match(by("TER-002", "infra").detail!, /code\.partner\.example/);
    assert.equal(by("TEB-001", "web:main").link, `${MOCK_GITEA_BASE}/platform/web/settings/branches`);
    // The second rule is the one that covers "main": the first is for release branches.
    assert.match(by("TEB-003", "docs:main").detail!, /still counts after new commits/);
    // Someone who is in the organization isn't an outsider, whatever access they were also given on the repository.
    assert.ok(!out.evaluation.findings.some((f) => f.checkId === "TEI-004" && /gus|reviewer-y/.test(f.resource!)));
    // Someone without a second factor who isn't a member of this organization is somebody else's finding.
    assert.ok(!failed(out).some((f) => f.includes("someone-else")));

    const rows = out.snapshot.repos!;
    assert.deepEqual(
      rows.map((r) => [r.name, r.visibility, r.protection]),
      [
        ["docs", "public", "Pull request, 1 approval"],
        ["infra", "private", "None"],
        ["legacy-billing", "private", null],
        ["payments", "private", "Pull request, 2 approvals"],
        ["scratch", "private", null],
        ["upstream-copy", "private", null],
        ["web", "public", "Protected"],
      ],
    );
    assert.equal(rows[0].url, `${MOCK_GITEA_BASE}/platform/docs`);
  });

  test("reads every page whatever the instance's page size, and stops where a list ends or isn't paged", async () => {
    mock();
    const whole = failed(await scan());
    for (const o of [{ pageSize: 2 }, { pageSize: 3, noTotals: true }, { noTotals: true }]) {
      restore();
      let requests = 0;
      mock({ ...o, onRequest: () => requests++ });
      assert.deepEqual(failed(await scan()), whole, JSON.stringify(o));
      assert.ok(requests < 150, `${requests} requests with ${JSON.stringify(o)}`);
    }
  });

  test("keeps no secret: not the token, a webhook's path, secret or header, a mirror's password or a key", async () => {
    mock();
    const stored = JSON.stringify(await scan());
    for (const secret of [KEY, ...MOCK_GITEA_SECRETS, MOCK_GITEA_SOURCE_CONTENT]) assert.ok(!stored.includes(secret), `${secret} was stored`);
    assert.match(stored, /chat\.mock-group\.example/, "the host a webhook delivers to is kept");
  });

  test("dependencies come from manifest and lock files only: the code is listed and never fetched", async () => {
    const blobs: string[] = [];
    const given: string[][] = [];
    mock({ onRequest: (url) => /\/git\/blobs\//.test(url.pathname) && blobs.push(url.pathname), anchore: { onSyft: (files) => given.push(files) } });
    const repo = freshRepo();
    const out = await scan(repo);
    // Six dependency files across three repositories; the source files beside them were listed and left alone.
    assert.equal(blobs.length, 6);
    const fetched = given.flat().sort();
    assert.deepEqual(fetched, [".gitea/workflows/ci.yml", "go.mod", "go.sum", "package-lock.json", "package.json", "requirements.txt"]);
    assert.ok(!fetched.includes(MOCK_GITEA_SOURCE_FILE));
    const cache = repo.cache.for(MOCK_GITEA_ACCOUNT);
    assert.ok(!JSON.stringify(cache.keys("").map((k) => cache.get(k))).includes(MOCK_GITEA_SOURCE_CONTENT));

    const by = (id: string) => out.evaluation.findings.find((f) => f.checkId === id && !f.pass)!;
    assert.equal(by("TED-001").severity, "critical");
    assert.match(by("TED-004").detail!, /mock-actions\/deploy@v2 is used by a tag/, "the action pinned to a commit, and actions/checkout, aren't counted");
    assert.equal(by("TED-004").link, `${MOCK_GITEA_BASE}/platform/web/src/branch/main/.gitea/workflows/ci.yml`);
    assert.equal(by("TED-005").link, `${MOCK_GITEA_BASE}/platform/infra/src/branch/main/`);
    const web = out.snapshot.repos!.find((r) => r.name === "web")!;
    assert.equal(web.dependencies!.packages, 2);
    assert.ok(web.dependencies!.ecosystems.includes("npm"));
    // An archived repository, an empty one and a copy pulled from elsewhere have no dependencies read.
    assert.deepEqual(cache.keys("deps:").sort(), ["deps:docs", "deps:infra", "deps:payments", "deps:web"]);

    // Nothing changed: the next scan lists the files again and fetches none of them.
    blobs.length = 0;
    given.length = 0;
    assert.deepEqual(failed(await scan(repo)), failed(out));
    assert.deepEqual([blobs.length, given.length], [0, 0]);
  });

  test("a long file list comes in pages and is read whole", async () => {
    mock();
    const whole = failed(await scan());
    restore();
    const trees: string[] = [];
    mock({ treePage: 2, onRequest: (url) => /\/git\/trees\//.test(url.pathname) && trees.push(url.search) });
    assert.deepEqual(failed(await scan()), whole);
    assert.ok(
      trees.some((q) => /page=3/.test(q)),
      "web has five files: three pages of two",
    );
  });

  test("without Syft or Grype the dependency checks are skipped, and say which tool is missing", async () => {
    mock({ anchore: { missing: ["syft", "grype", "grant"] } });
    const out = await scan();
    assert.deepEqual(
      out.coverage
        .filter((c) => !c.ok)
        .map((c) => c.key)
        .sort(),
      ["grant", "grype", "syft"],
    );
    assert.ok(!out.evaluation.results.some((r) => /^TED-00[1236]/.test(r.checkId)), "no vulnerability or license is concluded");
    // What needs only the files is still judged.
    assert.ok(failed(out).includes("TED-004 web") && failed(out).includes("TED-005 infra"));
  });

  test("an instance that asks everyone to sign in shows its public repositories to nobody outside", async () => {
    mock({ requireSignIn: true });
    assert.ok(!failed(await scan()).some((f) => f.startsWith("TER-001")));
  });

  test("what a token can't read is a gap that names the scope, and its checks are skipped, not passed", async () => {
    mock({ admin: false });
    const out = await scan();
    const gaps = out.coverage.filter((c) => !c.ok);
    assert.deepEqual(
      gaps.map((c) => [c.key, c.status, c.skippedChecks]),
      [["twoFactor", 403, ["TEI-001"]]],
    );
    assert.match(gaps[0].message!, /read:admin/);
    assert.ok(!out.evaluation.results.some((r) => r.checkId === "TEI-001"));

    restore();
    mock({ notAdmin: true });
    const limited = await scan();
    assert.deepEqual(
      limited.coverage
        .filter((c) => !c.ok)
        .map((c) => c.key)
        .sort(),
      ["collaborators", "deployKeys", "protection", "pushMirrors", "repoHooks"],
    );
    assert.ok(!limited.evaluation.results.some((r) => /^TEB-|^TEH-002|^TEI-004|^TER-002/.test(r.checkId)), "nothing is said about what couldn't be read");
    assert.ok(limited.snapshot.repos!.every((r) => r.protection === null));
  });

  test("an older instance that ignores the two-factor question is never taken to say nobody has it", async () => {
    mock({ legacy: true });
    const out = await scan();
    const gap = out.coverage.find((c) => c.key === "twoFactor")!;
    assert.equal(gap.ok, false);
    assert.match(gap.message!, /doesn't say who has two-factor/);
    assert.ok(!out.evaluation.results.some((r) => r.checkId === "TEI-001"));
    // It has no push mirrors either: that is "none", not a gap.
    assert.equal(out.coverage.find((c) => c.key === "pushMirrors")!.ok, true);
    assert.ok(!failed(out).some((f) => f.startsWith("TER-002")));
  });

  test("a redirect is reported with where it goes, and never followed", async () => {
    const real = globalThis.fetch;
    const asked: string[] = [];
    globalThis.fetch = (async (input: string | URL) => {
      asked.push(String(input));
      return new Response(null, { status: 302, headers: { location: "https://sso.example.net/login?token=abc&next=/" } });
    }) as typeof fetch;
    restore = () => {
      globalThis.fetch = real;
    };
    const e = (await new GiteaClient(`https://git.example.com:${KEY}`).raw("/user").catch((x) => x)) as Error;
    assert.equal(e.message, "The instance redirected to sso.example.net. Enter the address it redirects to.");
    assert.deepEqual(asked, ["https://git.example.com/api/v1/user"]);
  });

  test("an address that isn't a Gitea says so", async () => {
    const real = globalThis.fetch;
    globalThis.fetch = (async () => new Response("<html>Welcome</html>", { status: 200, headers: { "content-type": "text/html" } })) as typeof fetch;
    restore = () => {
      globalThis.fetch = real;
    };
    const info = await gitea.verify(`https://www.example.com:${KEY}`, []);
    assert.equal(info.valid, false);
    assert.match(info.message!, /didn't answer as Gitea's API/);
  });
});

describe("through the app", () => {
  let restoreCloudflare: () => void;
  const realSend = net.send;
  before(() => {
    restoreCloudflare = installMockCloudflare();
  });
  after(() => restoreCloudflare());
  afterEach(() => {
    net.send = realSend;
  });

  test("an organization is added, scanned and listed with its repositories, and the token never comes back", async () => {
    mock();
    const t = makeApp();
    const verified = await t.json("/api/accounts/verify", "POST", { provider: "gitea", token: MOCK_GITEA_TOKEN, accountIds: [MOCK_GITEA_ACCOUNT] });
    assert.equal(verified.token.valid, true);
    assert.deepEqual(verified.accounts, [{ id: MOCK_GITEA_ACCOUNT, name: "Mock Platform", added: false, entityId: null }]);
    const added = await t.json("/api/accounts", "POST", {
      provider: "gitea",
      token: MOCK_GITEA_TOKEN,
      accountIds: [MOCK_GITEA_ACCOUNT],
      entityName: "Mock Group",
    });
    assert.deepEqual(added.added, [MOCK_GITEA_ACCOUNT]);
    await t.scanner.idle();

    const repos = await t.json(`/api/repos?scope=a:${MOCK_GITEA_ACCOUNT}`);
    assert.equal(repos.repos.length, 7);
    assert.deepEqual([repos.repos[0].owner, repos.repos[0].url], ["platform", `${MOCK_GITEA_BASE}/platform/docs`]);
    const findings = await t.json(`/api/findings?scope=a:${MOCK_GITEA_ACCOUNT}`);
    assert.ok(findings.findings.length >= 15);
    assert.ok(findings.findings.every((f: any) => f.provider === "gitea"));
    const everything = JSON.stringify([
      repos,
      findings,
      await t.json("/api/accounts"),
      await t.json("/api/overview?scope=all"),
      await t.json("/api/checks?scope=all"),
    ]);
    for (const secret of [KEY, ...MOCK_GITEA_SECRETS]) assert.ok(!everything.includes(secret), `${secret} is in an API response`);
    t.cleanup();
  });

  test("a self-hosted instance is reached through the network chosen for Gitea, and a network's test asks it", async () => {
    mock();
    const t = makeApp();
    seedGitea(t.repo, t.vault);
    const seen: string[] = [];
    net.send = async (r, input, init) => {
      const url = new URL(String(input));
      seen.push(`${r.name} ${url.host}${url.pathname === "/" ? "/" : ""}`);
      if (url.pathname === "/cdn-cgi/trace") return new Response("ip=203.0.113.9\nwarp=off\n");
      if (url.hostname !== new URL(MOCK_GITEA_BASE).hostname) return new Response("", { status: 401 });
      return fetch(input, init);
    };
    const all = await t.json("/api/networks", "POST", { name: "Office", kind: "proxy", proxy: { protocol: "http", host: "proxy.office.example", port: 3128 } });
    await t.json("/api/network-use", "PUT", { target: "gitea", network: all.networks[0].id });
    await t.scanner.start("manual", [MOCK_GITEA_ACCOUNT]).done;
    const host = new URL(MOCK_GITEA_BASE).host;
    assert.equal(seen[0], `Office ${host}/`, "the instance is asked once before the scan, to know the network works");
    assert.ok(seen.length > 30 && seen.every((s) => s.startsWith(`Office ${host}`)), "every request of the scan goes through it");

    const tested = await t.json("/api/networks/test", "POST", { id: all.networks[0].id });
    assert.deepEqual(
      tested.reached.filter((r: any) => r.provider === "gitea"),
      [{ provider: "gitea", host, ok: true, ms: tested.reached.find((r: any) => r.provider === "gitea").ms, error: null }],
    );
    // With no Gitea connected there is no instance to ask.
    t.repo.accounts.remove(MOCK_GITEA_ACCOUNT);
    assert.ok(!(await t.json("/api/networks/test", "POST", { id: all.networks[0].id })).reached.some((r: any) => r.provider === "gitea"));
    t.cleanup();
  });
});
