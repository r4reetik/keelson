// A GitLab scan against the mock instance: it only reads, it never follows a
// redirect or keeps a secret, it concludes nothing a plan or a role didn't
// show, and what it shares lets AWS and Cloudflare tell what is the entity's.

import { test, describe, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import { installMockCloudflare } from "../dev/mock/cloudflare.ts";
import {
  installMockGitlab,
  MOCK_GITLAB_ACCOUNT,
  MOCK_GITLAB_BASE,
  MOCK_GITLAB_SECRETS,
  MOCK_GITLAB_SOURCE_CONTENT,
  MOCK_GITLAB_SOURCE_FILE,
  MOCK_GITLAB_TOKEN,
  type MockGitlabOptions,
} from "../dev/mock/gitlab.ts";
import { seedGitlab } from "../dev/mock/accounts.ts";
import { makeApp } from "./helpers/app.ts";
import { net } from "../src/core/net.ts";
import { accountIdOf, GitlabClient, instanceAddress, parseCredential } from "../src/providers/gitlab/client.ts";
import { gitlab } from "../src/providers/gitlab/index.ts";
import { ACCOUNT_ID_PATTERN, PROVIDER_INFO, providerForId, zoneWord } from "../src/shared/providers.ts";
import { registryKind, REGISTRY_PROVIDER } from "../src/shared/images.ts";
import { Store } from "../src/store/db.ts";
import { Repo } from "../src/store/repo.ts";
import type { ScanInput } from "../src/providers/types.ts";

const KEY = MOCK_GITLAB_TOKEN.slice(MOCK_GITLAB_TOKEN.lastIndexOf(":") + 1);

let restore = () => {};
afterEach(() => restore());
const mock = (o: MockGitlabOptions = {}) => {
  restore = installMockGitlab(o);
};

function freshRepo() {
  const repo = new Repo(new Store(":memory:"));
  const entity = repo.entities.create("Mock Group");
  repo.accounts.add({ id: MOCK_GITLAB_ACCOUNT, provider: "gitlab", name: null, entityId: entity.id, tokenId: "t", tokenKind: "user" });
  return repo;
}

/** One scan. Given the repo of an earlier one, it finds what that scan kept (each project's SBOM). */
async function scan(repo = freshRepo()) {
  const account = repo.accounts.get(MOCK_GITLAB_ACCOUNT)!;
  const input: ScanInput = {
    token: MOCK_GITLAB_TOKEN,
    account,
    engine: { orgDomains: [], disabledChecks: new Set(), severityOverrides: {} },
    probeTakeovers: false,
    previous: null,
    cache: repo.cache.for(account.id),
    toolDir: null,
    onProgress: () => {},
  };
  return gitlab.scan(input);
}
const failed = (out: Awaited<ReturnType<typeof scan>>) =>
  out.evaluation.findings
    .filter((f) => !f.pass)
    .map((f) => `${f.checkId} ${f.resource}`)
    .sort();

describe("the credential", () => {
  test("is an instance's address and a token, and a group's ID says which instance it is on", () => {
    assert.deepEqual(parseCredential(MOCK_GITLAB_TOKEN), { base: MOCK_GITLAB_BASE, token: KEY });
    assert.deepEqual(parseCredential(`https://gitlab.com:${KEY}`), { base: "https://gitlab.com", token: KEY });
    assert.equal(instanceAddress("https://GitLab.com/groups/acme/-/settings/access_tokens"), "https://gitlab.com");
    assert.equal(instanceAddress("https://git.example.com/gitlab/api/v4/user"), "https://git.example.com/gitlab");
    for (const bad of [KEY, `gitlab.com:${KEY}`, `https://u:p@gitlab.com:${KEY}`, "https://gitlab.com:short"]) assert.equal(parseCredential(bad), null, bad);
    assert.match(MOCK_GITLAB_ACCOUNT, ACCOUNT_ID_PATTERN.gitlab);
    assert.notEqual(accountIdOf("https://gitlab.com", 42), accountIdOf(MOCK_GITLAB_BASE, 42));
    assert.equal(providerForId(MOCK_GITLAB_ACCOUNT), "gitlab");
    assert.equal(zoneWord(["gitlab"]), "Project");
    assert.ok(PROVIDER_INFO.gitlab.selfHosted && gitlab.instanceOf!(MOCK_GITLAB_TOKEN) === MOCK_GITLAB_BASE);
    // gitlab.com's registry is GitLab's; an instance's own registry is known by its account, not by its name.
    assert.equal(REGISTRY_PROVIDER[registryKind("registry.gitlab.com")], "gitlab");
  });

  test("is verified with its expiry date, lists the groups it reaches, and says what a lower role can't read", async () => {
    mock({ owner: false });
    const info = await gitlab.verify(MOCK_GITLAB_TOKEN, []);
    assert.deepEqual([info.valid, info.expiresOn], [true, "2027-06-30"]);
    assert.deepEqual(await gitlab.listAccounts(MOCK_GITLAB_TOKEN), [{ id: MOCK_GITLAB_ACCOUNT, name: "Mock Labs" }]);
    const probes = await gitlab.probe(MOCK_GITLAB_TOKEN, MOCK_GITLAB_ACCOUNT);
    assert.deepEqual(
      probes.filter((p) => !p.ok).map((p) => [p.source, p.message]),
      [["Group settings", "GitLab shows a group's security settings only to its Owners."]],
    );
    const wrong = await gitlab.verify(`${MOCK_GITLAB_BASE}:${"x".repeat(30)}`, []);
    assert.equal(wrong.valid, false);
    assert.match(wrong.message!, /didn't accept the token/);
    await assert.rejects(() => gitlab.probe(MOCK_GITLAB_TOKEN, accountIdOf(MOCK_GITLAB_BASE, 999)), /can no longer read this group/);
    await assert.rejects(() => gitlab.probe(MOCK_GITLAB_TOKEN, accountIdOf("https://gitlab.com", 42)), /another GitLab instance/);
  });
});

describe("a scan", () => {
  test("only sends GET, to the instance's API, with the token in a header", async () => {
    const seen: { method: string; path: string; token: string | null; redirect: string | undefined }[] = [];
    mock({
      onRequest: (url, init) =>
        seen.push({
          method: init?.method || "GET",
          path: url.pathname + url.search,
          token: new Headers(init?.headers).get("private-token"),
          redirect: init?.redirect,
        }),
    });
    const out = await scan();
    // The group, about eight for each of its four active projects, and each one's file list and dependency files.
    assert.ok(seen.length > 40 && seen.length < 110, `${seen.length} requests`);
    assert.equal(out.calls, seen.length);
    assert.deepEqual([...new Set(seen.map((s) => s.method))], ["GET"]);
    assert.ok(seen.every((s) => s.path.startsWith("/api/v4/") && s.token === KEY && s.redirect === "manual"));
    assert.ok(
      seen.every((s) => !s.path.includes(KEY)),
      "the token is never in an address",
    );
    // CI/CD variables are never asked for: GitLab's API returns their values.
    assert.ok(!seen.some((s) => /\/variables/.test(s.path)));
  });

  test("finds what is wrong with the mock group, and nothing that isn't", async () => {
    mock();
    const out = await scan();
    assert.equal(out.accountName, "Mock Labs");
    assert.deepEqual(
      out.coverage.filter((c) => !c.ok),
      [],
    );
    assert.deepEqual(failed(out), [
      "GLB-001 infra:main",
      "GLB-001 web:main",
      "GLB-002 web:main",
      "GLB-003 backend/api:main",
      "GLB-004 backend/api:main",
      "GLD-001 mock-xml-parser (npm)",
      "GLD-002 mock.example/httpkit (Go)",
      "GLD-004 web",
      "GLD-005 infra",
      "GLG-001 mock-labs",
      "GLG-002 mock-labs",
      "GLG-003 mock-labs",
      "GLH-001 web:http://chat.mock-group.example",
      "GLH-002 backend/api:https://ci.mock-group.example",
      "GLH-003 web:deploy (write)",
      "GLH-004 backend/api:registry-push",
    ]);
    const by = (id: string, resource: string) => out.evaluation.findings.find((f) => f.checkId === id && f.resource === resource)!;
    // A group access token's own user isn't one of the owners.
    assert.match(by("GLG-002", "mock-labs").detail!, /^6 owners/);
    // From another group by a branch, and a component at a moving version; the group's own project, the pinned component, GitLab's template and the local file aren't counted.
    assert.equal(
      by("GLD-004", "web").detail,
      "other-group/ci-templates@main and other-group/scanners/secret-detection@1 are included by a ref that can be moved",
    );
    assert.equal(by("GLD-004", "web").link, `${MOCK_GITLAB_BASE}/mock-labs/web/-/blob/main/.gitlab-ci.yml`);
    assert.equal(by("GLB-004", "backend/api:main").link, `${MOCK_GITLAB_BASE}/mock-labs/backend/api/-/settings/repository`);
    assert.deepEqual(
      out.snapshot.repos!.map((r) => [r.name, r.visibility, r.protection, r.dependencies?.packages ?? null]),
      [
        ["backend/api", "private", "Merge request, 1 approval", 1],
        ["infra", "private", "None", 0],
        ["legacy-billing", "private", null, null],
        ["payments", "private", "Merge request, 2 approvals", 0],
        ["upstream-copy", "private", null, null],
        ["web", "public", "Protected", 1],
      ],
    );
    // What the entity's other accounts compare with: the group, its Pages domains, and which projects take merge requests only.
    const links = out.snapshot.links!;
    assert.deepEqual(links.gitlabGroups, [{ host: "gitlab.mock-group.example", group: "mock-labs" }]);
    assert.deepEqual(links.gitlabPages, [{ host: "handbook.mock-group.example", repo: "mock-labs/web" }]);
    assert.deepEqual(
      links.gitlabProjects!.map((p) => [p.repo, p.reviewed]),
      [
        ["mock-labs/backend/api", true],
        ["mock-labs/infra", false],
        ["mock-labs/legacy-billing", true],
        ["mock-labs/payments", true],
        ["mock-labs/upstream-copy", false],
        ["mock-labs/web", false],
      ],
    );
    // Images are listed with the project that builds them; one in a private project is never pulled.
    const images = [...out.snapshot.images!.images].sort((a, b) => a.repository.localeCompare(b.repository));
    assert.deepEqual(
      images.map((i) => [i.repository, [...i.tags].sort(), i.public, i.linkedRepo]),
      [
        ["mock-labs/backend/api", ["latest"], false, "mock-labs/backend/api"],
        ["mock-labs/web", ["1.4.0", "latest"], true, "mock-labs/web"],
      ],
    );
    assert.match(JSON.stringify(images[0]), /never hands to a scanner/);
  });

  test("dependencies come from manifest, lock and CI files only, and nothing secret is kept", async () => {
    const blobs: string[] = [];
    const given: string[][] = [];
    mock({ onRequest: (url) => /\/repository\/blobs\//.test(url.pathname) && blobs.push(url.pathname), anchore: { onSyft: (files) => given.push(files) } });
    const repo = freshRepo();
    const out = await scan(repo);
    const fetched = given.flat().sort();
    assert.deepEqual(fetched, [".gitlab-ci.yml", "go.mod", "go.sum", "package-lock.json", "package.json", "requirements.txt"]);
    assert.equal(blobs.length, fetched.length);
    assert.ok(!fetched.includes(MOCK_GITLAB_SOURCE_FILE));
    const cache = repo.cache.for(MOCK_GITLAB_ACCOUNT);
    const stored = JSON.stringify([out, cache.keys("").map((k) => cache.get(k))]);
    for (const secret of [KEY, ...MOCK_GITLAB_SECRETS, MOCK_GITLAB_SOURCE_CONTENT]) assert.ok(!stored.includes(secret), `${secret} was stored`);
    // A project in a subgroup keeps its path as its name.
    assert.deepEqual(cache.keys("deps:").sort(), ["deps:backend/api", "deps:infra", "deps:payments", "deps:web"]);

    // Nothing changed: the next scan lists the files again and fetches none of them.
    blobs.length = 0;
    assert.deepEqual(failed(await scan(repo)), failed(out));
    assert.equal(blobs.length, 0);
  });

  test("a long file list comes in pages and is read whole", async () => {
    mock();
    const whole = failed(await scan());
    restore();
    const trees: string[] = [];
    mock({ treePage: 2, onRequest: (url) => /\/repository\/tree/.test(url.pathname) && trees.push(url.search) });
    assert.deepEqual(failed(await scan()), whole);
    assert.ok(
      trees.some((q) => /page=3/.test(q)),
      "web has more than four entries",
    );
  });

  test("what a plan doesn't have isn't a gap, and what a role can't see is skipped, not passed", async () => {
    mock({ premium: false });
    const free = await scan();
    assert.deepEqual(
      free.coverage.filter((c) => !c.ok),
      [],
      "group webhooks and approval rules don't exist on Free",
    );
    assert.ok(!free.evaluation.results.some((r) => r.checkId === "GLB-003"), "no approval rules: nothing to judge");
    assert.deepEqual(free.snapshot.repos!.find((r) => r.name === "payments")!.protection, "Merge request");

    restore();
    mock({ owner: false });
    const limited = await scan();
    assert.deepEqual(
      limited.coverage
        .filter((c) => !c.ok)
        .map((c) => c.key)
        .sort(),
      ["deployKeys", "deployTokens", "group", "groupHooks", "pages", "projectHooks"],
    );
    assert.ok(!limited.evaluation.results.some((r) => /^GLG-00[13]|^GLH-/.test(r.checkId)));
    // Its Pages domains couldn't be read, so no list of them is shared: a DNS record isn't called dangling on half a list.
    assert.equal(limited.snapshot.links!.gitlabPages, undefined);
    assert.ok(failed(limited).includes("GLB-001 web:main"), "what a Developer can read is still judged");
  });

  test("a redirect is reported with where it goes, and never followed", async () => {
    const real = globalThis.fetch;
    const asked: string[] = [];
    globalThis.fetch = (async (input: string | URL) => {
      asked.push(String(input));
      return new Response(null, { status: 302, headers: { location: "https://sso.example.net/users/sign_in?token=abc" } });
    }) as typeof fetch;
    restore = () => {
      globalThis.fetch = real;
    };
    const e = (await new GitlabClient(`https://gitlab.example.com:${KEY}`).raw("/version").catch((x) => x)) as Error;
    assert.equal(e.message, "The instance redirected to sso.example.net. Enter the address it redirects to.");
    assert.deepEqual(asked, ["https://gitlab.example.com/api/v4/version"]);
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

  test("a group is added, scanned and listed with its projects, dependencies and images, and the token never comes back", async () => {
    mock();
    const t = makeApp();
    const verified = await t.json("/api/accounts/verify", "POST", { provider: "gitlab", token: MOCK_GITLAB_TOKEN, accountIds: [MOCK_GITLAB_ACCOUNT] });
    assert.deepEqual([verified.token.valid, verified.token.expiresOn], [true, "2027-06-30"]);
    const added = await t.json("/api/accounts", "POST", {
      provider: "gitlab",
      token: MOCK_GITLAB_TOKEN,
      accountIds: [MOCK_GITLAB_ACCOUNT],
      entityName: "Mock Group",
    });
    assert.deepEqual(added.added, [MOCK_GITLAB_ACCOUNT]);
    await t.scanner.idle();

    const scope = `scope=a:${MOCK_GITLAB_ACCOUNT}`;
    const repos = await t.json(`/api/repos?${scope}`);
    assert.deepEqual([repos.repos.length, repos.repos[0].owner, repos.repos[0].url], [6, "mock-labs", `${MOCK_GITLAB_BASE}/mock-labs/backend/api`]);
    const packages = await t.json(`/api/sbom/packages?${scope}`);
    assert.deepEqual(packages.rows.map((r: any) => r.name).sort(), ["mock-xml-parser", "mock.example/httpkit"]);
    // A project in a subgroup has a page of its own, at its path.
    const one = await t.json(`/api/dependencies?account=${MOCK_GITLAB_ACCOUNT}&repo=${encodeURIComponent("backend/api")}`);
    assert.deepEqual([one.repo, one.url], ["backend/api", `${MOCK_GITLAB_BASE}/mock-labs/backend/api`]);
    const findings = await t.json(`/api/findings?${scope}`);
    assert.ok(findings.findings.length >= 16 && findings.findings.every((f: any) => f.provider === "gitlab"));
    const everything = JSON.stringify([repos, packages, one, findings, await t.json("/api/accounts"), await t.json(`/api/images?${scope}`)]);
    for (const secret of [KEY, ...MOCK_GITLAB_SECRETS, MOCK_GITLAB_SOURCE_CONTENT]) assert.ok(!everything.includes(secret), `${secret} is in an API response`);
    t.cleanup();
  });

  test("an instance is reached through the network chosen for GitLab, and a network's test asks it", async () => {
    mock();
    const t = makeApp();
    seedGitlab(t.repo, t.vault);
    const seen: string[] = [];
    net.send = async (r, input, init) => {
      const url = new URL(String(input));
      seen.push(`${r.name} ${url.host}`);
      if (url.pathname === "/cdn-cgi/trace") return new Response("ip=203.0.113.9\nwarp=off\n");
      if (url.hostname !== new URL(MOCK_GITLAB_BASE).hostname) return new Response("", { status: 401 });
      return fetch(input, init);
    };
    const all = await t.json("/api/networks", "POST", { name: "Office", kind: "proxy", proxy: { protocol: "http", host: "proxy.office.example", port: 3128 } });
    await t.json("/api/network-use", "PUT", { target: "gitlab", network: all.networks[0].id });
    await t.scanner.start("manual", [MOCK_GITLAB_ACCOUNT]).done;
    const host = new URL(MOCK_GITLAB_BASE).host;
    assert.ok(seen.length > 40 && seen.every((s) => s === `Office ${host}`), "every request of the scan goes through it");
    const tested = await t.json("/api/networks/test", "POST", { id: all.networks[0].id });
    assert.deepEqual(
      tested.reached.filter((r: any) => r.provider === "gitlab").map((r: any) => [r.host, r.ok]),
      [[host, true]],
    );
    t.cleanup();
  });
});
