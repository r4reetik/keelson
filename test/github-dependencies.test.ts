// GitHub's dependency scan end to end, against the mocked API and the mock Syft,
// Grype and Grant (dev/mock/anchore.ts): Keelson fetches only manifest and lock
// files, never code, with GET; an SBOM is made again only when those files
// change; a monorepo's packages are attributed to its parts; and the findings,
// the Repositories page, the dependency view and the SBOM download agree. The
// pure pieces (manifest parsing, alias merging, version order) are tested too.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { Scanner } from "../src/scanner.ts";
import { installMockGithub, MOCK_GITHUB_ACCOUNT, MOCK_SOURCE_CONTENT, MOCK_SOURCE_FILE } from "../dev/mock/github.ts";
import { seedAccount, seedGithub, testRepo } from "../dev/mock/accounts.ts";
import { installMockCloudflare } from "../dev/mock/cloudflare.ts";
import { makeApp } from "./helpers/app.ts";
import { baseImages, findParts, goRequires, requirementLines, wanted } from "../src/providers/github/sbom/manifests.ts";
import { actionUses, compareVersions, mergeAliases } from "../src/providers/github/sbom/index.ts";
import type { DepVuln } from "../src/providers/github/types.ts";
import type { DependenciesResponse } from "../src/shared/dependencies.ts";
import { evaluateGithub } from "../src/providers/github/engine.ts";
import { dependencies, githubInventory, pkg, repoDeps, vuln } from "./github-cases.ts";

const ALLOWED_POST = /^\/app\/installations\/\d+\/access_tokens$/;

async function scan(o: Parameters<typeof installMockGithub>[0] = {}, existing?: ReturnType<typeof testRepo> & { scanner: Scanner }) {
  const requests: { method: string; path: string }[] = [];
  const syft: string[][] = [];
  const grype: string[][] = [];
  const restore = installMockGithub({
    ...o,
    anchore: { ...o.anchore, onSyft: (f) => syft.push(f), onGrype: (p) => grype.push(p) },
    onRequest: (u, init) => requests.push({ method: init?.method || "GET", path: u.pathname + u.search }),
  });
  try {
    const ctx =
      existing ??
      (() => {
        const t = testRepo();
        seedGithub(t.repo, t.vault, { entity: "Mock Group" });
        return { ...t, scanner: new Scanner(t.repo, t.vault, () => {}) };
      })();
    const [result] = await ctx.scanner.start("test").done;
    const snap = JSON.parse(ctx.repo.scans.latest(MOCK_GITHUB_ACCOUNT)!.snapshot as string);
    const findings = ctx.repo.findings.forScan(result.scanId, ctx.repo.settings.get().slaDays);
    return { ...ctx, result, snap, findings, requests, syft, grype };
  } finally {
    restore();
  }
}

describe("GitHub dependencies (SBOM) against the mocked API and tools", () => {
  test("fetches only manifest and lock files with GET, and stores no file's contents", async () => {
    const { requests, syft, repo, snap } = await scan();
    assert.ok(
      requests.every((r) => r.method === "GET" || ALLOWED_POST.test(r.path)),
      "nothing but GET besides the token request",
    );
    const given = syft.flat();
    assert.ok(given.includes("package-lock.json") && given.includes("go.mod") && given.includes(".github/workflows/ci.yml"));
    assert.ok(!given.includes(MOCK_SOURCE_FILE) && !given.includes("main.go"), "source code is never fetched");
    assert.ok(!given.some((f) => f.includes("node_modules")), "installed packages are skipped");
    const blobs = requests.filter((r) => r.path.includes("/git/blobs/"));
    assert.equal(blobs.length, given.length, "one blob request per file Syft was given");
    // Nothing of a source file reaches storage: not the snapshot, not the cached SBOM or view.
    const stored = [JSON.stringify(snap), ...repo.cache.keys(MOCK_GITHUB_ACCOUNT, "").map((k) => JSON.stringify(repo.cache.get(MOCK_GITHUB_ACCOUNT, k)))].join(
      "\n",
    );
    assert.ok(!stored.includes(MOCK_SOURCE_CONTENT));
    assert.ok(!stored.includes("mock-source-code-SECRET"));
    assert.ok(snap.coverage.filter((c: any) => ["manifests", "syft", "grype", "grant"].includes(c.key)).every((c: any) => c.ok));
  });

  test("finds exploited, vulnerable, malicious and copyleft packages, attributed to each part of a monorepo", async () => {
    const { findings } = await scan();
    const by = (id: string) => findings.filter((f) => f.checkId === id).map((f) => `${f.zone}|${f.resource}|${f.severity}`);
    assert.deepEqual(by("GDP-001"), ["web|mock-xml-parser (npm)|critical"]);
    assert.deepEqual(by("GDP-003"), ["api|mock-colorz (PyPI)|critical"]);
    assert.deepEqual(by("GDP-002").sort(), [
      "api|mock.example/httpkit (Go)|critical",
      "web|mock-actions/deploy (GitHub Actions)|high",
      // Medium in severity, but likely to be exploited soon.
      "web|mock-path-match (npm)|medium",
      "web|mock-router (npm)|high",
      // High, but only a development dependency.
      "web|mock-test-runner (npm)|medium",
    ]);
    assert.deepEqual(by("GDP-004"), ["web|web|low"], "an action used by its tag; actions/checkout and a pinned one aren't counted");
    assert.deepEqual(by("GDP-005").sort(), ["api|api/worker|low", "infra|infra/scripts|low"]);
    assert.deepEqual(by("GLI-001"), ["web|mock-readline (npm)|low"]);
    assert.ok(!findings.some((f) => f.resource.startsWith("mock-celery")), "a medium vulnerability unlikely to be exploited isn't a finding");

    const router = findings.find((f) => f.resource === "mock-router (npm)")!;
    assert.match(router.detail, /used directly by apps\/site and packages\/ui/);
    assert.match(router.detail, /upgrade to 1\.4\.2/);
    const parser = findings.find((f) => f.checkId === "GDP-001")!;
    const d = (parser.evidence as any).dependency;
    assert.equal(d.dependabot, "off", "Dependabot alerts are off in web");
    assert.deepEqual(
      d.versions[0].usedBy.map((u: any) => [u.part, u.direct]),
      [["apps/site", true]],
    );
    assert.equal(d.vulnerabilities[0].kev, true);
    const path = findings.find((f) => f.resource === "mock-path-match (npm)")!;
    assert.match(path.detail, /pulled in by other packages in apps\/site and packages\/ui/);
    const go = findings.find((f) => f.resource === "mock.example/httpkit (Go)")!;
    assert.equal((go.evidence as any).dependency.vulnerabilities.length, 1, "the advisory and its CVE are one vulnerability");
  });

  test("an unchanged repository reuses its SBOM, and Grype still runs on every scan", async () => {
    const first = await scan();
    const second = await scan({}, first);
    assert.equal(second.requests.filter((r) => r.path.includes("/git/blobs/")).length, 0, "no file fetched again");
    assert.equal(second.syft.length, 0, "no SBOM made again");
    assert.equal(second.grype.length, 1, "one Grype run over every repository's unique packages");
    assert.deepEqual(
      second.findings
        .filter((f) => f.checkId.startsWith("GDP"))
        .map((f) => f.fingerprint)
        .sort(),
      first.findings
        .filter((f) => f.checkId.startsWith("GDP"))
        .map((f) => f.fingerprint)
        .sort(),
    );
    const unique = second.grype[0];
    assert.equal(new Set(unique).size, unique.length, "each package is matched once");
  });

  test("an App without the Contents permission is a coverage gap, and no file is listed", async () => {
    const { requests, snap, findings } = await scan({ granted: { metadata: "read", administration: "read", vulnerability_alerts: "read" } });
    assert.ok(!requests.some((r) => r.path.includes("/git/")));
    const gap = snap.coverage.find((c: any) => c.key === "manifests");
    assert.equal(gap.ok, false);
    assert.match(gap.message, /Contents/);
    assert.ok(gap.skippedChecks.includes("GDP-001"));
    assert.ok(!findings.some((f) => f.checkId.startsWith("GDP") || f.checkId.startsWith("GLI")));
  });

  test("without Grype, the SBOM is still made and vulnerability checks are skipped", async () => {
    const { snap, findings } = await scan({ anchore: { missing: ["grype"] } });
    assert.equal(snap.coverage.find((c: any) => c.key === "grype").ok, false);
    assert.ok(!findings.some((f) => ["GDP-001", "GDP-002", "GDP-003"].includes(f.checkId)));
    assert.ok(
      findings.some((f) => f.checkId === "GDP-004"),
      "actions and lock files don't need Grype",
    );
    const web = snap.repos.find((r: any) => r.name === "web").dependencies;
    assert.equal(web.packages, 8);
    assert.equal(web.vulnerable, null);
  });

  test("the Repositories page and the dependency view show each repository's parts and packages, and the SBOM downloads", async () => {
    const t = makeApp();
    const restore = installMockGithub();
    try {
      seedGithub(t.repo, t.vault, { entity: "Mock Group" });
      await t.scanner.start("test").done;
      const repos = await t.json(`/api/repos?scope=a:${MOCK_GITHUB_ACCOUNT}`);
      const web = repos.repos.find((r: any) => r.name === "web").dependencies;
      assert.deepEqual([web.parts, web.packages, web.exploited, web.copyleft], [3, 8, 1, 1]);
      assert.deepEqual(web.ecosystems, ["GitHub Actions", "npm"]);
      assert.equal(web.languages[0].name, "TypeScript");

      const view: DependenciesResponse = await t.json(`/api/dependencies?account=${MOCK_GITHUB_ACCOUNT}&repo=web`);
      assert.deepEqual(
        view.dependencies!.parts.map((p) => p.path),
        ["", "apps/site", "packages/ui", ".github/workflows"],
      );
      assert.deepEqual(view.dependencies!.parts.find((p) => p.path === "apps/site")!.images, ["node:20-alpine", "gcr.io/distroless/nodejs20"]);
      assert.equal(view.dependencies!.parts.find((p) => p.path === "packages/ui")!.lockfile, "package-lock.json", "a workspace shares its root's lock file");
      assert.ok(view.findings.some((f) => f.resource === "mock-xml-parser (npm)"));
      assert.equal(view.url, "https://github.com/mock-org/web");

      const cdx = await t.call(`/api/dependencies/sbom?account=${MOCK_GITHUB_ACCOUNT}&repo=web&format=cyclonedx`);
      assert.equal(cdx.status, 200);
      assert.match(cdx.headers.get("content-disposition") ?? "", /web\.cdx\.json/);
      assert.equal(((await cdx.json()) as { bomFormat: string }).bomFormat, "CycloneDX");
      const raw = await t.json(`/api/dependencies/sbom?account=${MOCK_GITHUB_ACCOUNT}&repo=web&format=syft`);
      assert.ok(raw.artifacts.length >= 8);
      assert.equal((await t.call(`/api/dependencies?account=${MOCK_GITHUB_ACCOUNT}&repo=nope`)).status, 404);
      assert.equal((await t.call(`/api/dependencies/sbom?account=${MOCK_GITHUB_ACCOUNT}&repo=web&format=pdf`)).status, 400);

      // Someone limited to another entity doesn't know the account exists.
      const other = t.repo.entities.create("Other Ltd");
      const as = t.limitedAs("viewer", [other.id]);
      assert.equal((await as.call(`/api/dependencies?account=${MOCK_GITHUB_ACCOUNT}&repo=web`)).status, 404);
      assert.equal((await as.call(`/api/dependencies/sbom?account=${MOCK_GITHUB_ACCOUNT}&repo=web`)).status, 404);
    } finally {
      restore();
      t.cleanup();
    }
  });
});

describe("manifest and lock files", () => {
  test("only dependency files are fetched, outside installed packages and build output", () => {
    for (const p of [
      "package.json",
      "apps/web/pnpm-lock.yaml",
      "go.sum",
      "requirements-dev.txt",
      "requirements/base.txt",
      "api/App.csproj",
      ".github/workflows/ci.yaml",
      "Dockerfile",
      "deploy/api.Dockerfile",
      "infra/.terraform.lock.hcl",
    ])
      assert.ok(wanted(p), p);
    for (const p of [
      "src/index.ts",
      "node_modules/a/package.json",
      "vendor/x/go.mod",
      "dist/package.json",
      "test/fixtures/package-lock.json",
      ".github/dependabot.yml",
      "README.md",
    ])
      assert.ok(!wanted(p), p);
  });

  test("parts: a workspace takes its root's lock file, examples are development only, unpinned requirements are listed", () => {
    const parts = findParts(
      new Map([
        ["package.json", JSON.stringify({ name: "root", workspaces: ["apps/*"] })],
        ["yarn.lock", ""],
        ["apps/a/package.json", JSON.stringify({ name: "@x/a", dependencies: { left: "1" }, devDependencies: { jest: "1" } })],
        ["examples/demo/package.json", JSON.stringify({ name: "demo", dependencies: { left: "1" } })],
        ["svc/requirements.txt", "flask==2.0.0\nrequests>=2\n# comment\n-r base.txt\n"],
        ["svc/Dockerfile", "FROM python:3.12-slim AS base\nFROM base\n"],
        ["tool/go.mod", "module example.com/tool\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v1.0.0 // indirect\n)\n"],
      ]),
    );
    const at = (p: string) => parts.find((x) => x.path === p)!;
    assert.equal(at("apps/a").lockfile, "yarn.lock");
    assert.deepEqual(at("apps/a").direct, { left: { dev: false, ecosystem: "npm" }, jest: { dev: true, ecosystem: "npm" } });
    assert.equal(at("examples/demo").devOnly, true);
    assert.deepEqual(at("svc").unpinned, ["requests"]);
    assert.deepEqual(at("svc").images, ["python:3.12-slim"]);
    assert.deepEqual(at("tool").unpinned, ["github.com/a/b"], "go.mod without go.sum");
    assert.deepEqual(Object.keys(at("tool").direct), ["github.com/a/b"]);
  });

  test("the small parsers", () => {
    assert.deepEqual(requirementLines("a==1\nb===2\nc>=1\nd\ne==1.*\n"), [
      { name: "a", pinned: true },
      { name: "b", pinned: true },
      { name: "c", pinned: false },
      { name: "d", pinned: false },
      { name: "e", pinned: false },
    ]);
    assert.deepEqual(goRequires("require x.io/y v1.0.0\n"), [{ path: "x.io/y", indirect: false }]);
    assert.deepEqual(baseImages("FROM --platform=$B node:20 AS build\nFROM build\nFROM scratch\nFROM $IMG\n"), ["node:20"]);
    assert.deepEqual(
      actionUses(
        new Map([[".github/workflows/a.yml", "steps:\n  - uses: ./local\n  - uses: docker://alpine:3\n  - uses: 'owner/act/sub@v1' # pinned later\n"]]),
      ),
      [{ action: "owner/act/sub", ref: "v1", workflow: ".github/workflows/a.yml" }],
    );
  });

  test("versions order numerically, and an advisory and its CVE are one vulnerability with the smallest fix", () => {
    assert.ok(compareVersions("1.10.0", "1.9.2") > 0);
    assert.ok(compareVersions("v2.0.0", "2.0.1") < 0);
    const v = (o: Partial<DepVuln>): DepVuln => ({
      id: "",
      aliases: [],
      severity: "high",
      cvss: null,
      epss: null,
      percentile: null,
      kev: false,
      ransomware: false,
      fixedIn: null,
      state: "fixed",
      summary: "",
      url: null,
      risk: 0,
      cpeOnly: false,
      ...o,
    });
    const merged = mergeAliases([
      v({ id: "CVE-1", severity: "high", fixedIn: "4.2.24", epss: 0.2 }),
      v({ id: "GHSA-a", aliases: ["CVE-1"], severity: "critical", fixedIn: "3.2.25", kev: true }),
      v({ id: "GHSA-b", severity: "low" }),
    ]);
    assert.equal(merged.length, 2);
    assert.deepEqual([merged[0].id, merged[0].severity, merged[0].fixedIn, merged[0].kev, merged[0].epss], ["GHSA-a", "critical", "3.2.25", true, 0.2]);
    assert.deepEqual(merged[0].aliases, ["CVE-1"]);
  });
});

test("a permission the organization grants later gets a new installation token, not the cached one", async () => {
  const before = await scan({ granted: { metadata: "read", administration: "read" } });
  assert.equal(before.snap.coverage.find((c: any) => c.key === "manifests").ok, false);
  const after = await scan();
  assert.ok(after.snap.coverage.find((c: any) => c.key === "manifests").ok, "the new permission is used at once");
});

test("a tool that prints something other than its report is a coverage gap, not an empty result", async () => {
  const { snap, findings } = await scan({ anchore: { garbled: ["grant", "grype"] } });
  for (const key of ["grant", "grype"]) {
    const c = snap.coverage.find((x: any) => x.key === key);
    assert.equal(c.ok, false, key);
    assert.match(c.message, /wasn't the report/);
  }
  assert.ok(!findings.some((f) => ["GDP-001", "GDP-002", "GLI-001"].includes(f.checkId)));
});

test("a vulnerable package only another package uses, and unlikely to be exploited soon, is one step lower", () => {
  const opts = { orgDomains: [], disabledChecks: new Set<string>(), severityOverrides: {} };
  const sev = (p: ReturnType<typeof pkg>) =>
    evaluateGithub(githubInventory({ dependencies: dependencies([repoDeps({ packages: [p] })]) }), opts).findings.find((f) => f.checkId === "GDP-002")
      ?.severity;
  const through = [{ part: "", direct: false, dev: false }];
  assert.equal(sev(pkg({ vulns: [vuln({ severity: "critical", epss: 0.002 })] })), "critical", "direct");
  assert.equal(sev(pkg({ usedBy: through, vulns: [vuln({ severity: "critical", epss: 0.002 })] })), "high", "transitive, unlikely");
  assert.equal(sev(pkg({ usedBy: through, vulns: [vuln({ severity: "critical", epss: 0.05 })] })), "critical", "transitive, likely");
  assert.equal(sev(pkg({ usedBy: through, devOnly: true, vulns: [vuln({ severity: "high", epss: 0.001 })] })), "low", "transitive and development only");
});

test("Composer libraries and Bun's binary lock file don't count as unlocked projects", () => {
  const parts = findParts(
    new Map([
      ["composer.json", JSON.stringify({ type: "project", require: { "acme/http": "^1" } })],
      ["application/libraries/aws/composer.json", JSON.stringify({ name: "aws/sdk", require: { "guzzle/guzzle": "^7" } })],
      ["web/package.json", JSON.stringify({ dependencies: { react: "^18" } })],
      ["web/bun.lockb", ""],
    ]),
  );
  assert.deepEqual(
    parts.map((p) => [p.path, p.unpinned]),
    [
      ["", ["acme/http"]],
      ["application/libraries/aws", []],
      ["web", []],
    ],
  );
});

test("packages under one npm scope with a strong copyleft license are one finding", () => {
  const opts = { orgDomains: [], disabledChecks: new Set<string>(), severityOverrides: {} };
  const gpl = (name: string) => pkg({ name, licenses: ["GPL-2.0-or-later"], licenseRisk: "strong" });
  const found = evaluateGithub(
    githubInventory({ dependencies: dependencies([repoDeps({ packages: [gpl("@ck/editor"), gpl("@ck/table"), gpl("readline")] })]) }),
    opts,
  ).findings.filter((f) => f.checkId === "GLI-001");
  assert.deepEqual(found.map((f) => f.resource).sort(), ["@ck/* (npm)", "readline (npm)"]);
  const scope = found.find((f) => f.resource === "@ck/* (npm)")!;
  assert.match(scope.detail, /^2 @ck\/\* packages are under GPL-2.0-or-later/);
  assert.deepEqual(
    (scope.evidence as any).license.licenses.map((l: any) => l.name),
    ["@ck/editor", "@ck/table"],
  );
});

test("a license is judged by its own expression with Grant's classes: a choice takes the least restrictive", async () => {
  const { licenseRiskOf } = await import("../src/providers/github/sbom/index.ts");
  const classes = new Map<string, "permissive" | "weak" | "strong" | "other">([
    ["mit", "permissive"],
    ["gpl-3.0-only", "strong"],
    ["lgpl-2.1-only", "weak"],
  ]);
  assert.equal(licenseRiskOf(["MIT"], classes), "permissive");
  assert.equal(licenseRiskOf(["(MIT OR GPL-3.0-only)"], classes), "permissive");
  assert.equal(licenseRiskOf(["MIT AND GPL-3.0-only"], classes), "strong");
  assert.equal(licenseRiskOf(["LGPL-2.1-only", "MIT"], classes), "weak");
  assert.equal(licenseRiskOf(["SEE LICENSE IN LICENSE"], classes), "other");
  assert.equal(licenseRiskOf([], classes), null);
  assert.equal(licenseRiskOf(["MIT"], new Map()), null, "Grant didn't run");
});

test("the Dependencies page's APIs filter packages, vulnerabilities and licenses across repositories, with triage", async () => {
  const t = makeApp();
  const restore = installMockGithub();
  try {
    seedGithub(t.repo, t.vault, { entity: "Mock Group" });
    await t.scanner.start("test").done;
    const S = `scope=a:${MOCK_GITHUB_ACCOUNT}`;
    const sum = (await t.json(`/api/sbom?${S}`)).summary;
    assert.deepEqual([sum.repos, sum.exploited, sum.malicious, sum.copyleft], [4, 1, 1, 1], "handbook has an SBOM with no packages");
    assert.ok(sum.ecosystems.some((e: any) => e.name === "Go"));
    assert.deepEqual(
      sum.repoList.map((r: any) => r.repo),
      ["api", "handbook", "infra", "web"],
    );

    const names = async (q: string) => (await t.json(`/api/sbom/packages?${S}&${q}`)).rows.map((r: any) => r.name);
    assert.deepEqual(await names("status=exploited"), ["mock-xml-parser"]);
    assert.deepEqual(await names("status=malicious"), ["mock-colorz"]);
    assert.deepEqual(await names("ecosystem=Go&status=vulnerable"), ["mock.example/httpkit"]);
    assert.deepEqual(await names(`repo=${MOCK_GITHUB_ACCOUNT}/api&status=nofix`), ["mock-colorz", "mock-celery"]);
    assert.deepEqual(await names("env=dev"), ["mock-test-runner"]);
    assert.deepEqual(await names("risk=strong"), ["mock-readline"]);
    assert.deepEqual(await names("vuln=CVE-2026-90003"), ["mock-router"]);
    assert.ok((await names("usage=transitive")).includes("mock-path-match"));
    const first = (await t.json(`/api/sbom/packages?${S}&limit=1`)).rows[0];
    assert.equal(first.name, "mock-colorz", "malicious first, then exploited, then by severity");
    assert.equal((await t.json(`/api/sbom/packages?${S}&limit=2&offset=2`)).rows.length, 2);

    // A triaged finding shows its status on the package, and the triage filter finds it.
    const router = (await t.json(`/api/sbom/packages?${S}&q=mock-router`)).rows[0];
    assert.equal(router.uses[0].finding.status, "open");
    await t.json(`/api/triage/${router.uses[0].finding.fingerprint}`, "PUT", { status: "accepted", acceptUntil: "2099-01-01", note: "not reachable" });
    assert.deepEqual(await names("triage=accepted"), ["mock-router"]);

    const vulns = await t.json(`/api/sbom/vulnerabilities?${S}&status=exploited`);
    assert.deepEqual(
      vulns.rows.map((v: any) => [v.id, v.packages[0].name, v.repos]),
      [["GHSA-mock-0001-0001", "mock-xml-parser", 1]],
    );
    const licenses = (await t.json(`/api/sbom/licenses?${S}`)).rows;
    assert.equal(licenses[0].license, "GPL-3.0-only");
    assert.equal(licenses[0].risk, "strong");
    assert.ok(
      licenses.some((l: any) => l.license === "" && l.risk === "none"),
      "packages without a stated license are listed",
    );

    const csv = await (await t.call(`/api/sbom/packages.csv?${S}&status=exploited`)).text();
    assert.match(csv, /"package","version","ecosystem"/);
    assert.match(csv, /"mock-xml-parser","0\.9\.1","npm"/);

    // Languages: each ecosystem's packages under the language they're written for, as a filter and in the search.
    assert.ok(sum.languages.some((l: any) => l.name === "JavaScript and TypeScript"));
    assert.ok(sum.languages.some((l: any) => l.name === "Go"));
    assert.deepEqual(await names(`language=Go&status=vulnerable`), await names("ecosystem=Go&status=vulnerable"));
    assert.ok((await names("language=JavaScript and TypeScript")).includes("mock-xml-parser"));
    assert.ok(!(await names("language=JavaScript and TypeScript")).includes("mock.example/httpkit"));
    assert.ok(
      (await names("q=python")).every((n: string) => !n.startsWith("mock.example/")),
      "a search for a language finds its packages",
    );
    assert.ok((await names("q=python")).includes("mock-celery"));
    assert.match(csv, /"language"/);

    // The repositories behind picked rows, or behind every row that matches, across pages.
    const affected = (q: string) => t.json(`/api/sbom/affected?${S}&${q}`);
    const vulnerable = await affected("tab=packages&status=vulnerable");
    assert.ok(vulnerable.repos.length >= 2);
    assert.ok(
      vulnerable.repos.every((r: any) => r.fullName.includes("/") && r.url.startsWith("https://github.com/")),
      "named owner/repo, with a link",
    );
    assert.equal(vulnerable.packages, (await t.json(`/api/sbom/packages?${S}&status=vulnerable`)).total);
    const xml = (await t.json(`/api/sbom/packages?${S}&q=mock-xml-parser`)).rows[0];
    const one = await affected(`tab=packages&key=${encodeURIComponent(`${xml.ecosystem}|${xml.name}|${xml.version}`)}`);
    assert.deepEqual(
      one.repos.map((r: any) => r.repo),
      xml.uses.map((u: any) => u.repo).sort(),
    );
    assert.deepEqual(one.names, [`mock-xml-parser@${xml.version}`]);
    assert.ok(one.repos[0].packages[0].upgrade);
    const byVuln = await affected("tab=vulnerabilities&key=GHSA-mock-0001-0001");
    assert.deepEqual(byVuln.names, ["GHSA-mock-0001-0001"]);
    assert.equal(byVuln.repos.length, 1);
    const byCve = await affected("tab=vulnerabilities&q=CVE-2026-90003");
    assert.ok(byCve.cves.includes("CVE-2026-90003"));
    assert.ok(byCve.repos.some((r: any) => r.packages.some((p: any) => p.name === "mock-router")));
    const gpl = await affected("tab=licenses&key=GPL-3.0-only");
    assert.deepEqual(gpl.names, ["GPL-3.0-only"]);
    assert.ok(gpl.repos.every((r: any) => r.packages.every((p: any) => p.name === "mock-readline")));
    assert.equal((await t.call(`/api/sbom/affected?${S}&tab=findings`)).status, 400);
    const tooMany = Array.from({ length: 201 }, (_, i) => `key=k${i}`).join("&");
    assert.equal((await t.call(`/api/sbom/affected?${S}&tab=packages&${tooMany}`)).status, 400, "a selection that large is sent as every row that matches");

    // Someone limited to another entity sees no dependencies.
    const other = t.repo.entities.create("Other Ltd");
    const as = t.limitedAs("viewer", [other.id]);
    assert.equal((await as.call(`/api/sbom?${S}`)).status, 404);
    assert.equal((await as.call(`/api/sbom/affected?${S}&tab=packages`)).status, 404);
  } finally {
    restore();
    t.cleanup();
  }
});

test("an account without an SBOM in the view doesn't shift other accounts' repositories, and repositories carry their owner", async () => {
  const t = makeApp();
  const restoreCf = installMockCloudflare();
  const restore = installMockGithub();
  try {
    // The Cloudflare account comes first in the view and has no SBOM.
    seedAccount(t.repo, t.vault, { entity: "Mock Group" });
    seedGithub(t.repo, t.vault, { entity: "Mock Group" });
    await t.scanner.start("test").done;
    const entity = t.repo.accounts.get(MOCK_GITHUB_ACCOUNT)!.entityId;
    const sum = (await t.json(`/api/sbom?scope=e:${entity}`)).summary;
    assert.ok(sum.repoList.length > 0);
    assert.ok(
      sum.repoList.every((r: any) => r.accountId === MOCK_GITHUB_ACCOUNT),
      "each repository is under the account that has it",
    );
    const repos = (await t.json(`/api/repos?scope=e:${entity}`)).repos;
    assert.ok(repos.length && repos.every((r: any) => typeof r.owner === "string" && r.owner.length > 0));
  } finally {
    restore();
    restoreCf();
    t.cleanup();
  }
});
