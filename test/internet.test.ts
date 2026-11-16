// Sonar scans end to end against mocked crt.sh, Shodan and public DNS
// (dev/mock/internet.ts), with the entity's Cloudflare and AWS accounts mocked too:
// it only sends GET requests and none to the entity's own hosts; it runs after the
// entity's other accounts; the Shodan key never reaches storage, a response or an
// error; a source it couldn't read skips its checks; and it is added per entity.

import { test, describe, after, before } from "node:test";
import assert from "node:assert/strict";
import { Scanner } from "../src/scanner.ts";
import { installMockCloudflare, MOCK_ACCOUNT } from "../dev/mock/cloudflare.ts";
import { installMockAws, MOCK_AWS_ACCOUNT, MOCK_AWS_IP } from "../dev/mock/aws.ts";
import { installMockInternet, MOCK_LEGACY_DOMAIN, MOCK_SHODAN_KEY } from "../dev/mock/internet.ts";
import { seedAccount, seedAws, seedInternet, seedVercel, testRepo } from "../dev/mock/accounts.ts";
import { installMockVercel, MOCK_VERCEL_TEAM } from "../dev/mock/vercel.ts";
import { pacing } from "../src/providers/internet/client.ts";
import { accountIdForEntity, providerForId } from "../src/shared/providers.ts";
import { makeApp } from "./helpers/app.ts";
import type { ScanSnapshot } from "../src/shared/api.ts";

/** The only hosts a scan here may ask (Sonar's services and the platforms' APIs); anything else would be a request to the entity's own hosts. */
const SERVICES = new Set(["crt.sh", "api.shodan.io", "internetdb.shodan.io", "cloudflare-dns.com", "api.vercel.com"]);

function setup(o: { key?: string; aws?: boolean; vercel?: boolean } = {}) {
  const { repo, vault } = testRepo();
  seedAccount(repo, vault);
  if (o.aws !== false) seedAws(repo, vault);
  if (o.vercel) seedVercel(repo, vault);
  const ext = seedInternet(repo, vault, { key: o.key });
  const log: string[] = [];
  return { repo, vault, ext, log, scanner: new Scanner(repo, vault, (m) => log.push(m)) };
}

const findingsOf = (repo: ReturnType<typeof testRepo>["repo"], accountId: string) => {
  const scan = repo.scans.latest(accountId)!;
  return { scan, snap: JSON.parse(scan.snapshot as string) as ScanSnapshot, findings: repo.findings.forScan(scan.id as number, repo.settings.get().slaDays) };
};

describe("Sonar scan against mocked certificate logs, Shodan and DNS", () => {
  const requests: { url: URL; method: string }[] = [];
  const seeded: { domains: string[] }[] = [];
  let restore: () => void;
  const install = (o: { crtshDown?: boolean; noAmass?: boolean } = {}) => {
    const cf = installMockCloudflare();
    const aws = installMockAws();
    const vercel = installMockVercel();
    const net = installMockInternet({ ...o, onAmass: (input) => seeded.push(input) });
    const all = globalThis.fetch;
    // Outermost, so it sees every request, including the ones the mocks answer.
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
      requests.push({ url, method: init?.method || "GET" });
      return all(input as string, init);
    }) as typeof fetch;
    restore = () => {
      globalThis.fetch = all;
      net();
      vercel();
      aws();
      cf();
    };
  };
  const paced = { ...pacing };
  before(() => {
    // Shodan's rate and crt.sh's retry are real-world waits; the mock answers at once.
    for (const k of Object.keys(pacing) as (keyof typeof pacing)[]) pacing[k] = 0;
    install();
  });
  after(() => {
    restore();
    Object.assign(pacing, paced);
  });

  test("runs after the entity's other accounts, sends only GETs to public services, and finds what the mock holds", async () => {
    const { repo, ext, log, scanner } = setup({ vercel: true });
    requests.length = 0;
    // Queued first, scanned last: it reads the others' latest scans.
    await scanner.start("test", [ext.id, MOCK_ACCOUNT, MOCK_AWS_ACCOUNT, MOCK_VERCEL_TEAM]).done;
    assert.match(log[3], /\(Internet\) finished/);

    const sonar = requests.filter((r) => ["crt.sh", "api.shodan.io", "internetdb.shodan.io"].includes(r.url.hostname));
    assert.ok(sonar.length > 0);
    assert.ok(
      sonar.every((r) => r.method === "GET"),
      "Sonar only reads",
    );
    const hosts = new Set(requests.map((r) => r.url.hostname));
    assert.ok(
      [...hosts].every((h) => SERVICES.has(h) || h.endsWith(".cloudflare.com") || h.endsWith(".amazonaws.com")),
      `nothing goes to the entity's own hosts: ${[...hosts].join(", ")}`,
    );
    const asked = new Set(requests.filter((r) => r.url.hostname === "internetdb.shodan.io").map((r) => decodeURIComponent(r.url.pathname.slice(1))));
    assert.ok(asked.has(MOCK_AWS_IP) && asked.has("203.0.113.90"), "held addresses and addresses the entity's DNS leads to are asked about");
    assert.ok(!asked.has("198.51.100.201"), "an AWS address no account in the entity holds is someone else's");

    const { snap, findings } = findingsOf(repo, ext.id);
    const open = findings.filter((f) => f.status === "open").map((f) => `${f.checkId} ${f.resource}`);
    for (const expected of [
      `NDS-001 ${MOCK_LEGACY_DOMAIN}`,
      "NCT-001 staging.mock.example",
      "NSV-001 203.0.113.90:6379",
      `NSV-001 ${MOCK_AWS_IP}:5432`,
      "NSV-002 203.0.113.40:22",
      "NSV-003 203.0.113.90",
      "XP-012 origin-api.mock.example",
    ])
      assert.ok(open.includes(expected), `${expected} in ${open.join("; ")}`);
    assert.ok(!open.some((f) => f.startsWith("NCT-001 www.")), "Let's Encrypt is allowed by CAA");

    const s = snap.surface!;
    assert.ok(!s.domains.some((d) => d.name === "vercel.app"), "a Vercel deployment's name doesn't make vercel.app the entity's domain");
    assert.ok(!requests.some((r) => r.url.hostname === "crt.sh" && r.url.search.includes("vercel.app")), "nor is it sent to the logs");
    assert.equal(s.domains.find((d) => d.name === MOCK_LEGACY_DOMAIN)?.dns, null);
    assert.equal(s.domains.find((d) => d.name === "mock.example")?.dns, "cloudflare");
    assert.equal(s.hosts.find((h) => h.name === `shop.${MOCK_LEGACY_DOMAIN}`)?.servedBy, "Outside connected accounts");
    assert.deepEqual(s.hosts.find((h) => h.name === "staging.mock.example")?.found, ["Certificate logs"]);
    const origin = s.addresses.find((a) => a.ip === MOCK_AWS_IP)!;
    assert.equal(origin.heldBy, "AWS");
    assert.equal(origin.origin, true);
    const stored = JSON.stringify(snap);
    assert.ok(!stored.includes("other-company.example"), "another company's hostname on a shared address isn't kept");
  });

  test("hostnames are followed into AWS: load balancer, matching rules and targets, and what anyone can reach", async () => {
    const { repo, ext, scanner } = setup();
    await scanner.start("test", [MOCK_ACCOUNT, MOCK_AWS_ACCOUNT, ext.id]).done;
    const { snap, findings } = findingsOf(repo, ext.id);
    const open = findings.filter((f) => f.status === "open");
    const direct = open.find((f) => f.checkId === "XP-013" && f.resource === MOCK_AWS_IP);
    assert.equal(direct?.severity, "critical", "web-1 serves the /admin route that signs visitors in, and anyone can reach it on 443 directly");
    assert.match(direct!.detail, /web-1 .* port 443/);
    assert.ok(
      open.some((f) => f.checkId === "XP-014" && f.resource === "legacy.mock-aws.example"),
      "a public record for an internal load balancer",
    );
    assert.ok(
      open.some((f) => f.checkId === "XP-015" && f.resource === "beta.mock-aws.example"),
      "a rule for a hostname no DNS points at",
    );
    assert.ok(!open.some((f) => f.checkId === "XP-015" && f.resource === "api.mock-aws.example"), "api's DNS points at the load balancer");

    const s = snap.surface!;
    const api = s.hosts.find((h) => h.name === "api.mock-aws.example")!;
    assert.equal(api.servedBy, "AWS load balancer");
    assert.equal(api.route?.loadBalancer, "web-alb");
    const https = api.route!.listeners.find((l) => l.port === 443)!;
    assert.deepEqual(
      https.routes!.map((r) => r.rule),
      ["10", "30", "default"],
      "only the rules a request for this hostname can take, up to the one that catches the rest",
    );
    assert.equal(https.routes![0].action, "Signs visitors in, then forwards to admin");
    assert.ok(https.routes![0].targets!.some((t) => t.direct && t.publicIp === MOCK_AWS_IP));
    assert.ok(api.findings.critical >= 1, "the hostname shows the target it can be bypassed through");
    const vm = s.hosts.find((h) => h.name === "vm.mock-aws.example")!;
    assert.deepEqual(vm.route?.address?.open?.sort(), ["tcp 22", "tcp 443"]);
    const alb = s.loadBalancers!.find((lb) => lb.name === "web-alb")!;
    assert.ok(alb.hosts.includes("api.mock-aws.example"));
    assert.deepEqual(alb.unpointed, ["beta.mock-aws.example"]);
    assert.ok(s.hosts.find((h) => h.name === "beta.mock-aws.example") == null, "beta doesn't resolve, so it is counted, not listed");
    assert.deepEqual(s.addresses.find((a) => a.ip === MOCK_AWS_IP)?.open?.sort(), ["tcp 22", "tcp 443"]);

    // Shodan saw PostgreSQL on web-1's address, but none of its groups lets anyone reach 5432 now: one step lower, and said why.
    const pg = open.find((f) => f.checkId === "NSV-001" && f.resource === `${MOCK_AWS_IP}:5432`)!;
    assert.equal(pg.severity, "medium");
    assert.ok(pg.evidence?.chain?.some((c) => c.label === "AWS security groups" && /No group on instance web-1/.test(c.value)));
  });

  test("Amass starts from the domains of every connected account and adds what nothing else found", async () => {
    seeded.length = 0;
    const { repo, ext, scanner } = setup();
    await scanner.start("test", [MOCK_ACCOUNT, MOCK_AWS_ACCOUNT, ext.id]).done;
    const { snap } = findingsOf(repo, ext.id);
    assert.equal(seeded.length, 1);
    assert.ok(seeded[0].domains.includes("mock.example") && seeded[0].domains.includes("mock-aws.example"), "Cloudflare's and Route 53's zones");
    assert.deepEqual(snap.surface!.hosts.find((h) => h.name === "vpn.mock.example")?.found, ["Amass"]);
    assert.deepEqual(
      snap.surface!.hosts.find((h) => h.name === "staging.mock.example")?.found,
      ["Certificate logs"],
      "a name another source found stays theirs",
    );
    assert.deepEqual([snap.surface!.amass!.names, snap.surface!.amass!.added], [2, 1]);
    assert.equal(snap.coverage.find((c) => c.key === "amass")?.ok, true);
  });

  test("without Amass, only its source is a gap", async () => {
    restore();
    install({ noAmass: true });
    try {
      const { repo, ext, scanner } = setup();
      await scanner.start("test", [MOCK_ACCOUNT, MOCK_AWS_ACCOUNT, ext.id]).done;
      const { snap, findings } = findingsOf(repo, ext.id);
      assert.match(snap.coverage.find((c) => c.key === "amass")?.message ?? "", /isn't installed/);
      assert.equal(snap.coverage.find((c) => c.key === "routing")?.ok, true);
      assert.ok(findings.some((f) => f.checkId === "XP-013"));
      assert.equal(snap.surface!.amass, null);
    } finally {
      restore();
      install();
    }
  });

  test("with a Shodan key: products and subdomains, and the key stays in the vault", async () => {
    const { repo, ext, scanner } = setup({ key: MOCK_SHODAN_KEY });
    requests.length = 0;
    await scanner.start("test", [MOCK_ACCOUNT, MOCK_AWS_ACCOUNT, ext.id]).done;
    assert.ok(requests.some((r) => r.url.hostname === "api.shodan.io" && r.url.pathname.startsWith("/dns/domain/")));
    assert.ok(!requests.some((r) => r.url.hostname === "internetdb.shodan.io"), "the full API replaces InternetDB");

    const { scan, snap, findings } = findingsOf(repo, ext.id);
    assert.equal(snap.coverage.find((c) => c.key === "shodanDns")?.ok, true);
    assert.deepEqual(snap.surface!.addresses.find((a) => a.ip === MOCK_AWS_IP)?.shodan?.products, ["PostgreSQL 14.2"]);
    assert.equal(findings.find((f) => f.checkId === "NSV-003")?.severity, "high", "a CVSS 10 vulnerability");
    assert.ok(
      snap.surface!.hosts.some((h) => h.name === `shop.${MOCK_LEGACY_DOMAIN}` && h.found.includes("Shodan")),
      "Shodan's subdomains join the logs'",
    );
    assert.ok(snap.surface!.unresolved >= 1, "a subdomain that doesn't resolve is counted, not listed");
    const stored = JSON.stringify({ scan, findings });
    assert.ok(!stored.includes(MOCK_SHODAN_KEY), "the key isn't stored with the scan");
    assert.ok(!stored.includes("MOCK-BANNER-CONTENT"), "banners are dropped");
  });

  test("a refused key is a coverage gap whose message doesn't carry the key, and Shodan's checks are skipped", async () => {
    const wrong = "wrongShodanKey000000000000000000";
    const { repo, ext, scanner } = setup({ key: wrong });
    await scanner.start("test", [MOCK_ACCOUNT, MOCK_AWS_ACCOUNT, ext.id]).done;
    const { scan, snap, findings } = findingsOf(repo, ext.id);
    const gap = snap.coverage.find((c) => c.key === "shodan")!;
    assert.equal(gap.ok, false);
    assert.match(gap.message!, /refused the key/);
    assert.ok(gap.skippedChecks?.includes("NSV-001"));
    assert.ok(!findings.some((f) => f.checkId.startsWith("NSV")), "skipped, not passed or failed");
    assert.ok(!JSON.stringify({ scan, findings }).includes(wrong));
    assert.ok(
      findings.some((f) => f.checkId === "NDS-001"),
      "the rest of the view is still judged",
    );
  });

  test("an account in the entity that hasn't published its DNS yet makes the starting point a gap", async () => {
    const { repo, ext, scanner } = setup();
    // Only Sonar: the Cloudflare and AWS accounts have never been scanned.
    await scanner.start("test", [ext.id]).done;
    const { snap, findings } = findingsOf(repo, ext.id);
    const gap = snap.coverage.find((c) => c.key === "related")!;
    assert.equal(gap.ok, false);
    assert.match(gap.message!, /Cloudflare and AWS account in this entity hasn't been scanned/);
    assert.ok(!findings.some((f) => f.checkId === "NDS-001"));
  });

  test("crt.sh failing is a gap for the certificate check only", async () => {
    restore();
    install({ crtshDown: true });
    try {
      const { repo, ext, scanner } = setup();
      await scanner.start("test", [MOCK_ACCOUNT, MOCK_AWS_ACCOUNT, ext.id]).done;
      const { snap, findings } = findingsOf(repo, ext.id);
      assert.equal(snap.coverage.find((c) => c.key === "certificates")?.ok, false);
      assert.ok(!findings.some((f) => f.checkId === "NCT-001"));
      assert.ok(findings.some((f) => f.checkId === "NSV-001"));
      assert.equal(snap.surface!.domains.find((d) => d.name === "mock.example")?.certificates, null);
    } finally {
      restore();
      install();
    }
  });

  test("Sonar is added per entity through the API, with or without a key, and stays in its entity", async () => {
    const { json, call, repo, scanner, cleanup } = makeApp({ configured: true });
    try {
      const entity = repo.entities.list()[0];
      const id = accountIdForEntity(entity.id);
      assert.equal(providerForId(id), "internet");

      const v = await json("/api/accounts/verify", "POST", { provider: "internet", token: "" });
      assert.equal(v.token.valid, true, "the key is optional");
      assert.deepEqual(v.accounts, [{ id, name: entity.name, added: false, entityId: null }], "the entities are what can be watched");

      const bad = await json("/api/accounts/verify", "POST", { provider: "internet", token: "wrongShodanKey000000000000000000" });
      assert.equal(bad.token.valid, false);
      assert.ok(!bad.token.message.includes("wrongShodanKey"));

      const withKey = await json("/api/accounts/verify", "POST", { provider: "internet", token: MOCK_SHODAN_KEY, accountIds: [id] });
      assert.equal(withKey.token.valid, true);
      assert.ok(withKey.probes[id].every((p: { ok: boolean }) => p.ok));

      // A Cloudflare scan from before Sonar shared its DNS: adding Sonar scans it again first.
      const cf = repo.accounts.list().find((a) => a.provider === "cloudflare")!;
      await scanner.start("test", [cf.id]).done;
      const before = repo.scans.latest(cf.id)!;
      const snap = JSON.parse(before.snapshot as string);
      delete snap.links.cloudflareDns;
      repo.store.db.prepare("UPDATE scans SET snapshot = ? WHERE id = ?").run(JSON.stringify(snap), before.id);

      const added = await json("/api/accounts", "POST", { provider: "internet", token: "", accountIds: [id] });
      assert.deepEqual(added.added, [id]);
      assert.equal(added.entityId, entity.id);
      const account = repo.accounts.get(id)!;
      assert.equal(account.provider, "internet");
      assert.equal(account.entityId, entity.id);
      await scanner.start("test", [id]).done;
      assert.ok(repo.scans.latest(cf.id)!.id > before.id, "the stale Cloudflare scan was redone");
      assert.equal(
        JSON.parse(repo.scans.latest(id)!.snapshot as string).coverage.find((c: { key: string }) => c.key === "related").ok,
        true,
        "so Sonar's first scan starts complete",
      );

      const other = repo.entities.create("Elsewhere");
      const move = await call(`/api/accounts/${id}`, { method: "PATCH", body: JSON.stringify({ entityId: other.id }) });
      assert.equal(move.status, 400);
      assert.match(((await move.json()) as { error: string }).error, /stays there/);

      const notAnEntity = await call("/api/accounts", { method: "POST", body: JSON.stringify({ provider: "internet", token: "", accountIds: ["ext_999"] }) });
      assert.equal(notAnEntity.status, 400);

      const surface = await json(`/api/surface?scope=a:${id}`);
      assert.ok(surface.surface.domains.length > 0);
      for (const path of ["/api/accounts", `/api/surface?scope=a:${id}`, `/api/findings?scope=a:${id}`]) {
        const body = await (await call(path)).text();
        assert.ok(!body.includes(MOCK_SHODAN_KEY), path);
      }
    } finally {
      cleanup();
    }
  });
});
