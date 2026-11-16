// AWS scans end to end against the mocked AWS APIs (dev/mock/aws.ts): requests
// are signed GETs, or signed POSTs for read actions named in READ_ACTIONS and
// nothing else, secrets never reach storage, a region that
// refuses is skipped without failing the rest, and checks that span providers
// compare against the entity's Cloudflare and Vercel accounts.

import { test, describe, after, before } from "node:test";
import assert from "node:assert/strict";
import { Scanner } from "../src/scanner.ts";
import { installMockCloudflare, MOCK_ACCOUNT } from "../dev/mock/cloudflare.ts";
import { installMockVercel } from "../dev/mock/vercel.ts";
import {
  installMockAws,
  MOCK_AWS_ACCOUNT,
  MOCK_AWS_BUILD_PASSWORD,
  MOCK_AWS_KEY_ID,
  MOCK_AWS_SECRET_VALUE,
  MOCK_AWS_SNS_SECRET,
  MOCK_AWS_TASK_TOKEN,
  MOCK_AWS_TOKEN,
  MOCK_AWS_USER_DATA_KEY,
  mockAws,
} from "../dev/mock/aws.ts";
import { seedAccount, seedAws, seedVercel, testRepo } from "../dev/mock/accounts.ts";
import { AWS_CHECKS } from "../src/providers/aws/catalog.ts";
import { parseCredentials, READ_ACTION, READ_ACTIONS } from "../src/providers/aws/client.ts";
import { signGet, signPost } from "../src/providers/aws/sigv4.ts";
import { parseXml, items, text, bool, find } from "../src/providers/aws/xml.ts";
import { PROVIDER } from "../src/providers/index.ts";
import { ACCOUNT_ID_PATTERN, PROVIDERS, PROVIDER_INFO, providerForId, providerList, providerOfUrl, zoneWord } from "../src/shared/providers.ts";
import { makeApp } from "./helpers/app.ts";
import { filterFindings } from "../src/shared/filters.ts";
import type { Finding, ScanSnapshot } from "../src/shared/api.ts";
import { CHECKS } from "../src/providers/catalog.ts";

function setup(o: { cloudflare?: boolean; vercel?: boolean } = {}) {
  const { repo, vault } = testRepo();
  if (o.cloudflare) seedAccount(repo, vault);
  if (o.vercel) seedVercel(repo, vault, { entity: "Mock Group" });
  seedAws(repo, vault);
  return { repo, vault, scanner: new Scanner(repo, vault, () => {}) };
}
const snapshotOf = (repo: ReturnType<typeof setup>["repo"], id = MOCK_AWS_ACCOUNT) => JSON.parse(repo.scans.latest(id)!.snapshot as string);
const findingsOf = (repo: ReturnType<typeof setup>["repo"], id = MOCK_AWS_ACCOUNT) =>
  repo.findings.forScan(repo.scans.latest(id)!.id, repo.settings.get().slaDays);

describe("AWS scan against the mocked API", () => {
  const methods = new Set<string>();
  /** POSTs that aren't a read action Keelson names: must stay empty. */
  const writes: string[] = [];
  const unsigned: string[] = [];
  let restore: () => void;
  const install = (o: Parameters<typeof installMockAws>[0] = {}) => {
    const cf = installMockCloudflare();
    const v = installMockVercel();
    const a = installMockAws({
      ...o,
      onRequest: (u, init) => {
        const method = init?.method || "GET";
        methods.add(method);
        const target = new Headers(init?.headers).get("x-amz-target") ?? "";
        if (method === "POST") {
          // A read of a POST-only API: its service's allowlisted read action, named in X-Amz-Target.
          const service = u.hostname.replace(/^api\./, "").split(".")[0];
          const action = target.split(".").pop() ?? "";
          if (!READ_ACTIONS[service]?.includes(action) || !READ_ACTION.test(action)) writes.push(`${service} ${target}`);
        } else if (init?.body != null || method !== "GET") writes.push(`${method} ${u.href}`);
        const auth = new Headers(init?.headers).get("authorization") ?? "";
        // AWS's address ranges are a public file: it must be read without the access key.
        if (u.hostname === "ip-ranges.amazonaws.com") {
          if (auth) unsigned.push(`credential sent to ${u.hostname}`);
          return;
        }
        if (!/^AWS4-HMAC-SHA256 Credential=.+SignedHeaders=[a-z0-9;-]*host;[a-z0-9;-]*x-amz-date[a-z0-9;-]*, Signature=[0-9a-f]{64}$/.test(auth))
          unsigned.push(u.href);
      },
    });
    restore = () => {
      a();
      v();
      cf();
    };
  };
  before(() => install());
  after(() => restore());

  test("reads only, finds what the mock data holds, and stores no secret", async () => {
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    assert.deepEqual(writes, [], "the AWS scanner sends GETs, and POSTs only for the read actions it names");
    assert.deepEqual([...methods].sort(), ["GET", "POST"]);
    assert.deepEqual(unsigned, [], "every API request is signed, and the public address-range file is read without the key");

    const findings = findingsOf(repo);
    const ids = new Set(findings.map((f) => f.checkId));
    // Everything but the checks that need another platform's account in the entity.
    const expected = AWS_CHECKS.filter((c) => !c.spans && c.id !== "ADN-002").map((c) => c.id);
    assert.deepEqual(
      expected.filter((id) => !ids.has(id)),
      [],
      "the mock holds a failing case for each of these",
    );
    assert.ok(!ids.has("XP-005") && !ids.has("XP-006"), "skipped without an account on the other provider");
    assert.ok(!ids.has("ADN-002"), "nothing has left the account on its first scan");

    const stored = JSON.stringify({ findings, snap: snapshotOf(repo), scans: repo.scans.latest(MOCK_AWS_ACCOUNT) });
    assert.ok(!stored.includes(MOCK_AWS_SECRET_VALUE), "a Lambda environment variable's value must never be stored");
    assert.ok(!stored.includes(MOCK_AWS_TOKEN.split(":")[1]), "the secret access key must never be stored");
    assert.ok(!stored.includes("AKIAMOCKALEX00000A1B2"), "only the last characters of an access key ID are kept");
    assert.ok(!stored.includes(MOCK_AWS_USER_DATA_KEY) && !stored.includes("systemctl"), "a start-up script is scanned, never stored");
    assert.ok(!/Statement|sts%3AAssumeRole/.test(stored), "policy documents aren't stored");
    for (const secret of [MOCK_AWS_TASK_TOKEN, MOCK_AWS_BUILD_PASSWORD, MOCK_AWS_SNS_SECRET])
      assert.ok(!stored.includes(secret), `a credential found in configuration is reported by kind, never stored: ${secret}`);
    assert.ok(!stored.includes("mock-secret-value"), "a listener rule's header condition keeps the header's name, never its value");
    assert.equal(repo.accounts.get(MOCK_AWS_ACCOUNT)!.name, "mock-aws", "the account takes its alias as its name");
  });

  test("load balancers are published with their routing down to the targets, and public addresses with what anyone can reach", async () => {
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    const links = (snapshotOf(repo) as ScanSnapshot).links!;
    const alb = links.awsLoadBalancers!.find((lb) => lb.name === "web-alb")!;
    assert.equal(alb.internetFacing, true);
    assert.equal(alb.web, "open");
    const https = alb.listeners.find((l) => l.port === 443)!;
    assert.deepEqual(
      https.routes!.map((r) => [r.rule, r.hosts, r.paths, r.conditions, r.authenticates]),
      [
        ["10", ["api.mock-aws.example"], ["/admin/*"], [], true],
        ["20", ["beta.mock-aws.example"], [], [], false],
        ["30", ["*.mock-aws.example"], [], ["header X-Mock-Verify"], false],
        ["default", [], [], [], false],
      ],
      "rules in the order the load balancer tries them, the default last",
    );
    const web1 = https.routes![0].targets!.find((t) => t.name === "web-1")!;
    assert.deepEqual([web1.kind, web1.group, web1.port, web1.publicIp != null, web1.openOnPort], ["instance", "admin", 443, true, true]);
    const worker = https.routes![3].targets!.find((t) => t.name === "worker-1")!;
    assert.equal(worker.publicIp, null, "a target without a public address can only be reached through the load balancer");
    const legacy = links.awsLoadBalancers!.find((lb) => lb.type === "classic")!;
    assert.equal(legacy.internetFacing, false);
    assert.deepEqual(
      legacy.listeners[0].routes![0].targets!.map((t) => [t.id, t.port]),
      [["i-0worker0000000001", 8443]],
      "a classic load balancer forwards to its instances on the instance port",
    );
    const vm = links.awsExposure!.find((e) => e.resource.includes("web-1"))!;
    assert.deepEqual(
      vm.open!.map((o) => `${o.protocol} ${o.from}`).sort(),
      ["tcp 22", "tcp 443"],
      "the ports anyone can reach on an instance's public address",
    );
  });

  test("findings carry their region, the judgement behind them and a console link", async () => {
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    const findings = findingsOf(repo);
    const one = (id: string, resource?: RegExp) => findings.find((f) => f.checkId === id && (!resource || resource.test(f.resource)))!;

    assert.equal(one("AID-001").zone, "Global");
    assert.deepEqual(one("AID-001").spans, [], "a check on one platform spans nothing");
    assert.equal(one("AS3-002").resource, "mock-public-assets");
    assert.equal(one("AS3-002").zone, "eu-west-1");
    assert.deepEqual(
      findings.filter((f) => f.checkId === "AS3-003").map((f) => f.resource),
      ["mock-logs"],
      "not the public bucket, and not the one with its own block",
    );
    assert.equal(one("ANW-001").severity, "high", "the admin group is on an instance with a public address");
    assert.match(one("ANW-001").link!, /^https:\/\/eu-west-1\.console\.aws\.amazon\.com\/ec2\//);
    assert.match(one("ANW-001").detail, /reachable on 1 public address: web-1/);
    assert.equal(one("ANW-003").severity, "low", "the all-traffic group isn't attached to anything");
    assert.equal(one("ANW-002").severity, "high", "the database group is on the database's public interface");
    assert.equal(one("AEC-007").severity, "critical", "public, running as an administrator, with IMDSv1 allowed");
    assert.equal(one("AEC-007").resource, "web-1 (i-0web00000000000001)");
    assert.match(one("AEC-008").detail, /an AWS access key/);
    assert.equal(one("AEC-006").severity, "high", "the public function's role is an administrator");
    assert.equal(one("AID-011").resource, "vendor-monitoring");
    assert.equal(one("AMO-003").resource, "web-alb");
    assert.deepEqual(
      findings.filter((f) => f.checkId === "ADN-003").map((f) => f.resource),
      ["partner.mock-aws.example"],
      "the address nobody here holds, not the ones the account has",
    );
    assert.equal(one("ADN-001", /^gone-lb/).severity, "low", "a deleted load balancer's name can't be claimed");
    assert.equal(one("ADN-001", /^static/).severity, "high", "a missing bucket's name can");
    assert.match(one("AEC-001").detail, /runs as the role web-admin-role, which has administrator access/);
    assert.equal(one("ADB-001").severity, "critical", "public database behind a group that opens its port");
    assert.equal(one("AEC-001").resource, "web-1 (i-0web00000000000001)");
    assert.equal(one("AEC-006").confidence, "likely");
    assert.match(one("AID-008").detail, /through the group Admins/);
    assert.equal(one("AID-009").resource, "partner-access");
    assert.deepEqual(
      findings
        .filter((f) => f.checkId === "ADN-001")
        .map((f) => f.resource)
        .sort(),
      ["gone-lb.mock-aws.example", "old-shop.mock-aws.example", "static.mock-aws.example"],
    );
    // Per-region checks stay out of the empty region.
    assert.ok(!findings.some((f) => f.zone === "us-east-1" && ["AMO-001", "AEC-002"].includes(f.checkId)));

    const snap = snapshotOf(repo);
    const rows = Object.fromEntries(snap.regions.map((r: { name: string }) => [r.name, r]));
    assert.deepEqual(Object.keys(rows), ["Global", "eu-west-1", "us-east-1"]);
    assert.equal(rows["eu-west-1"].guardDuty, false);
    assert.ok(rows["eu-west-1"].resources.some((x: { label: string; count: number }) => x.label === "Instances" && x.count === 2));
    assert.ok(rows.Global.findings.critical > 0);
    assert.deepEqual(snap.ownedDomains, ["mock-aws.example"]);
    assert.ok(snap.coverage.every((c: { ok: boolean }) => c.ok));
  });

  test("a region that refuses the access key is skipped, and the rest of the account is still checked", async () => {
    restore();
    install({ refuseRegions: ["ap-south-1"] });
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    const snap = snapshotOf(repo);
    const skipped = snap.regions.find((r: { name: string }) => r.name === "ap-south-1");
    assert.equal(skipped.skipped, true);
    assert.ok(
      snap.coverage.every((c: { ok: boolean }) => c.ok),
      "one closed region isn't a coverage gap",
    );
    assert.ok(findingsOf(repo).some((f) => f.checkId === "ANW-001"));
    assert.equal(snap.links.awsEndpoints, undefined, "an incomplete endpoint list isn't shared with other providers");
    assert.equal(snap.links.awsOrigins, undefined, "nor is an incomplete list of origins");
    restore();
    install();
  });

  test("a source the access key can't read is a coverage gap and its checks are skipped, not passed", async () => {
    restore();
    install({ deny: [/Action=DescribeDBInstances/, /Action=GetAccountSummary/] });
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    const snap = snapshotOf(repo);
    const gap = snap.coverage.find((c: { key: string }) => c.key === "databases");
    assert.equal(gap.ok, false);
    assert.equal(gap.permission, "rds:DescribeDBInstances");
    assert.ok(gap.skippedChecks.includes("ADB-001") && gap.skippedChecks.includes("AMO-001"));
    for (const id of ["ADB-001", "ADB-002", "AMO-001", "AID-001", "AID-002"]) assert.equal(snap.checks[id], undefined, `no pass is recorded for ${id}`);
    assert.ok(
      findingsOf(repo).some((f) => f.checkId === "AS3-002"),
      "the other checks still run",
    );
    restore();
    install();
  });

  test("checks that span providers compare AWS with the entity's Cloudflare and Vercel accounts", async () => {
    const { repo, scanner } = setup({ cloudflare: true, vercel: true });
    // The first pass gives each account the others' snapshots; the second uses them.
    await scanner.start("setup").done;
    await scanner.start("manual").done;
    const cf = findingsOf(repo, MOCK_ACCOUNT);
    assert.deepEqual(
      cf.filter((f) => f.checkId === "XP-004").map((f) => f.resource),
      ["downloads.mock.example"],
      "the CloudFront record is served by the AWS account; the bucket isn't there",
    );
    assert.equal(cf.find((f) => f.checkId === "XP-004")!.confidence, "likely");
    // A finding from a check that compares platforms says which, so the UI can mark it.
    assert.deepEqual(cf.find((f) => f.checkId === "XP-004")!.spans, ["aws"]);
    const aws = findingsOf(repo);
    assert.deepEqual(
      aws.filter((f) => f.checkId === "XP-005").map((f) => f.resource),
      ["docs.mock-aws.example"],
    );
    assert.ok(JSON.parse(repo.scans.latest(MOCK_ACCOUNT)!.snapshot as string).checks["XP-004"].evaluated >= 2);
    // Both origins that Cloudflare proxies to let the whole internet reach them.
    assert.deepEqual(
      aws
        .filter((f) => f.checkId === "XP-006")
        .map((f) => f.resource)
        .sort(),
      ["web-1 (i-0web00000000000001)", "web-alb"],
    );
    assert.deepEqual(aws.find((f) => f.checkId === "XP-006")!.spans, ["cloudflare"]);
    // The correlation filter keeps only those, on either side.
    const correlated = filterFindings(aws as unknown as Finding[], { status: "all", spans: "1" });
    assert.ok(correlated.length >= 3 && correlated.every((f) => f.checkId.startsWith("XP-")));
    // An AWS address nobody in the entity holds is noted; nothing has been released yet.
    assert.deepEqual(
      cf.filter((f) => f.checkId === "XP-008").map((f) => f.resource),
      ["vendor.mock.example"],
    );
    assert.equal(cf.filter((f) => f.checkId === "XP-007").length, 0);
  });

  test("Cloudflare rates an exposed origin by what the entity's AWS account says about its security groups", async () => {
    const { repo, scanner } = setup({ cloudflare: true });
    const ats = () =>
      Object.fromEntries(
        findingsOf(repo, MOCK_ACCOUNT)
          .filter((f) => f.checkId === "ATS-001" && ["origin-api.mock.example", "shop.mock.example"].includes(f.resource))
          .map((f) => [f.resource, f]),
      );
    try {
      await scanner.start("setup").done;
      await scanner.start("manual").done;
      // The AWS scan shares who can reach its origins, by kind only: no ranges.
      const origins = snapshotOf(repo).links.awsOrigins;
      assert.deepEqual(
        origins.map((o: { kind: string; web: string; resource: string }) => `${o.kind} ${o.web} ${o.resource}`).sort(),
        [
          "elb open load balancer legacy-elb",
          "elb open load balancer web-alb",
          "ip open instance web-1 (i-0web00000000000001)",
          "ip open load balancer eni-0alb0000000000001",
        ],
        "the database's group admits no web traffic, so it isn't an origin Keelson can judge",
      );
      // Both origins let anyone in: critical, naming the security group and the AWS finding that reports it.
      let found = ats();
      assert.deepEqual(
        Object.values(found).map((f) => f.severity),
        ["critical", "critical"],
      );
      for (const f of Object.values(found)) {
        const chain = f.evidence!.chain!;
        assert.ok(
          chain.some((s) => s.label === "Security group" && /^web \(sg-/.test(s.value)),
          f.resource,
        );
        assert.ok(chain.some((s) => s.label === "Also reported" && s.value.includes("XP-006")));
      }
      assert.ok(
        findingsOf(repo)
          .find((f) => f.checkId === "XP-006")!
          .evidence!.chain!.some((s) => s.label === "Also reported" && s.value.includes("ATS-001")),
      );

      // The web group is narrowed to Cloudflare's ranges: the exposed addresses are only a note, and XP-006 passes.
      mockAws.cloudflareOnly = true;
      await scanner.start("manual").done;
      await scanner.start("manual").done;
      found = ats();
      assert.deepEqual(
        Object.values(found).map((f) => f.severity),
        ["low", "low"],
      );
      assert.match(found["shop.mock.example"].detail, /only Cloudflare's address ranges/);
      assert.equal(findingsOf(repo).filter((f) => f.checkId === "XP-006").length, 0);

      // When the prefix list can't be read, the origin can't be judged: a coverage gap, and ATS-001 rates it as before.
      restore();
      install({ deny: [/Action=GetManagedPrefixListEntries/] });
      await scanner.start("manual").done;
      await scanner.start("manual").done;
      const gap = snapshotOf(repo).coverage.find((c: { key: string }) => c.key === "prefixLists");
      assert.equal(gap.ok, false);
      assert.equal(gap.permission, "ec2:GetManagedPrefixListEntries");
      found = ats();
      assert.deepEqual(
        Object.values(found).map((f) => f.severity),
        ["critical", "critical"],
      );
      assert.ok(Object.values(found).every((f) => !f.evidence!.chain!.some((s) => s.label === "AWS origin")));
    } finally {
      mockAws.cloudflareOnly = false;
      restore();
      install();
    }
  });

  test("an address that leaves the account between scans makes the records that still point at it dangling", async () => {
    const { repo, scanner } = setup({ cloudflare: true });
    try {
      await scanner.start("setup").done;
      await scanner.start("manual").done;
      assert.equal(findingsOf(repo).filter((f) => f.checkId === "ADN-002").length, 0);
      // The account deletes an old server and its Elastic IP.
      mockAws.released = true;
      await scanner.start("manual").done;
      const aws = findingsOf(repo).filter((f) => f.checkId === "ADN-002");
      assert.deepEqual(
        aws.map((f) => f.resource),
        ["old-vm.mock-aws.example"],
      );
      assert.equal(aws[0].severity, "high");
      assert.match(aws[0].detail, /left this entity's AWS accounts on \d{4}-\d{2}-\d{2}/);
      assert.equal(snapshotOf(repo).addressHistory.released.length, 1);
      // Cloudflare was scanned before AWS noticed; its next scan sees it.
      await scanner.start("manual", [MOCK_ACCOUNT]).done;
      const cf = findingsOf(repo, MOCK_ACCOUNT);
      assert.deepEqual(
        cf.filter((f) => f.checkId === "XP-007").map((f) => f.resource),
        ["old-vm.mock.example"],
      );
      assert.ok(!cf.some((f) => f.checkId === "XP-008" && f.resource === "old-vm.mock.example"), "one finding for it, not two");
      // It stays reported on later scans, until the record is removed or the address is held again.
      await scanner.start("manual").done;
      assert.equal(findingsOf(repo).filter((f) => f.checkId === "ADN-002").length, 1);
    } finally {
      mockAws.released = false;
    }
  });

  test("Cloudflare's AWS check is skipped when the entity has no AWS account", async () => {
    const { repo, vault } = testRepo();
    seedAccount(repo, vault);
    await new Scanner(repo, vault, () => {}).start("test").done;
    assert.equal(JSON.parse(repo.scans.latest(MOCK_ACCOUNT)!.snapshot as string).checks["XP-004"], undefined);
  });

  test("an access key is verified, its account listed and probed, and added through the API", async () => {
    const { json, call, repo, scanner, cleanup } = makeApp();
    try {
      const v = await json("/api/accounts/verify", "POST", { provider: "aws", token: MOCK_AWS_TOKEN, accountIds: [MOCK_AWS_ACCOUNT] });
      assert.equal(v.token.valid, true);
      assert.deepEqual(v.accounts, [{ id: MOCK_AWS_ACCOUNT, name: "mock-aws", added: false, entityId: null }]);
      assert.ok(v.probes[MOCK_AWS_ACCOUNT].length > 10 && v.probes[MOCK_AWS_ACCOUNT].every((p: { ok: boolean }) => p.ok));

      for (const bad of ["not-a-key", `${MOCK_AWS_KEY_ID}`, "ASIAMOCKMOCKMOCK0001:mockSecretMockSecretMockSecretMockSecret0"]) {
        const r = await json("/api/accounts/verify", "POST", { provider: "aws", token: bad });
        assert.equal(r.token.valid, false, bad);
        assert.match(r.token.message, /access key ID/);
      }
      const unknown = await json("/api/accounts/verify", "POST", { provider: "aws", token: "AKIAOTHEROTHEROTHER1:mockSecretMockSecretMockSecretMockSecret0" });
      assert.equal(unknown.token.valid, false);
      assert.match(unknown.token.message, /didn't accept this access key/);

      const wrongId = await call("/api/accounts", { method: "POST", body: JSON.stringify({ provider: "aws", token: MOCK_AWS_TOKEN, accountIds: ["12345"] }) });
      assert.equal(wrongId.status, 400);
      assert.match(((await wrongId.json()) as { error: string }).error, /12 digits/);

      const added = await json("/api/accounts", "POST", { provider: "aws", token: MOCK_AWS_TOKEN, accountIds: [MOCK_AWS_ACCOUNT], entityName: "Mock Group" });
      assert.deepEqual(added.added, [MOCK_AWS_ACCOUNT]);
      await scanner.start("test").done;
      assert.equal(repo.accounts.get(MOCK_AWS_ACCOUNT)!.provider, "aws");

      const regions = await json(`/api/regions?scope=a:${MOCK_AWS_ACCOUNT}`);
      assert.ok(regions.regions.some((r: { name: string }) => r.name === "eu-west-1"));
      const list = await json(`/api/findings?scope=a:${MOCK_AWS_ACCOUNT}`);
      assert.ok(list.findings.length > 20 && list.findings.every((f: { provider: string }) => f.provider === "aws"));
      // No response carries the key.
      for (const path of ["/api/accounts", "/api/session", `/api/findings?scope=a:${MOCK_AWS_ACCOUNT}`, `/api/regions?scope=a:${MOCK_AWS_ACCOUNT}`]) {
        const body = await (await call(path)).text();
        assert.ok(!body.includes(MOCK_AWS_TOKEN.split(":")[1]) && !body.includes(MOCK_AWS_KEY_ID), path);
      }
    } finally {
      cleanup();
    }
  });
});

test("requests are signed as AWS's published example is", () => {
  // The "get-vanilla" case of AWS's Signature Version 4 test suite.
  const headers = signGet(
    { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" },
    { host: "example.amazonaws.com", path: "/", query: {}, region: "us-east-1", service: "service", now: new Date("2015-08-30T12:36:00Z") },
  );
  assert.equal(headers["x-amz-date"], "20150830T123600Z");
  assert.equal(
    headers.Authorization,
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
  );
  // Query parameters are sorted and strictly encoded; extra headers are signed.
  const q = signGet(
    { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" },
    {
      host: "example.amazonaws.com",
      path: "/",
      query: { Param2: "value2", Param1: "value1" },
      region: "us-east-1",
      service: "service",
      now: new Date("2015-08-30T12:36:00Z"),
    },
  );
  assert.match(q.Authorization, /Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500$/);
  // The "post-vanilla" and "post-x-www-form-urlencoded" cases: the body's hash is signed.
  const creds = { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" };
  const base = { host: "example.amazonaws.com", path: "/", query: {}, region: "us-east-1", service: "service", now: new Date("2015-08-30T12:36:00Z") };
  assert.match(
    signPost(creds, base, "").Authorization,
    /SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b$/,
  );
  assert.match(
    signPost(creds, { ...base, headers: { "content-type": "application/x-www-form-urlencoded" } }, "Param1=value1").Authorization,
    /SignedHeaders=content-type;host;x-amz-date, Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a$/,
  );
});

test("the AWS client sends a POST only for a read action it names", async () => {
  for (const [service, actions] of Object.entries(READ_ACTIONS)) for (const a of actions) assert.match(a, READ_ACTION, `${service}:${a} reads`);
  const { AwsClient } = await import("../src/providers/aws/client.ts");
  const client = new AwsClient(parseCredentials(MOCK_AWS_TOKEN)!);
  for (const [service, action] of [
    ["kms", "ScheduleKeyDeletion"],
    ["ecs", "RunTask"],
    ["cloudtrail", "StopLogging"],
    ["unknown", "ListThings"],
  ])
    await assert.rejects(client.rpc(service, "us-east-1", action), /isn't a read action/, `${service}:${action} is refused before anything is sent`);
});

test("credentials: a long-lived key pair, and nothing else", () => {
  assert.deepEqual(parseCredentials(MOCK_AWS_TOKEN), { accessKeyId: MOCK_AWS_KEY_ID, secretAccessKey: MOCK_AWS_TOKEN.split(":")[1] });
  for (const bad of ["", "AKIAMOCKMOCKMOCK0001", "ASIAMOCKMOCKMOCK0001:mockSecretMockSecretMockSecretMockSecret0", "AKIAMOCKMOCKMOCK0001:short"])
    assert.equal(parseCredentials(bad), null, bad);
});

test("the XML reader handles what AWS sends", () => {
  const doc = parseXml(
    `<?xml version="1.0" encoding="UTF-8"?>\n<R xmlns="http://x/"><List><member><Name>a &amp; b</Name><On>TRUE</On></member><member><Name>c</Name><Empty/></member></List><Grant><Grantee xmlns:xsi="x" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee></Grant></R>`,
  );
  assert.equal(doc.name, "R");
  assert.deepEqual(
    items(doc, "List").map((m) => text(m, "Name")),
    ["a & b", "c"],
  );
  assert.equal(bool(items(doc, "List")[0], "On"), true);
  assert.equal(text(items(doc, "List")[1], "Empty"), null);
  assert.equal(text(find(doc, "URI")), "http://acs.amazonaws.com/groups/global/AllUsers");
  assert.throws(() => parseXml("not xml"));
});

test("every provider says what the app needs to know about it", () => {
  for (const p of PROVIDERS) {
    const info = PROVIDER_INFO[p];
    assert.equal(PROVIDER[p].info, info);
    assert.ok(info.label && info.account && info.accounts && info.resource && info.blurb && info.covers && info.credential && info.apiHost, p);
    assert.ok(info.fields.length >= 1 && info.fields.some((f) => f.secret), `${p} has a secret field`);
    assert.ok(info.sites.length && info.noAccounts && info.needsToRead && info.idHint, p);
    assert.ok(PROVIDER[p].checks.length > 0 && PROVIDER[p].checks.every((c) => c.provider === p), p);
    assert.ok(ACCOUNT_ID_PATTERN[p] instanceof RegExp);
  }
  assert.equal(providerForId(MOCK_AWS_ACCOUNT), "aws");
  assert.equal(providerForId(MOCK_ACCOUNT), "cloudflare");
  assert.equal(providerForId("team_MockWeb0000000000000001"), "vercel");
  assert.equal(providerForId("gh_1000001"), "github", "a GitHub ID isn't mistaken for an AWS or Vercel one");
  assert.equal(providerForId("ext_3"), "internet", "Sonar's account is named after its entity");
  assert.equal(providerList(), "Cloudflare, Vercel, AWS and GitHub");
  assert.equal(providerList(["cloudflare", "vercel"], "or"), "Cloudflare or Vercel");
  assert.equal(providerList(["aws"]), "AWS");
  assert.equal(zoneWord(["cloudflare"]), "Zone");
  assert.equal(zoneWord([]), "Zone");
  assert.equal(zoneWord(["aws"]), "Region");
  assert.equal(zoneWord(["github"]), "Repository");
  assert.equal(zoneWord(["cloudflare", "vercel", "aws"]), "Location", "one word when platforms mix");
  assert.equal(zoneWord(["aws", "aws"]), "Region");
  assert.equal(providerOfUrl("https://docs.aws.amazon.com/IAM/latest/UserGuide/x.html"), "aws");
  assert.equal(providerOfUrl("https://eu-west-1.console.aws.amazon.com/ec2/home"), "aws");
  assert.equal(providerOfUrl("https://vercel.com/docs"), "vercel");
  assert.equal(providerOfUrl("https://docs.github.com/en/pages"), "github");
  assert.equal(providerOfUrl("https://developers.cloudflare.com/x"), "cloudflare");
  assert.equal(providerOfUrl("https://example.com"), null);
});

test("a check that compares platforms names the other platform, and no other check does", () => {
  for (const c of CHECKS) {
    if (c.id.startsWith("XP-")) {
      assert.ok(c.spans?.length, `${c.id} says which platforms it compares with`);
      assert.ok(!c.spans.includes(c.provider), `${c.id} spans other platforms, not its own`);
    } else assert.equal(c.spans, undefined, c.id);
  }
});
