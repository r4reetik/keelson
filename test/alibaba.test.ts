// Alibaba Cloud scans end to end against the mocked APIs (dev/mock/alibaba.ts),
// which sign every request again and refuse a wrong signature: requests are signed
// GETs for read actions Keelson's policy names and nothing else, secrets never
// reach storage, a region that refuses is skipped without failing the rest, an
// address released between scans is caught, and checks that span providers and
// Sonar compare against the entity's other accounts.

import { test, describe, after, before } from "node:test";
import assert from "node:assert/strict";
import { Scanner } from "../src/scanner.ts";
import { installMockVercel } from "../dev/mock/vercel.ts";
import { installMockAws, MOCK_AWS_ACCOUNT } from "../dev/mock/aws.ts";
import { installMockGithub, MOCK_GITHUB_ACCOUNT } from "../dev/mock/github.ts";
import { installMockCloudflare, MOCK_ACCOUNT } from "../dev/mock/cloudflare.ts";
import { installMockInternet } from "../dev/mock/internet.ts";
import {
  installMockAlibaba,
  MOCK_ALIBABA_ACCOUNT,
  MOCK_ALIBABA_ALB,
  MOCK_ALIBABA_DOMAIN,
  MOCK_ALIBABA_FUNCTION_TOKEN,
  MOCK_ALIBABA_KEY_ID,
  MOCK_ALIBABA_RELEASED_IP,
  MOCK_ALIBABA_TEMPLATE_PASSWORD,
  MOCK_ALIBABA_TOKEN,
  MOCK_ALIBABA_USER_DATA_KEY,
  mockAlibaba,
} from "../dev/mock/alibaba.ts";
import { seedAccount, seedAlibaba, seedAws, seedGithub, seedInternet, seedVercel, testRepo } from "../dev/mock/accounts.ts";
import { pacing } from "../src/providers/internet/client.ts";
import { ALIBABA_CHECKS } from "../src/providers/alibaba/catalog.ts";
import { AlibabaError, isReadAction, parseCredentials, productOfHost, PRODUCTS, READ_ACTION, retry } from "../src/providers/alibaba/client.ts";
import { signAcs3, signOss4 } from "../src/providers/alibaba/sign.ts";
import { ALIBABA_ACTIONS, ALIBABA_DATA_ACTIONS, ALIBABA_POLICY_ACTIONS, alibabaPolicy } from "../src/shared/alibaba.ts";
import { PROVIDER } from "../src/providers/index.ts";
import { ACCOUNT_ID_PATTERN, providerForId, providerOfUrl } from "../src/shared/providers.ts";
import type { ScanSnapshot } from "../src/shared/api.ts";

type Repo = ReturnType<typeof testRepo>["repo"];
const snapshotOf = (repo: Repo, id = MOCK_ALIBABA_ACCOUNT) => JSON.parse(repo.scans.latest(id)!.snapshot as string) as ScanSnapshot;
const findingsOf = (repo: Repo, id = MOCK_ALIBABA_ACCOUNT) => repo.findings.forScan(repo.scans.latest(id)!.id, repo.settings.get().slaDays);

test("signatures match Alibaba Cloud's published examples", () => {
  // Signature V3's worked example (a POST with an empty body), from Alibaba Cloud's signature documentation.
  const v3 = signAcs3(
    { accessKeyId: "YourAccessKeyId", accessKeySecret: "YourAccessKeySecret" },
    {
      method: "POST",
      host: "ecs.cn-shanghai.aliyuncs.com",
      path: "/",
      query: { ImageId: "win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd", RegionId: "cn-shanghai" },
      action: "RunInstances",
      version: "2014-05-26",
      now: new Date("2023-10-26T10:22:32Z"),
      nonce: "3156853299f313e23d1673dc12e1703d",
    },
  );
  assert.equal(
    v3.authorization,
    "ACS3-HMAC-SHA256 Credential=YourAccessKeyId,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature=06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0",
  );
  // OSS Signature V4, from the test vectors of Alibaba Cloud's OSS SDK (alibabacloud-oss-go-sdk-v2, signer_test.go).
  const base = {
    method: "PUT",
    bucket: "bucket",
    key: "1234+-/123/1.txt",
    region: "cn-hangzhou",
    query: { param1: "value1", "+param1": "value3", "|param1": "value4", "+param2": "", "|param2": "", param2: "" },
    headers: { "x-oss-head1": "value", abc: "value", ZAbc: "value", XYZ: "value", "content-type": "text/plain" },
  };
  const creds = { accessKeyId: "ak", accessKeySecret: "sk" };
  assert.equal(
    signOss4(creds, { ...base, now: new Date(1702743657000) }).authorization,
    "OSS4-HMAC-SHA256 Credential=ak/20231216/cn-hangzhou/oss/aliyun_v4_request,Signature=e21d18daa82167720f9b1047ae7e7f1ce7cb77a31e8203a7d5f4624fa0284afe",
  );
  assert.equal(
    signOss4(creds, { ...base, additionalHeaders: ["ZAbc", "abc"], now: new Date(1702747512000) }).authorization,
    "OSS4-HMAC-SHA256 Credential=ak/20231216/cn-hangzhou/oss/aliyun_v4_request,AdditionalHeaders=abc;zabc,Signature=4a4183c187c07c8947db7620deb0a6b38d9fbdd34187b6dbaccb316fa251212f",
  );
});

test("the policy Keelson asks for only reads, and the client refuses anything else before sending it", async () => {
  // One action reads data: pulling an image's layers, which Trivy needs to scan it. It is the registry's own permission,
  // never an API call the client sends, and nothing else in the policy may be anything but a read of configuration.
  assert.deepEqual(ALIBABA_DATA_ACTIONS, ["cr:PullRepository"]);
  for (const a of ALIBABA_POLICY_ACTIONS.filter((x) => !ALIBABA_DATA_ACTIONS.includes(x))) assert.match(a.split(":")[1], READ_ACTION, `${a} is a read`);
  assert.ok(!isReadAction("cr", "PullRepository"), "the client never sends it");
  assert.ok(!ALIBABA_POLICY_ACTIONS.some((a) => /GetObject$|GetSecretValue$|Decrypt$|GetFunctionCode$|Kubeconfig/.test(a)), "never data, secrets or code");
  assert.deepEqual(JSON.parse(alibabaPolicy()).Statement[0].Action, ALIBABA_POLICY_ACTIONS);
  assert.ok(Object.values(ALIBABA_ACTIONS).every((list) => list.length > 0));
  assert.ok(isReadAction("cs", "DescribeClustersV1"), "ACK's list is cs:GetClusters in RAM");
  assert.ok(!isReadAction("ecs", "DeleteInstance"));
  assert.ok(!isReadAction("ecs", "DescribeCloudAssistantStatus"), "a read the policy doesn't name is refused too");
  const client = PROVIDER.alibaba;
  assert.ok(client);
  const { AlibabaClient } = await import("../src/providers/alibaba/client.ts");
  const c = new AlibabaClient(parseCredentials(MOCK_ALIBABA_TOKEN)!);
  await assert.rejects(c.rpc("ecs", "cn-hangzhou", "StopInstance"), /isn't a read action/);
  await assert.rejects(c.rpc("kms", "cn-hangzhou", "GetSecretValue"), /isn't a read action/);
  assert.ok(Object.keys(PRODUCTS).length > 10);
});

test("credentials and account IDs", () => {
  assert.ok(parseCredentials(MOCK_ALIBABA_TOKEN));
  assert.equal(parseCredentials("STS.NUgYrLnoC37mZZCNnAbez2EV:secret"), null, "STS tokens expire within hours");
  assert.equal(parseCredentials(MOCK_ALIBABA_KEY_ID), null);
  assert.ok(ACCOUNT_ID_PATTERN.alibaba.test(MOCK_ALIBABA_ACCOUNT));
  assert.equal(providerForId(MOCK_ALIBABA_ACCOUNT), "alibaba");
  assert.equal(providerForId("111122223333"), "aws", "12 digits stay AWS's");
  assert.equal(providerOfUrl("https://ram.console.alibabacloud.com/users"), "alibaba");
});

describe("Alibaba Cloud scan against the mocked API", () => {
  const sent: { url: URL; method: string; action: string | null; auth: string; body: unknown }[] = [];
  let restore: () => void;
  const install = (o: Parameters<typeof installMockAlibaba>[0] = {}) => {
    restore?.();
    const cf = installMockCloudflare();
    const v = installMockVercel();
    const a = installMockAws();
    const g = installMockGithub();
    const net = installMockInternet();
    const ali = installMockAlibaba({
      ...o,
      onRequest: (url, init) => {
        const h = new Headers(init?.headers);
        sent.push({ url, method: init?.method || "GET", action: h.get("x-acs-action"), auth: h.get("authorization") ?? "", body: init?.body });
      },
    });
    restore = () => {
      ali();
      net();
      g();
      a();
      v();
      cf();
    };
  };
  const paced = { ...pacing };
  before(() => {
    for (const k of Object.keys(pacing) as (keyof typeof pacing)[]) pacing[k] = 0;
    install();
  });
  after(() => {
    restore();
    Object.assign(pacing, paced);
    mockAlibaba.released = false;
  });

  const setup = (o: { vercel?: boolean; aws?: boolean; github?: boolean; cloudflare?: boolean } = {}) => {
    const { repo, vault } = testRepo();
    if (o.cloudflare) seedAccount(repo, vault);
    if (o.vercel) seedVercel(repo, vault, { entity: "Mock Group" });
    if (o.aws) seedAws(repo, vault);
    if (o.github) seedGithub(repo, vault);
    seedAlibaba(repo, vault);
    return { repo, vault, scanner: new Scanner(repo, vault, () => {}) };
  };

  test("reads only, with signed GETs, finds what the mock holds, and stores no secret", async () => {
    sent.length = 0;
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    assert.equal(repo.scans.latest(MOCK_ALIBABA_ACCOUNT)!.status, "done");
    assert.deepEqual([...new Set(sent.map((r) => r.method))], ["GET"], "every request is a GET");
    assert.ok(
      sent.every((r) => r.body == null),
      "with no body",
    );
    const oss = sent.filter((r) => /(^|\.)oss-/.test(r.url.hostname));
    assert.ok(oss.length && oss.every((r) => r.auth.startsWith("OSS4-HMAC-SHA256 ")), "OSS requests are V4-signed");
    const apis = sent.filter((r) => !oss.includes(r));
    assert.ok(
      apis.every((r) => r.auth.startsWith("ACS3-HMAC-SHA256 ")),
      "API requests are V3-signed",
    );
    const actions = [...new Set(apis.map((r) => `${productOfHost(r.url.hostname)}:${r.action}`))];
    const refused = actions.filter((a) => {
      const [product, action] = a.split(":");
      return !isReadAction(product, action);
    });
    assert.deepEqual(refused, [], "every action is a read the policy names");
    assert.ok(!oss.some((r) => r.url.pathname !== "/"), "no object in a bucket is ever asked for");

    const coverage = snapshotOf(repo).coverage.filter((c) => !c.ok);
    assert.deepEqual(coverage, [], "the mock answers every source");
    const ids = new Set(findingsOf(repo).map((f) => f.checkId));
    const expected = ALIBABA_CHECKS.filter((c) => !c.spans && c.id !== "LDN-002").map((c) => c.id);
    assert.deepEqual(
      expected.filter((id) => !ids.has(id)),
      [],
      "the mock holds a failing case for each of these",
    );
    assert.ok(!ids.has("LDN-002"), "nothing has left the account on its first scan");
    assert.ok(![...ids].some((id) => id.startsWith("XP-")), "checks that span providers are skipped without the other platform");

    const stored = JSON.stringify({ findings: findingsOf(repo), snap: snapshotOf(repo), scan: repo.scans.latest(MOCK_ALIBABA_ACCOUNT) });
    for (const secret of [
      MOCK_ALIBABA_TOKEN.split(":")[1],
      MOCK_ALIBABA_FUNCTION_TOKEN,
      MOCK_ALIBABA_USER_DATA_KEY,
      MOCK_ALIBABA_TEMPLATE_PASSWORD,
      "LTAIMOCKALEX0000A1B2",
      "mock-secret-header-value",
      "mock-server-key",
    ])
      assert.ok(!stored.includes(secret), `never stored: ${secret.slice(0, 12)}…`);
    assert.ok(!/sts:AssumeRole|"Effect"|log:Get\*|oss:PutObject/.test(stored), "policy documents aren't stored");
    assert.ok(stored.includes("header X-Mock-Verify"), "a header condition keeps the header's name");
    assert.equal(repo.accounts.get(MOCK_ALIBABA_ACCOUNT)!.name, "mock-alibaba", "the account takes its alias as its name");
  });

  test("an EIP released between scans makes the DNS record that still points at it dangling", async () => {
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    mockAlibaba.released = true;
    try {
      await scanner.start("test").done;
    } finally {
      mockAlibaba.released = false;
    }
    const f = findingsOf(repo).find((x) => x.checkId === "LDN-002")!;
    assert.equal(f.resource, `old.${MOCK_ALIBABA_DOMAIN}`);
    assert.match(f.detail, new RegExp(`A ${MOCK_ALIBABA_RELEASED_IP.replace(/\./g, "\\.")}, which left`));
    assert.deepEqual(
      snapshotOf(repo).links!.alibabaReleased!.map((r) => r.ip),
      [MOCK_ALIBABA_RELEASED_IP],
    );
  });

  test("the scan lists every resource with where it is, how the internet reaches it, and its findings", async () => {
    const { repo, scanner } = setup();
    await scanner.start("test").done;
    const view = snapshotOf(repo).resources!;
    const row = (kind: string, id: string) => view.rows.find((r) => r.kind === kind && r.id === id)!;
    const web = row("ECS instance", "i-mockweb0001");
    assert.match(web.exposure ?? "", /^Public address /);
    assert.ok(web.facts.includes("Linux, password") && web.facts.includes("Runs as ops-admin"), web.facts.join(", "));
    assert.ok(web.findings.high + web.findings.critical > 0, "its findings are counted on it");
    assert.match(row("OSS bucket", "mock-uploads").exposure ?? "", /read and write/);
    assert.equal(row("Tair (Redis)", "r-mocksessions").exposure, null, "a VPC-only cache isn't reachable from the internet");
    assert.ok(row("Tair (Redis)", "r-mocksessions").facts.includes("No password in the VPC"));
    assert.ok(!view.rows.some((r) => r.kind === "RAM role" && r.id.startsWith("AliyunServiceRole")), "service-linked roles are Alibaba Cloud's");
    assert.deepEqual(
      view.regions.map((r) => [r.name, r.label]),
      [["cn-hangzhou", "China (Hangzhou)"]],
      "only regions in use, with their names",
    );
    assert.equal(view.emptyRegions, 1);
    // The new reads are on Keelson's policy, so the scan sends them and nothing it reads goes missing.
    const coverage = snapshotOf(repo).coverage;
    for (const key of ["securityPreference", "lbAccess", "redis", "mongodb"]) assert.ok(coverage.find((c) => c.key === key)?.ok, key);
  });

  test("a product's answer that the region isn't valid for it means it isn't offered there, not a gap", () => {
    // Elastic Container Instance in cn-fuzhou, on a real account.
    assert.ok(new AlibabaError(400, "InvalidParameter", "The specified parameter RegionId:cn-fuzhou is not valid").noEndpoint);
    assert.ok(!new AlibabaError(400, "InvalidParameter", "The specified parameter PageSize:500 is not valid").noEndpoint);
  });

  test("a region where Function Compute isn't offered (its endpoint answers 503) is empty, not a gap", async () => {
    const paused = retry.pauseMs;
    retry.pauseMs = 0;
    install({ unavailable: [/^fcv3\.ap-southeast-1\./] });
    try {
      const { repo, scanner } = setup();
      await scanner.start("test").done;
      const fc = snapshotOf(repo).coverage.find((c) => c.key === "functions")!;
      assert.ok(fc.ok, fc.message ?? "functions unreadable");
      assert.ok(
        findingsOf(repo).some((f) => f.checkId === "LCN-002"),
        "functions elsewhere are still judged",
      );
    } finally {
      retry.pauseMs = paused;
      install();
    }
  });

  test("a region that refuses is skipped, and a source that refuses is a gap whose checks are skipped", async () => {
    install({ refuseRegions: ["eu-central-1"], deny: [/\?policy/] });
    try {
      const { repo, scanner } = setup();
      await scanner.start("test").done;
      const snap = snapshotOf(repo);
      assert.deepEqual(snap.resources!.skippedRegions, ["eu-central-1"]);
      assert.equal(snap.regions, undefined, "Alibaba Cloud lists resources, not region rows");
      assert.equal(snap.links!.alibabaAddresses, undefined, "an incomplete address list isn't shared");
      const gap = snap.coverage.find((c) => c.key === "bucketPolicies")!;
      assert.equal(gap.ok, false);
      assert.ok(gap.skippedChecks!.includes("LOS-004"));
      const ids = new Set(findingsOf(repo).map((f) => f.checkId));
      assert.ok(!ids.has("LOS-004") && !ids.has("LOS-002"), "skipped, not passed or failed");
    } finally {
      install();
    }
  });

  test("checks that span providers compare with the entity's Vercel, AWS and GitHub accounts", async () => {
    const { repo, scanner } = setup({ vercel: true, aws: true, github: true });
    await scanner.start("test", [MOCK_AWS_ACCOUNT, MOCK_GITHUB_ACCOUNT]).done;
    await scanner.start("test").done;
    const findings = findingsOf(repo);
    const at = (id: string) => findings.filter((f) => f.checkId === id).map((f) => f.resource);
    assert.deepEqual(at("XP-019"), [`promo.${MOCK_ALIBABA_DOMAIN}`], "a Vercel hostname no project serves");
    assert.deepEqual(at("XP-020"), [`media.${MOCK_ALIBABA_DOMAIN}`], "a CloudFront distribution no AWS account has");
    assert.deepEqual(at("XP-024"), [`docs.${MOCK_ALIBABA_DOMAIN}`], "a Pages site no organization publishes");
    assert.deepEqual(at("XP-023"), ["github-release"], "any branch of the mock organization can assume it");
    assert.deepEqual(findings.find((f) => f.checkId === "XP-019")!.spans, ["vercel"]);
  });

  test("Sonar watches the Alibaba Cloud account's DNS, addresses and load balancers", async () => {
    const { repo, vault, scanner } = setup({ cloudflare: true });
    const ext = seedInternet(repo, vault);
    await scanner.start("test", [MOCK_ACCOUNT, MOCK_ALIBABA_ACCOUNT, ext.id]).done;
    const surface = snapshotOf(repo, ext.id).surface!;
    const api = surface.hosts.find((h) => h.name === `api.${MOCK_ALIBABA_DOMAIN}`)!;
    assert.ok(api, "Alibaba Cloud DNS's hostnames are in the outside view");
    assert.equal(api.route?.loadBalancer, "web-alb", "and followed into the ALB they point at");
    const lb = surface.loadBalancers!.find((b) => b.name === "web-alb")!;
    assert.equal(lb.provider, "alibaba");
    assert.ok(lb.hosts.includes(`api.${MOCK_ALIBABA_DOMAIN}`));
    assert.ok(
      surface.addresses.some((a) => a.ip === "203.0.113.20"),
      "the addresses it holds are asked about",
    );
    // The ALB's backend has its own public address and a group that lets anyone reach 443.
    const direct = findingsOf(repo, ext.id).find((f) => f.checkId === "XP-025");
    assert.equal(direct?.resource, "203.0.113.20");
    assert.ok(MOCK_ALIBABA_ALB.endsWith(".alb.aliyuncs.com"));
  });
});
