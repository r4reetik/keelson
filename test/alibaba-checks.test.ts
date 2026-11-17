// The rules every Alibaba Cloud check follows, as the other providers' checks do:
// each fails on its case, the well-configured fixture passes everything, and an
// unreadable source skips its checks instead of passing them. Then the judgement
// calls that make the findings worth reading, and the policy and rule reductions
// the inventory makes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { evaluateAlibaba } from "../src/providers/alibaba/engine.ts";
import { ALIBABA_CHECKS } from "../src/providers/alibaba/catalog.ts";
import { ALIBABA_MODULES } from "../src/providers/alibaba/checks/index.ts";
import { ALIBABA_SOURCES } from "../src/providers/alibaba/sources.ts";
import { bucketPolicy, escalationPaths, grantsEverything, trustOf } from "../src/providers/alibaba/policy.ts";
import { collectAlibaba, secretInUserData, toSecurityGroup } from "../src/providers/alibaba/inventory.ts";
import { alibabaLinks, ownAddresses, ownEndpoints } from "../src/providers/alibaba/views.ts";
import { accountOf } from "../src/providers/alibaba/checks/define.ts";
import { alibabaEndpointOf } from "../src/core/links.ts";
import { CATEGORIES } from "../src/core/categories.ts";
import { providerOfUrl } from "../src/shared/providers.ts";
import { ALIBABA_CASE_OPTS, ALIBABA_CASES, ACCOUNT, alibabaInventory, region, role } from "./alibaba-cases.ts";
import { AlibabaClient, parseCredentials } from "../src/providers/alibaba/client.ts";
import { installMockAlibaba, MOCK_ALIBABA_TOKEN } from "../dev/mock/alibaba.ts";
import type { AlibabaBucket, AlibabaDatabase, AlibabaLoadBalancer } from "../src/providers/alibaba/types.ts";
import { opts } from "./fixtures/inventory.ts";

const run = (inv = alibabaInventory(), o = {}) => evaluateAlibaba(inv, opts(o));
const withDb = (db: AlibabaDatabase) => alibabaInventory({ regions: [region({ databases: [db] })] });
const by = (r: ReturnType<typeof run>, id: string) => r.results.filter((x) => x.checkId === id);

test("every Alibaba Cloud check fails on its case", () => {
  const missing = ALIBABA_CHECKS.filter((c) => !ALIBABA_CASES[c.id]).map((c) => c.id);
  assert.deepEqual(missing, []);
  const silent = ALIBABA_CHECKS.filter((c) => !run(ALIBABA_CASES[c.id](), ALIBABA_CASE_OPTS[c.id]).findings.some((f) => f.checkId === c.id)).map((c) => c.id);
  assert.deepEqual(silent, [], "these cases don't make their check fail");
});

test("the well-configured Alibaba Cloud account passes every check it evaluates", () => {
  const failing = run(alibabaInventory(), { related: { vercelDomains: [], awsEndpoints: [], githubPages: [] } }).findings.map(
    (f) => `${f.checkId} ${f.resource}`,
  );
  assert.deepEqual(failing, []);
});

test("an Alibaba Cloud check whose source was unreadable reports nothing, even on its failing case", () => {
  const leaked: string[] = [];
  for (const c of ALIBABA_CHECKS)
    for (const source of c.requires ?? []) {
      const inv = { ...ALIBABA_CASES[c.id](), unreadable: [source] };
      if (run(inv, ALIBABA_CASE_OPTS[c.id]).results.some((r) => r.checkId === c.id)) leaked.push(`${c.id} (${source})`);
    }
  assert.deepEqual(leaked, []);
});

test("Alibaba Cloud check metadata: L… IDs, shared categories, Alibaba Cloud's docs, known sources, and every module file registered", () => {
  for (const c of ALIBABA_CHECKS) {
    assert.match(c.id, /^(L[A-Z]{2}|XP)-\d{3}$/, c.id);
    assert.ok((CATEGORIES as readonly string[]).includes(c.category), c.id);
    assert.ok(c.title && c.why && c.fix, c.id);
    if (!c.id.startsWith("XP-")) assert.equal(providerOfUrl(c.docs!), "alibaba", `${c.id} links Alibaba Cloud's docs`);
    else assert.ok(c.spans?.length, `${c.id} names the platform it compares with`);
    for (const s of c.requires ?? []) assert.ok(s in ALIBABA_SOURCES, `${c.id} requires a known source: ${s}`);
  }
  const dir = new URL("../src/providers/alibaba/checks/", import.meta.url);
  const files = readdirSync(dir).filter((f) => /^export default defineChecks\(/m.test(readFileSync(new URL(f, dir), "utf8")));
  assert.equal(files.length, ALIBABA_MODULES.length, `modules on disk: ${files.join(", ")}`);
});

test("a bucket is public only when neither its own nor the account's Block Public Access stops it", () => {
  const open = { name: "b", region: "cn-hangzhou", acl: "public-read-write", blockPublicAccess: false, policy: null };
  const f = run(alibabaInventory({ ossBlock: false, buckets: [open] })).findings.find((x) => x.checkId === "LOS-002")!;
  assert.match(f.detail, /lets anyone read and write/);
  assert.equal(by(run(alibabaInventory({ ossBlock: true, buckets: [open] })), "LOS-002")[0].pass, true, "the account's block stops it");
  assert.equal(
    by(run(alibabaInventory({ ossBlock: false, buckets: [{ ...open, blockPublicAccess: true }] })), "LOS-002")[0].pass,
    true,
    "so does the bucket's",
  );
  // A bucket ActionTrail delivers to says so: it publishes the account's audit log.
  const trail = run(alibabaInventory({ ossBlock: false, buckets: [{ ...open, name: "trail-logs" }] })).findings.find((x) => x.checkId === "LOS-002")!;
  assert.match(trail.detail, /audit log/);
  // A bucket whose settings couldn't be read is left out, not passed.
  assert.equal(by(run(alibabaInventory({ ossBlock: false, buckets: [{ ...open, acl: undefined }] })), "LOS-002").length, 0);
});

test("an open port is judged by what the group is attached to, and a higher-priority drop rule shadows an accept", () => {
  const rule = [{ protocol: "tcp", from: 22, to: 22, cidr: "0.0.0.0/0" }];
  const group = { id: "sg-web", name: "web", vpcId: "vpc-1", open: rule };
  const finding = (id: string) =>
    run(alibabaInventory({ regions: [region({ securityGroups: [{ ...group, id }] })] })).findings.find((f) => f.checkId === "LNW-001")!;
  assert.equal(finding("sg-web").severity, "high");
  assert.equal(finding("sg-db").severity, "medium");
  assert.equal(finding("sg-unused").severity, "low");

  const g = (perms: object[]) => toSecurityGroup({ SecurityGroupId: "sg-1", SecurityGroupName: "web" }, perms);
  const accept = { Direction: "ingress", IpProtocol: "TCP", PortRange: "22/22", SourceCidrIp: "0.0.0.0/0", Policy: "Accept", Priority: "50" };
  assert.equal(g([accept]).open.length, 1);
  assert.equal(g([accept, { ...accept, Policy: "Drop", Priority: "1" }]).open.length, 0, "a drop rule that comes first wins");
  assert.equal(g([accept, { ...accept, Policy: "Drop", Priority: "100" }]).open.length, 1, "one that comes later doesn't");
  assert.equal(g([{ ...accept, SourceCidrIp: "10.0.0.0/8" }]).open.length, 0, "a private range isn't the internet");
  assert.deepEqual(g([{ ...accept, IpProtocol: "ALL", PortRange: "-1/-1" }]).open, [{ protocol: "all", from: null, to: null, cidr: "0.0.0.0/0" }]);
  const web = g([{ ...accept, PortRange: "443/443", SourceCidrIp: "173.245.48.0/20" }]);
  assert.deepEqual(web.webFrom, { cloudflare: true, other: false, prefixLists: [] }, "Cloudflare's ranges on the web ports are recognised by kind");
});

test("a group that only load balancers and Alibaba Cloud's services use isn't judged as a server's, and repeated rules read once", () => {
  const lbGroup = {
    ...region().securityGroups![1],
    id: "sg-alb",
    name: "ALB_SYSTEM_SECURITY_GROUP-alb-1",
    open: [{ protocol: "all", from: null, to: null, cidr: "0.0.0.0/0" }],
  };
  const inv = alibabaInventory({
    regions: [
      region({
        securityGroups: [...region().securityGroups!, lbGroup],
        interfaces: [
          ...region().interfaces!,
          { id: "eni-alb", publicIp: "203.0.113.50", privateIp: "10.0.0.50", securityGroups: ["sg-alb"], kind: "service", owner: null },
        ],
      }),
    ],
  });
  assert.ok(!run(inv).findings.some((f) => f.resource.includes("sg-alb")), "an ALB answers only on its listeners");
  const accept = { Direction: "ingress", Policy: "Accept", Priority: "1", IpProtocol: "ALL", PortRange: "-1/-1", SourceCidrIp: "0.0.0.0/0" };
  const g = toSecurityGroup({ SecurityGroupId: "sg-1" }, [accept, { ...accept, DestCidrIp: "10.0.0.5/32" }, { ...accept, NicType: "internet" }]);
  assert.equal(g.open.length, 1);
});

test("a database's whitelist is judged with its endpoints", () => {
  const db = { ...region().databases![0], openWhitelist: ["0.0.0.0/0"] };
  const pub = run(alibabaInventory({ regions: [region({ databases: [{ ...db, publicEndpoint: true }] })] })).findings.find((f) => f.checkId === "LDB-001")!;
  assert.equal(pub.severity, "critical", "a public endpoint that admits everyone is anyone's to try");
  assert.equal(pub.evidence?.chain?.length, 2);
  const inner = run(alibabaInventory({ regions: [region({ databases: [db] })] })).findings.find((f) => f.checkId === "LDB-001")!;
  assert.equal(inner.severity, "medium", "without a public endpoint, only the network can reach it");
  const plain = run(alibabaInventory({ regions: [region({ databases: [{ ...region().databases![0], ssl: false }] })] })).findings.find(
    (f) => f.checkId === "LDB-002",
  )!;
  assert.equal(plain.severity, "low", "plain text inside the VPC is lower than over the internet");
});

test("password-free access on Tair or MongoDB is critical when the whitelist admits everyone", () => {
  const cache = { ...region().databases![1], passwordFree: true };
  const sev = (db: typeof cache) => run(withDb(db)).findings.find((f) => f.checkId === "LDB-004")!.severity;
  assert.equal(sev(cache), "high");
  assert.equal(sev({ ...cache, openWhitelist: ["0.0.0.0/0"] }), "critical");
  assert.ok(!run(withDb({ ...region().databases![0] })).findings.some((f) => f.checkId === "LDB-004"), "RDS has no password-free access to judge");
});

test("Tair's and MongoDB's VpcAuthMode mean opposite things, and are read that way", async () => {
  const restore = installMockAlibaba();
  try {
    const inv = await collectAlibaba(new AlibabaClient(parseCredentials(MOCK_ALIBABA_TOKEN)!));
    const dbs = inv.regions.flatMap((r) => r.databases ?? []);
    assert.equal(dbs.find((d) => d.service === "redis")?.passwordFree, true, "Tair's Close is password-free");
    assert.equal(dbs.find((d) => d.service === "mongodb")?.passwordFree, false, "MongoDB's Close is passwords required");
  } finally {
    restore();
  }
});

test("a public bucket anyone can write to, or that holds the audit log, is critical; one a CDN serves says so", () => {
  const sev = (b: Partial<AlibabaBucket>) =>
    run(alibabaInventory({ ossBlock: false, buckets: [{ ...alibabaInventory().buckets![0], blockPublicAccess: false, ...b }] })).findings.find(
      (f) => f.checkId === "LOS-002",
    )!;
  assert.equal(sev({ acl: "public-read" }).severity, "high");
  assert.equal(sev({ acl: "public-read-write" }).severity, "critical");
  assert.equal(sev({ acl: "private", policy: { public: true, publicWrite: true, otherAccounts: [] } }).severity, "critical");
  assert.match(sev({ acl: "public-read" }).detail, /CDN domain cdn\.example\.com/);
  assert.equal(bucketPolicy([{ Effect: "Allow", Principal: ["*"], Action: ["oss:Get*", "oss:ListObjects"] }], ACCOUNT).publicWrite, false);
  assert.equal(bucketPolicy([{ Effect: "Allow", Principal: ["*"], Action: ["oss:PutObject"] }], ACCOUNT).publicWrite, true);
  const registry = run(
    alibabaInventory({ ossBlock: false, buckets: [{ ...alibabaInventory().buckets![0], name: "cri-abc123-registry", blockPublicAccess: false }] }),
  );
  assert.ok(!registry.findings.some((f) => f.checkId === "LOS-003"), "Container Registry's own buckets aren't the account's to configure");
});

test("MFA is judged with the account's sign-in setting, and administrators stay critical without it", () => {
  const sev = (pref: "mandatory" | "independent", admin = false) =>
    run(
      alibabaInventory({
        securityPreference: { mfaAtLogin: pref, usersManageKeys: false },
        users: [{ ...alibabaInventory().users![0], mfa: false }],
        admins: admin ? [{ kind: "user", name: "alex", via: "the AdministratorAccess policy" }] : [],
      }),
    ).findings.find((f) => f.checkId === "LID-002")!.severity;
  assert.equal(sev("independent"), "high");
  assert.equal(sev("mandatory"), "medium", "the next sign-in binds a device, whoever makes it");
  assert.equal(sev("independent", true), "critical");
  assert.equal(sev("mandatory", true), "high");
});

test("a CLB listener is judged by its access control, and an NLB by its security groups", () => {
  const clb = (access: "allow" | "deny" | null | undefined, port = 22): AlibabaLoadBalancer => ({
    id: "lb-1",
    name: "legacy",
    type: "clb",
    dnsName: null,
    address: "203.0.113.30",
    internetFacing: true,
    vpcId: "vpc-1",
    securityGroups: [],
    listeners: [{ port, protocol: "TCP", backendPort: port, access, tlsPolicy: null, redirects: false }],
  });
  const find = (lb: AlibabaLoadBalancer, groups = region().securityGroups) =>
    run(alibabaInventory({ regions: [region({ loadBalancers: [lb], securityGroups: groups })] })).findings.find((f) => f.checkId === "LNW-005");
  assert.ok(find(clb(null)), "no access control: anyone");
  assert.ok(find(clb("deny")), "a blacklist still lets everyone else in");
  assert.ok(!find(clb("allow")), "a whitelist decides who connects");
  assert.ok(!find(clb(undefined)), "a listener whose access control couldn't be read isn't judged");
  assert.ok(!find(clb(null, 443)), "a web port is what a load balancer is for");
  const nlb = (sgs: string[]): AlibabaLoadBalancer => ({
    ...clb(null),
    id: "nlb-1",
    type: "nlb",
    address: null,
    dnsName: "nlb-1.example",
    securityGroups: sgs,
  });
  assert.ok(find(nlb([])), "an NLB without security groups lets everyone in");
  assert.ok(!find(nlb(["sg-db"])), "one whose group doesn't open the port doesn't");
});

test("an internet-facing Linux instance without a key pair is judged only when SSH is open to it", () => {
  const groups = (port: number) => [
    { ...region().securityGroups![0], open: [{ protocol: "tcp", from: port, to: port, cidr: "0.0.0.0/0" }] },
    region().securityGroups![1],
  ];
  const find = (keyPair: boolean, port = 22) =>
    run(alibabaInventory({ regions: [region({ instances: [{ ...region().instances![0], keyPair }], securityGroups: groups(port) })] })).findings.find(
      (f) => f.checkId === "LEC-009",
    );
  assert.equal(find(false)?.confidence, "likely");
  assert.ok(!find(true));
  assert.ok(!find(false, 443), "no SSH from the internet, nothing to guess");
});

test("GitHub's immutable subjects (owner@ID/repo@ID) name the same owners as the others", () => {
  const roleWith = (sub: string) =>
    alibabaInventory({
      roles: [
        role({ name: "deploy", trust: [{ principal: `acs:ram::${ACCOUNT}:oidc-provider/github`, kind: "federated", conditional: true, github: [sub] }] }),
      ],
    });
  const related = ALIBABA_CASE_OPTS["XP-022"]!.related;
  const outside = (sub: string) => run(roleWith(sub), { related }).findings.filter((f) => f.checkId === "XP-022");
  assert.deepEqual(outside("repo:example@1001/app@2002:ref:refs/heads/main"), [], "the entity's organization, with IDs");
  assert.equal(outside("repo:other-org@3003/app@4004:ref:refs/heads/main").length, 1);
});

test("the main account: its AccessKeys and MFA from the security practice report, or Keelson's own key", () => {
  assert.equal(by(run(alibabaInventory({ root: null, rootKey: false })), "LID-001").length, 0, "nothing is known without the report");
  const own = run(alibabaInventory({ root: null, rootKey: true })).findings.find((f) => f.checkId === "LID-001")!;
  assert.match(own.detail, /belongs to the main account/);
  assert.equal(by(run(alibabaInventory({ root: null })), "LID-013").length, 0);
});

test("an instance in normal metadata mode is judged by the role it would give away", () => {
  const inst = region().instances![0];
  const sev = (o: object, extra: object = {}) =>
    run(alibabaInventory({ regions: [region({ instances: [{ ...inst, metadataTokens: false, ...o }] })], ...extra })).findings.find(
      (f) => f.checkId === "LEC-001",
    )!.severity;
  assert.equal(sev({ role: null }), "low");
  assert.equal(sev({}), "high", "public, with a role");
  assert.equal(sev({ publicIp: null }), "medium");
  // Public, open, and running as an administrator: critical, since one forged request takes the credentials.
  const admin = run(
    alibabaInventory({ regions: [region({ instances: [{ ...inst, metadataTokens: false }] })], roles: [role({ name: "web", admin: true })] }),
  ).findings;
  assert.equal(admin.find((f) => f.checkId === "LEC-007")!.severity, "critical");
});

test("RAM policies: administrators, escalation paths and trust", () => {
  assert.ok(grantsEverything([{ Effect: "Allow", Action: "*", Resource: "*" }]));
  assert.ok(!grantsEverything([{ Effect: "Allow", Action: "oss:*", Resource: "*" }]));
  assert.ok(!grantsEverything([{ Effect: "Allow", Action: "*", Resource: "*", Condition: { IpAddress: { "acs:SourceIp": "10.0.0.0/8" } } }]));
  assert.deepEqual(escalationPaths([{ Effect: "Allow", Action: "ram:Attach*", Resource: "*" }]), [
    "ram:AttachPolicyToUser",
    "ram:AttachPolicyToGroup",
    "ram:AttachPolicyToRole",
  ]);
  assert.deepEqual(escalationPaths([{ Effect: "Allow", Action: ["ram:PassRole", "ecs:RunInstances"], Resource: "*" }]), [
    "ram:PassRole with ecs:RunInstances (give a role to an ECS instance)",
  ]);
  assert.deepEqual(escalationPaths([{ Effect: "Allow", Action: "*", Resource: "*" }]), [], "an administrator has nothing to escalate to");
  assert.deepEqual(escalationPaths([{ Effect: "Deny", Action: "ram:*", Resource: "*" }]), []);

  const github = new Set([`acs:ram::${ACCOUNT}:oidc-provider/gh`]);
  assert.deepEqual(trustOf([{ Effect: "Allow", Principal: { RAM: "*" } }], github), [{ principal: "*", kind: "anyone", conditional: false }]);
  assert.deepEqual(
    trustOf(
      [
        {
          Effect: "Allow",
          Principal: { Federated: [`acs:ram::${ACCOUNT}:oidc-provider/gh`] },
          Condition: { StringEquals: { "oidc:sub": "repo:Example/App:ref:refs/heads/main" } },
        },
      ],
      github,
    ),
    [{ principal: `acs:ram::${ACCOUNT}:oidc-provider/gh`, kind: "federated", conditional: true, github: ["repo:example/app:ref:refs/heads/main"] }],
  );
  // A provider Keelson couldn't look up still counts as GitHub's when the condition names GitHub's issuer.
  const byIssuer = trustOf(
    [
      {
        Effect: "Allow",
        Principal: { Federated: ["acs:ram::1:oidc-provider/other"] },
        Condition: { StringEquals: { "oidc:iss": "https://token.actions.githubusercontent.com" } },
      },
    ],
    new Set(),
  );
  assert.deepEqual(byIssuer[0].github, []);
  assert.equal(accountOf(`acs:ram::${ACCOUNT}:root`), ACCOUNT);
  assert.equal(accountOf("ecs.aliyuncs.com"), null);
});

test("bucket policies: anyone without a narrowing condition is public, and other accounts are named", () => {
  assert.deepEqual(bucketPolicy([{ Effect: "Allow", Principal: ["*"], Action: ["oss:GetObject"] }], ACCOUNT), {
    public: true,
    publicWrite: false,
    otherAccounts: [],
  });
  assert.deepEqual(
    bucketPolicy([{ Effect: "Allow", Principal: ["*"], Action: ["oss:GetObject"], Condition: { IpAddress: { "acs:SourceIp": ["10.0.0.0/8"] } } }], ACCOUNT)
      .public,
    false,
    "a source IP condition keeps it private",
  );
  assert.deepEqual(bucketPolicy([{ Effect: "Deny", Principal: ["*"], Action: ["oss:*"] }], ACCOUNT), { public: false, publicWrite: false, otherAccounts: [] });
  assert.deepEqual(bucketPolicy([{ Effect: "Allow", Principal: ["5000000000009999", ACCOUNT, "27737962156157"] }], ACCOUNT).otherAccounts, [
    "5000000000009999",
  ]);
});

test("start-up scripts are scanned for credentials, Alibaba Cloud AccessKeys included", () => {
  assert.equal(secretInUserData(Buffer.from("export KEY=LTAI5tMockMockMockMock01\n").toString("base64")), "an Alibaba Cloud AccessKey");
  assert.equal(secretInUserData(Buffer.from("systemctl start app\n").toString("base64")), null);
  assert.equal(secretInUserData(null), null);
});

test("Alibaba Cloud endpoints are recognised by name", () => {
  assert.deepEqual(alibabaEndpointOf("assets.oss-cn-hangzhou.aliyuncs.com"), { kind: "oss", name: "assets" });
  assert.deepEqual(alibabaEndpointOf("assets.oss-accelerate.aliyuncs.com."), { kind: "oss", name: "assets" });
  assert.deepEqual(alibabaEndpointOf("ALB-abc.cn-hangzhou.alb.aliyuncs.com"), { kind: "slb", name: "alb-abc.cn-hangzhou.alb.aliyuncs.com" });
  assert.deepEqual(alibabaEndpointOf("nlb-xyz.ap-southeast-1.nlb.aliyuncsslb.com"), { kind: "slb", name: "nlb-xyz.ap-southeast-1.nlb.aliyuncsslb.com" });
  assert.deepEqual(alibabaEndpointOf("cdn.example.com.w.kunlunsl.com"), { kind: "cdn", name: "cdn.example.com.w.kunlunsl.com" });
  assert.equal(alibabaEndpointOf("ecs.cn-hangzhou.aliyuncs.com"), null);
  assert.equal(alibabaEndpointOf("d1.cloudfront.net"), null);
});

test("what an Alibaba Cloud account shares, and nothing it couldn't read all of", () => {
  const inv = alibabaInventory();
  assert.deepEqual(
    ownEndpoints(inv)!.map((e) => `${e.kind}:${e.name}`),
    ["oss:assets", "slb:alb-abc123.cn-hangzhou.alb.aliyuncs.com", "cdn:cdn.example.com.w.kunlunsl.com"],
  );
  assert.deepEqual(ownAddresses(inv), ["203.0.113.9"]);
  const links = alibabaLinks(inv);
  assert.deepEqual(links.alibabaAccounts, [ACCOUNT]);
  assert.deepEqual(links.alidnsZones, ["example.com"]);
  assert.equal(links.alibabaLoadBalancers![0].provider, "alibaba");
  assert.equal(links.alibabaLoadBalancers![0].type, "application");
  assert.equal(links.alibabaOrigins!.find((o) => o.kind === "elb")!.web, "open");
  // A region that refused the scan leaves the lists out, so a missing endpoint is never taken for a deleted one.
  const partial = alibabaLinks({ ...inv, skippedRegions: ["eu-central-1"] });
  assert.equal(partial.alibabaEndpoints, undefined);
  assert.equal(partial.alibabaAddresses, undefined);
  assert.deepEqual(partial.alibabaAccounts, [ACCOUNT]);
  // A bucket list that couldn't be read does the same.
  assert.equal(alibabaLinks({ ...inv, buckets: null }).alibabaEndpoints, undefined);
});

test("dangling records name what can be claimed: an OSS bucket is medium, a load balancer low", () => {
  const sev = (value: string) =>
    run(alibabaInventory({ domains: [{ name: "example.com", records: [{ name: "x.example.com", type: "CNAME", value }] }] })).findings.find(
      (f) => f.checkId === "LDN-001",
    )?.severity;
  assert.equal(sev("gone.oss-cn-hangzhou.aliyuncs.com"), "medium");
  assert.equal(sev("alb-gone.cn-hangzhou.alb.aliyuncs.com"), "low");
  assert.equal(sev("alb-abc123.cn-hangzhou.alb.aliyuncs.com"), undefined, "the account's own load balancer passes");
  // Another Alibaba Cloud account in the entity that hasn't shared its list could be the owner: nothing is judged.
  const unknown = run(ALIBABA_CASES["LDN-001"](), { related: { unknown: ["alibabaEndpoints"] } });
  assert.equal(by(unknown, "LDN-001").length, 0);
});
