// A well-configured Alibaba Cloud account, and one failing case per Alibaba Cloud
// check. The type is Record<AlibabaCheckId, …>, so a new check without a case
// doesn't compile, and test/alibaba-checks.test.ts asserts each case really makes
// its check fail.

import { imageCase } from "./helpers/images.ts";
import type { AlibabaCheckId } from "../src/providers/alibaba/checks/index.ts";
import type { EngineOptions } from "../src/core/types.ts";
import type {
  AlibabaBucket,
  AlibabaInventory,
  AlibabaLoadBalancer,
  AlibabaRegion,
  AlibabaRole,
  AlibabaSecurityGroup,
  AlibabaUser,
} from "../src/providers/alibaba/types.ts";

export const NOW = Date.parse("2026-06-01T00:00:00Z");
const days = (n: number) => NOW + n * 86_400_000;
const R = "cn-hangzhou";
const VPC = "vpc-1";
export const ACCOUNT = "5000000000000001";
const OUTSIDER = "5000000000009999";
const IP = "203.0.113.9";
const ALB = "alb-abc123.cn-hangzhou.alb.aliyuncs.com";

const openTo = (protocol: string, port: number | null): AlibabaSecurityGroup["open"] => [{ protocol, from: port, to: port, cidr: "0.0.0.0/0" }];
const sg = (id: string, open: AlibabaSecurityGroup["open"] = []): AlibabaSecurityGroup => ({
  id,
  name: id,
  vpcId: VPC,
  open,
  webFrom: { cloudflare: false, other: false, prefixLists: [] },
});
const bucket = (extra: Partial<AlibabaBucket> = {}): AlibabaBucket => ({
  name: "assets",
  region: R,
  acl: "private",
  blockPublicAccess: true,
  policy: null,
  ...extra,
});

const alb = (extra: Partial<AlibabaLoadBalancer> = {}): AlibabaLoadBalancer => ({
  id: "alb-abc123",
  name: "web",
  type: "alb",
  dnsName: ALB,
  address: null,
  internetFacing: true,
  vpcId: VPC,
  securityGroups: ["sg-web"],
  listeners: [
    { port: 80, protocol: "HTTP", tlsPolicy: null, redirects: true },
    { port: 443, protocol: "HTTPS", tlsPolicy: "tls_cipher_policy_1_2_strict_with_1_3", redirects: false },
  ],
  ...extra,
});

export function region(extra: Partial<AlibabaRegion> = {}): AlibabaRegion {
  return {
    name: R,
    securityGroups: [sg("sg-web", openTo("tcp", 443)), sg("sg-db")],
    instances: [
      {
        id: "i-1",
        name: "web",
        running: true,
        publicIp: IP,
        privateIp: "10.0.0.5",
        vpcId: VPC,
        network: "vpc",
        securityGroups: ["sg-web"],
        os: "linux",
        keyPair: true,
        metadataTokens: true,
        role: "web",
        userDataSecret: null,
      },
    ],
    interfaces: [
      { id: "eni-1", publicIp: IP, privateIp: "10.0.0.5", securityGroups: ["sg-web"], kind: "instance", owner: "i-1" },
      { id: "eni-2", publicIp: null, privateIp: "10.0.0.6", securityGroups: ["sg-db"], kind: "network interface", owner: null },
    ],
    addresses: [IP],
    disks: [{ id: "d-1", encrypted: true, inUse: true }],
    diskEncryptionByDefault: true,
    images: [{ id: "m-1", name: "golden", sharedWith: [] }],
    launchTemplates: [{ id: "lt-1", name: "web", metadataTokens: true, userDataSecret: null }],
    vpcs: [{ id: VPC, flowLogs: true }],
    databases: [
      { id: "rm-1", name: "orders", service: "rds", engine: "MySQL", publicEndpoint: false, openWhitelist: [], ssl: true, tde: true },
      {
        id: "r-1",
        name: "sessions",
        service: "redis",
        engine: "Redis 7.0",
        publicEndpoint: false,
        openWhitelist: [],
        ssl: true,
        tde: null,
        passwordFree: false,
      },
    ],
    loadBalancers: [alb()],
    serverGroups: [],
    functions: [{ name: "fn", runtime: "nodejs20", role: "fn-role", anonymousTriggers: [], envSecret: null }],
    keys: [{ id: "key-1", description: "data", enabled: true, rotatable: true, rotation: true, deletionDate: null }],
    secrets: [{ name: "db", createdAt: days(-500), rotation: true, rotatedAt: days(-20) }],
    clusters: [{ id: "c-1", name: "prod", region: R, version: "1.32.1", publicEndpoint: false }],
    ...extra,
  };
}

const user = (extra: Partial<AlibabaUser> = {}): AlibabaUser => ({
  name: "alex",
  createdAt: days(-400),
  console: true,
  lastLoginAt: days(-1),
  mfa: true,
  keys: [],
  ...extra,
});

export const role = (extra: Partial<AlibabaRole> = {}): AlibabaRole => ({
  name: "app",
  trust: [{ principal: "ecs.aliyuncs.com", kind: "service", conditional: false }],
  admin: false,
  serviceLinked: false,
  ...extra,
});

export function alibabaInventory(extra: Partial<AlibabaInventory> = {}): AlibabaInventory {
  return {
    accountId: ACCOUNT,
    accountName: "example",
    now: NOW,
    unreadable: [],
    rootKey: false,
    root: { accessKeys: 0, mfa: true },
    securityPreference: { mfaAtLogin: "mandatory", usersManageKeys: false },
    passwordPolicy: {
      minLength: 14,
      requireLowercase: true,
      requireUppercase: true,
      requireNumbers: true,
      requireSymbols: true,
      maxAge: 0,
      reusePrevention: 5,
      maxLoginAttempts: 5,
    },
    users: [user()],
    admins: [],
    roles: [role()],
    policies: [{ name: "app", fullAdmin: false, attachments: 1 }],
    escalations: [],
    ossBlock: true,
    buckets: [bucket()],
    regions: [region()],
    regionNames: { [R]: "China (Hangzhou)" },
    skippedRegions: [],
    trails: [{ name: "main", homeRegion: R, allRegions: true, allEvents: true, logging: true, delivers: true, ossBucket: "trail-logs", organization: false }],
    protectedInstances: new Set(["i-1"]),
    cdnDomains: [
      { name: "cdn.example.com", cname: "cdn.example.com.w.kunlunsl.com", origins: ["assets.oss-cn-hangzhou.aliyuncs.com"], https: true, online: true },
    ],
    domains: [
      {
        name: "example.com",
        records: [
          { name: "app.example.com", type: "CNAME", value: ALB },
          { name: "www.example.com", type: "A", value: IP },
        ],
      },
    ],
    released: [],
    images: imageCase("alibaba", "example-registry.cn-hangzhou.cr.aliyuncs.com", 0, { region: "cn-hangzhou", repository: "shop/web" }),
    ...extra,
  };
}

const withRegion = (extra: Partial<AlibabaRegion>) => alibabaInventory({ regions: [region(extra)] });
const withUser = (extra: Partial<AlibabaUser>) => alibabaInventory({ users: [user(extra)] });
const withRecord = (name: string, type: string, value: string) => alibabaInventory({ domains: [{ name: "example.com", records: [{ name, type, value }] }] });
const withGithubRole = (subjects: string[]) =>
  alibabaInventory({
    roles: [
      role({ name: "deploy", trust: [{ principal: `acs:ram::${ACCOUNT}:oidc-provider/github`, kind: "federated", conditional: true, github: subjects }] }),
    ],
  });
/** A role GitLab CI on gitlab.com can assume, with these subjects on its trust policy. */
const withGitlabRole = (subjects: string[]) =>
  alibabaInventory({
    roles: [
      role({
        name: "deploy",
        trust: [{ principal: `acs:ram::${ACCOUNT}:oidc-provider/gitlab`, kind: "federated", conditional: true, oidc: { host: "gitlab.com", subjects } }],
      }),
    ],
  });
const GITLAB_ENTITY = {
  gitlabGroups: [{ host: "gitlab.com", group: "example" }],
  gitlabProjects: [{ host: "gitlab.com", repo: "example/app", defaultBranch: "main", reviewed: true }],
};
const instance = region().instances![0];

/** An image in the account's registry instance, run by a workload the internet reaches, failing image check `n`. */
const ACR = "example-registry.cn-hangzhou.cr.aliyuncs.com";
export const withImage = (n: 0 | 1 | 2 | 3 | 4) =>
  alibabaInventory({ images: imageCase("alibaba", ACR, n, { region: "cn-hangzhou", repository: "shop/web" }) });

export const ALIBABA_CASES: Record<AlibabaCheckId, () => AlibabaInventory> = {
  "LID-001": () => alibabaInventory({ root: { accessKeys: 1, mfa: true } }),
  "LID-013": () => alibabaInventory({ root: { accessKeys: 0, mfa: false } }),
  "LID-002": () => withUser({ mfa: false }),
  "LID-014": () => alibabaInventory({ securityPreference: { mfaAtLogin: "mandatory", usersManageKeys: true } }),
  "LID-015": () => withUser({ keys: [{ hint: "A1B2", active: true, createdAt: days(-10), lastUsedAt: days(-1) }] }),
  "LID-003": () => withUser({ keys: [{ hint: "A1B2", active: true, createdAt: days(-200), lastUsedAt: days(-1) }] }),
  "LID-004": () => withUser({ keys: [{ hint: "A1B2", active: true, createdAt: days(-200), lastUsedAt: days(-150) }] }),
  "LID-005": () => withUser({ lastLoginAt: days(-200) }),
  "LID-006": () => alibabaInventory({ passwordPolicy: { ...alibabaInventory().passwordPolicy!, minLength: 8 } }),
  "LID-007": () =>
    alibabaInventory({
      users: [user({ keys: [{ hint: "A1B2", active: true, createdAt: days(-10), lastUsedAt: days(-1) }] })],
      admins: [{ kind: "user", name: "alex", via: "the AdministratorAccess policy" }],
    }),
  "LID-008": () => alibabaInventory({ roles: [role({ trust: [{ principal: "*", kind: "anyone", conditional: false }] })] }),
  "LID-009": () => alibabaInventory({ policies: [{ name: "everything", fullAdmin: true, attachments: 1 }] }),
  "LID-010": () => alibabaInventory({ roles: [role({ trust: [{ principal: `acs:ram::${OUTSIDER}:root`, kind: "account", conditional: false }] })] }),
  "LID-011": () => alibabaInventory({ escalations: [{ kind: "user", name: "ci", via: "the policy deploy", paths: ["ram:AttachPolicyToUser"] }] }),
  "LID-012": () => withGithubRole([]),
  "XP-022": () => withGithubRole(["repo:other-org/app:ref:refs/heads/main"]),
  "XP-023": () => withGithubRole(["repo:example/app:*"]),

  "LOS-001": () => alibabaInventory({ ossBlock: false, buckets: [bucket({ blockPublicAccess: true })] }),
  "LOS-002": () => alibabaInventory({ ossBlock: false, buckets: [bucket({ blockPublicAccess: false, acl: "public-read" })] }),
  "LOS-003": () => alibabaInventory({ ossBlock: false, buckets: [bucket({ blockPublicAccess: false })] }),
  "LOS-004": () => alibabaInventory({ buckets: [bucket({ policy: { public: false, otherAccounts: [OUTSIDER] } })] }),

  "LNW-001": () => withRegion({ securityGroups: [sg("sg-web", openTo("tcp", 22))] }),
  "LNW-002": () => withRegion({ securityGroups: [sg("sg-web", openTo("tcp", 3306))] }),
  "LNW-003": () => withRegion({ securityGroups: [sg("sg-web", openTo("all", null))] }),
  "LNW-004": () => withRegion({ instances: [{ ...instance, network: "classic" }] }),
  // A CLB passing SSH from anyone to its backends: the backends' groups admit the CLB, so they don't stop it.
  "LNW-005": () =>
    withRegion({
      loadBalancers: [
        alb(),
        {
          id: "lb-1",
          name: "legacy",
          type: "clb",
          dnsName: null,
          address: "203.0.113.30",
          internetFacing: true,
          vpcId: VPC,
          securityGroups: [],
          listeners: [{ port: 2222, protocol: "TCP", backendPort: 22, access: null, tlsPolicy: null, redirects: false }],
        },
      ],
    }),

  "LEC-001": () => withRegion({ instances: [{ ...instance, metadataTokens: false }] }),
  "LEC-002": () => withRegion({ diskEncryptionByDefault: false }),
  "LEC-009": () => withRegion({ instances: [{ ...instance, keyPair: false }], securityGroups: [sg("sg-web", openTo("tcp", 22)), sg("sg-db")] }),
  "LEC-004": () => withRegion({ instances: [{ ...instance, userDataSecret: "an Alibaba Cloud AccessKey" }] }),
  "LEC-005": () => withRegion({ launchTemplates: [{ id: "lt-1", name: "web", metadataTokens: false, userDataSecret: null }] }),
  "LEC-006": () => withRegion({ launchTemplates: [{ id: "lt-1", name: "web", metadataTokens: true, userDataSecret: "a password in a URL" }] }),
  "LEC-007": () => ({
    ...withRegion({}),
    roles: [role({ name: "web", admin: true })],
    admins: [{ kind: "role", name: "web", via: "the AdministratorAccess policy" }],
  }),
  "LEC-008": () => withRegion({ images: [{ id: "m-1", name: "golden", sharedWith: [OUTSIDER] }] }),

  "LDB-001": () => withRegion({ databases: [{ ...region().databases![0], publicEndpoint: true, openWhitelist: ["0.0.0.0/0"] }] }),
  "LDB-002": () => withRegion({ databases: [{ ...region().databases![0], ssl: false }] }),
  "LDB-003": () => withRegion({ databases: [{ ...region().databases![0], tde: false }] }),
  "LDB-004": () => withRegion({ databases: [{ ...region().databases![1], passwordFree: true }] }),

  "LCN-001": () => withRegion({ clusters: [{ id: "c-1", name: "prod", region: R, version: "1.32.1", publicEndpoint: true }] }),
  "LCN-002": () =>
    withRegion({
      functions: [{ name: "fn", runtime: "nodejs20", role: null, anonymousTriggers: [], envSecret: { where: "TOKEN", kind: "a GitHub token", likely: false } }],
    }),
  "LCN-003": () => withRegion({ functions: [{ name: "fn", runtime: "nodejs20", role: null, anonymousTriggers: ["http"], envSecret: null }] }),

  "LKM-001": () => withRegion({ keys: [{ id: "key-1", description: null, enabled: true, rotatable: true, rotation: false, deletionDate: null }] }),
  "LKM-002": () => withRegion({ keys: [{ id: "key-1", description: null, enabled: false, rotatable: true, rotation: true, deletionDate: days(7) }] }),
  "LKM-003": () => withRegion({ secrets: [{ name: "db", createdAt: days(-500), rotation: false, rotatedAt: null }] }),

  "LLB-001": () => withRegion({ loadBalancers: [alb({ listeners: [{ port: 80, protocol: "HTTP", tlsPolicy: null, redirects: false }] })] }),
  "LLB-002": () =>
    withRegion({ loadBalancers: [alb({ listeners: [{ port: 443, protocol: "HTTPS", tlsPolicy: "tls_cipher_policy_1_0", redirects: false }] })] }),
  "LLB-003": () =>
    alibabaInventory({ cdnDomains: [{ name: "cdn.example.com", cname: "cdn.example.com.w.kunlunsl.com", origins: [], https: false, online: true }] }),

  "LDN-001": () => withRecord("files.example.com", "CNAME", "gone-bucket.oss-cn-hangzhou.aliyuncs.com"),
  // The address was the account's until an earlier scan; the record still points at it.
  "LDN-002": () => ({ ...withRecord("old.example.com", "A", "203.0.113.77"), released: [{ ip: "203.0.113.77", at: "2026-05-20T00:00:00.000Z" }] }),
  "XP-019": () => withRecord("promo.example.com", "CNAME", "cname.vercel-dns.com"),
  "XP-020": () => withRecord("media.example.com", "CNAME", "d9gone.cloudfront.net"),
  "XP-024": () => withRecord("docs.example.com", "CNAME", "someone.github.io"),
  "LID-016": () => withGitlabRole([]),
  "XP-031": () => withGitlabRole(["project_path:other-group/app:ref_type:branch:ref:main"]),
  "XP-032": () => withGitlabRole(["project_path:example/app:*"]),
  "XP-033": () => withRecord("handbook.example.com", "CNAME", "someone.gitlab.io"),

  "LMO-001": () => alibabaInventory({ trails: [] }),
  "LMO-002": () => withRegion({ vpcs: [{ id: VPC, flowLogs: false }] }),
  "LMO-003": () => alibabaInventory({ protectedInstances: new Set() }),

  // The fixture's load balancer uses a group that lets everyone reach 443; a Cloudflare-proxied hostname points at it.
  "XP-018": () => alibabaInventory(),

  "LIM-001": () => withImage(1),
  "LIM-002": () => withImage(2),
  "LIM-003": () => withImage(3),
  "LIM-004": () => withImage(4),
};

const GITHUB_ENTITY: Partial<EngineOptions["related"]> = {
  githubOrgs: ["example"],
  githubRepos: [{ repo: "example/app", defaultBranch: "main", reviewed: true }],
};

/** Engine options a case needs beyond the defaults: checks that span providers read the entity's other accounts. */
export const ALIBABA_CASE_OPTS: Partial<Record<AlibabaCheckId, Partial<EngineOptions>>> = {
  "XP-022": { related: GITHUB_ENTITY },
  "XP-023": { related: GITHUB_ENTITY },
  "XP-018": { related: { toAlibaba: [{ host: "shop.example.com", zone: "example.com", target: ALB, kind: "slb", name: ALB, proxied: true }] } },
  "XP-019": { related: { vercelDomains: [{ host: "app.example.com", project: "web", projectId: "prj_1", protectsDeploymentUrls: true }] } },
  "XP-020": { related: { awsEndpoints: [{ kind: "cloudfront", name: "d1current.cloudfront.net" }] } },
  "XP-024": { related: { githubPages: [{ host: "www.example.com", repo: "site" }] } },
  "XP-031": { related: GITLAB_ENTITY },
  "XP-032": { related: GITLAB_ENTITY },
  "XP-033": { related: { gitlabPages: [{ host: "www.example.com", repo: "example/site" }] } },
};
