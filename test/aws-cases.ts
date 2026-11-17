// A well-configured AWS account, and one failing case per AWS check. The type is
// Record<AwsCheckId, …>, so a new check without a case doesn't compile, and
// test/aws-checks.test.ts asserts each case really makes its check fail.

import type { AwsCheckId } from "../src/providers/aws/checks/index.ts";
import type { EngineOptions } from "../src/core/types.ts";
import { toPrefixes } from "../src/core/aws-ranges.ts";
import type { AwsBucket, AwsDistribution, AwsInventory, AwsRegion, AwsRole, AwsSecurityGroup, AwsUser, PublicAccessBlock } from "../src/providers/aws/types.ts";

export const NOW = Date.parse("2026-06-01T00:00:00Z");
const days = (n: number) => NOW + n * 86_400_000;
const R = "eu-west-1";
const VPC = "vpc-1";
/** The instance's address, inside the fixture's "EC2 range". */
const IP = "198.51.100.9";
const LB_DNS = `alb-1.${R}.elb.amazonaws.com`;
const LB_ARN = `arn:aws:elasticloadbalancing:${R}:111122223333:loadbalancer/app/alb/1`;
const TRAIL = `arn:aws:cloudtrail:${R}:111122223333:trail/main`;

const blocked: PublicAccessBlock = { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true };
const unblocked: PublicAccessBlock = { blockPublicAcls: false, ignorePublicAcls: false, blockPublicPolicy: false, restrictPublicBuckets: false };
const openTo = (protocol: string, port: number | null): AwsSecurityGroup["open"] => [{ protocol, from: port, to: port, cidr: "0.0.0.0/0" }];
const sg = (id: string, open: AwsSecurityGroup["open"] = []): AwsSecurityGroup => ({ id, name: id, vpcId: VPC, open });
const bucket = (extra: Partial<AwsBucket> = {}): AwsBucket => ({
  name: "assets",
  region: R,
  block: blocked,
  policyPublic: null,
  aclPublic: [],
  policy: { otherAccounts: [], deniesHttp: true },
  ...extra,
});

export function region(extra: Partial<AwsRegion> = {}): AwsRegion {
  return {
    name: R,
    securityGroups: [sg("sg-web", openTo("tcp", 443)), sg("sg-db")],
    instances: [
      { id: "i-1", name: "web", running: true, publicIp: IP, vpcId: VPC, securityGroups: ["sg-web"], imdsV2: true, profile: "web", userDataSecret: null },
    ],
    interfaces: [
      { id: "eni-1", publicIp: IP, securityGroups: ["sg-web"], kind: "instance", owner: "i-1" },
      { id: "eni-2", publicIp: null, securityGroups: ["sg-db"], kind: "database", owner: "RDSNetworkInterface" },
    ],
    addresses: [IP],
    apiDomains: [],
    ebsEncryptionByDefault: true,
    publicSnapshots: [],
    publicImages: [],
    vpcs: [{ id: VPC, isDefault: false, flowLogs: true }],
    databases: [
      {
        id: "db",
        engine: "postgres",
        public: false,
        encrypted: true,
        backupDays: 7,
        replica: false,
        vpcId: VPC,
        securityGroups: ["sg-db"],
        port: 5432,
        tlsRequired: true,
        parameterGroup: "pg",
      },
    ],
    loadBalancers: [
      {
        name: "alb",
        arn: LB_ARN,
        desync: "defensive",
        dnsName: LB_DNS,
        type: "application",
        internetFacing: true,
        vpcId: VPC,
        securityGroups: ["sg-web"],
        accessLogs: true,
        listeners: [
          { port: 80, protocol: "HTTP", sslPolicy: null, redirects: true },
          { port: 443, protocol: "HTTPS", sslPolicy: "ELBSecurityPolicy-TLS13-1-2-2021-06", redirects: false },
        ],
      },
    ],
    functions: [{ name: "fn", runtime: "nodejs22.x", role: "app", urls: [{ authType: "AWS_IAM" }], publicPolicy: false, envSecret: null }],
    guardDuty: true,
    trails: [{ arn: TRAIL, name: "main", homeRegion: R, multiRegion: true, organization: false, own: true, logging: true, validation: true }],
    configRecording: true,
    keys: [{ id: "key-1", description: "app data", enabled: true, rotatable: true, rotation: true, deletionDate: null, publicPolicy: false }],
    certificates: [{ id: "cert-1", domain: "www.example.com", type: "IMPORTED", inUse: true, notAfter: days(200), renews: false }],
    secrets: [{ name: "db-password", createdAt: days(-400), changedAt: days(-30), accessedAt: days(-1), rotation: true, publicPolicy: false }],
    repositories: [{ name: "app", scanned: true, immutableTags: true, publicPolicy: false }],
    taskDefinitions: [{ name: "app:3", services: ["app"], privileged: [], hostNamespaces: [], secret: null }],
    kubernetes: [
      { name: "prod", version: "1.33", publicEndpoint: true, openToAll: false, secretsEncrypted: true, auditLogs: true, versionStatus: "STANDARD_SUPPORT" },
    ],
    tables: [{ name: "orders", pitr: true }],
    userPools: [{ id: "pool-1", name: "customers", mfa: "OPTIONAL" }],
    identityPools: [{ id: "idp-1", name: "app", guest: false, guestRole: null }],
    webAcls: [
      { name: "web", arn: "arn:aws:wafv2:eu-west-1:111122223333:regional/webacl/web/1", scope: "REGIONAL", rules: 3, logging: true, loadBalancers: [LB_ARN] },
    ],
    documents: [{ name: "patch-hosts", public: false }],
    buildProjects: [{ name: "build", public: false, secret: null }],
    eventBuses: [{ name: "default", public: false }],
    notebooks: [{ name: "research", internet: false }],
    searchDomains: [
      { name: "logs", vpc: true, openPolicy: false, fineGrained: true, encryptedAtRest: true, nodeToNode: true, enforceHttps: true, tls12: true },
    ],
    caches: [{ id: "sessions", engine: "redis", transit: true, atRest: true }],
    warehouses: [{ id: "analytics", public: false, encrypted: true }],
    topics: [{ name: "alerts", public: false }],
    httpSubscriptions: [],
    queues: [{ name: "jobs", public: false }],
    brokers: [{ name: "events", engine: "RABBITMQ", public: false }],
    kafka: [{ name: "stream", public: false, unauthenticated: false, plaintext: false }],
    fileSystems: [{ id: "fs-1", name: "shared", encrypted: true }],
    launchTemplates: [{ id: "lt-1", name: "web", imdsV2: true, userDataSecret: null }],
    unencryptedVolumes: [],
    sharingBlocks: { snapshots: "block-all-sharing", images: "block-new-sharing" },
    transitGateways: [{ id: "tgw-1", autoAccept: false }],
    dbSnapshots: [{ id: "before-migration", cluster: false, public: false }],
    ...extra,
  };
}

const distribution = (extra: Partial<AwsDistribution> = {}): AwsDistribution => ({
  id: "E1",
  domainName: "d1example.cloudfront.net",
  enabled: true,
  aliases: ["www.example.com"],
  viewerPolicies: ["redirect-to-https"],
  minTls: "TLSv1.2_2021",
  defaultCertificate: false,
  waf: true,
  origins: [
    { domain: "origin.example.com", protocolPolicy: "https-only", s3: false, restricted: false },
    { domain: "assets.s3.amazonaws.com", protocolPolicy: null, s3: true, restricted: true, missingBucket: false },
  ],
  ...extra,
});

export const role = (extra: Partial<AwsRole> = {}): AwsRole => ({
  name: "app",
  trust: [{ principal: "ec2.amazonaws.com", kind: "service", conditional: false }],
  admin: false,
  serviceLinked: false,
  profiles: ["web"],
  lastUsedAt: days(-1),
  ...extra,
});

export function awsInventory(extra: Partial<AwsInventory> = {}): AwsInventory {
  return {
    accountId: "111122223333",
    accountName: "example",
    now: NOW,
    unreadable: [],
    rootKey: false,
    root: { mfa: true, accessKeys: false, users: 2 },
    passwordPolicy: { minLength: 14, symbols: true, numbers: true, uppercase: true, lowercase: true, reusePrevention: 24 },
    users: [
      { name: "dana", createdAt: days(-400), console: true, passwordLastUsedAt: days(-3), mfa: true, keys: [] },
      {
        name: "deploy",
        createdAt: days(-200),
        console: false,
        passwordLastUsedAt: null,
        mfa: false,
        keys: [{ hint: "AB12", active: true, createdAt: days(-30), lastUsedAt: days(-1) }],
      },
    ],
    admins: [{ user: "dana", via: "the group Admins" }],
    roles: [role()],
    policies: [{ name: "deploy-policy", fullAdmin: false, attachments: 1 }],
    escalations: [],
    serverCertificates: [{ name: "legacy-cert", expiresAt: days(100) }],
    s3Block: blocked,
    buckets: [bucket()],
    regions: [region()],
    skippedRegions: [],
    distributions: [distribution()],
    released: [],
    hostedZones: [
      {
        id: "Z1",
        name: "example.com",
        private: false,
        records: [
          { name: "www.example.com", type: "A", targets: ["d1example.cloudfront.net"], alias: true },
          { name: "vm.example.com", type: "A", targets: [IP], alias: false },
        ],
      },
    ],
    ec2Prefixes: toPrefixes(["198.51.100.0/24"]),
    ...extra,
  };
}

const withUser = (u: Partial<AwsUser>) => awsInventory({ users: [{ ...awsInventory().users![0], ...u }] });
const withKey = (createdAt: number, lastUsedAt: number | null) =>
  awsInventory({ users: [{ ...awsInventory().users![1], keys: [{ hint: "AB12", active: true, createdAt, lastUsedAt }] }] });
const withRegion = (extra: Partial<AwsRegion>) => awsInventory({ regions: [region(extra)] });
const withGroup = (open: AwsSecurityGroup["open"]) => withRegion({ securityGroups: [sg("sg-web", open), sg("sg-db")] });
const withDb = (extra: Partial<NonNullable<AwsRegion["databases"]>[number]>) => withRegion({ databases: [{ ...region().databases![0], ...extra }] });
const withDist = (extra: Partial<AwsDistribution>) => awsInventory({ distributions: [distribution(extra)] });
const withListeners = (listeners: NonNullable<AwsRegion["loadBalancers"]>[number]["listeners"]) =>
  withRegion({ loadBalancers: [{ ...region().loadBalancers![0], listeners }] });
const withRecord = (name: string, type: string, target: string, alias = false) =>
  awsInventory({ hostedZones: [{ id: "Z1", name: "example.com", private: false, records: [{ name, type, targets: [target], alias }] }] });

export const AWS_CASES: Record<AwsCheckId, () => AwsInventory> = {
  "AID-001": () => awsInventory({ root: { mfa: false, accessKeys: false, users: 2 } }),
  "AID-002": () => awsInventory({ root: { mfa: true, accessKeys: true, users: 2 } }),
  "AID-003": () => withUser({ mfa: false }),
  "AID-004": () => withKey(days(-200), days(-1)),
  "AID-005": () => withKey(days(-200), days(-150)),
  "AID-006": () => withUser({ passwordLastUsedAt: days(-200) }),
  "AID-007": () => awsInventory({ passwordPolicy: null }),
  "AID-008": () => awsInventory({ admins: [{ user: "deploy", via: "the AdministratorAccess policy" }] }),
  "AID-009": () =>
    awsInventory({ roles: [role({ name: "open", trust: [{ principal: "*", kind: "anyone", conditional: false }], admin: true, profiles: [] })] }),
  "AID-010": () => awsInventory({ policies: [{ name: "everything", fullAdmin: true, attachments: 1 }] }),
  "AID-011": () =>
    awsInventory({
      roles: [
        role({ name: "vendor", trust: [{ principal: "arn:aws:iam::999988887777:root", kind: "account", conditional: false }], profiles: [], lastUsedAt: null }),
      ],
    }),

  "AS3-001": () => awsInventory({ s3Block: null }),
  "AS3-002": () => awsInventory({ s3Block: null, buckets: [bucket({ block: null, policyPublic: true })] }),
  "AS3-003": () => awsInventory({ s3Block: unblocked, buckets: [bucket({ block: null })] }),

  "ANW-001": () => withGroup(openTo("tcp", 22)),
  "ANW-002": () => withGroup(openTo("tcp", 5432)),
  "ANW-003": () => withGroup(openTo("-1", null)),

  "AEC-001": () => withRegion({ instances: [{ ...region().instances![0], imdsV2: false }] }),
  "AEC-002": () => withRegion({ ebsEncryptionByDefault: false }),
  "AEC-003": () => withRegion({ publicSnapshots: ["snap-1"] }),
  "AEC-004": () => withRegion({ publicImages: [{ id: "ami-1", name: "base" }] }),
  "AEC-005": () => withRegion({ functions: [{ name: "fn", runtime: "nodejs16.x", role: "app", urls: [] }] }),
  "AEC-006": () => withRegion({ functions: [{ name: "fn", runtime: "nodejs22.x", role: "app", urls: [{ authType: "NONE" }] }] }),
  // The fixture's instance is public behind a group that opens 443: all it takes is an administrator's role.
  "AEC-007": () => awsInventory({ roles: [role({ admin: true })] }),
  "AEC-008": () => withRegion({ instances: [{ ...region().instances![0], userDataSecret: "an AWS access key" }] }),

  "ADB-001": () => withDb({ public: true }),
  "ADB-002": () => withDb({ encrypted: false }),
  "ADB-003": () => withDb({ backupDays: 0 }),

  "AED-001": () => withDist({ viewerPolicies: ["allow-all"] }),
  "AED-002": () => withDist({ minTls: "TLSv1_2016" }),
  "AED-003": () => withDist({ waf: false }),
  "AED-004": () => withDist({ origins: [{ domain: "origin.example.com", protocolPolicy: "http-only", s3: false, restricted: false }] }),
  "AED-005": () => withListeners([{ port: 80, protocol: "HTTP", sslPolicy: null, redirects: false }]),
  "AED-006": () => withListeners([{ port: 443, protocol: "HTTPS", sslPolicy: "ELBSecurityPolicy-2016-08", redirects: false }]),

  "ADN-001": () => withRecord("old.example.com", "CNAME", "d9gone.cloudfront.net"),
  // The address was the account's until an earlier scan; the record still points at it.
  "ADN-002": () => ({ ...withRecord("old-vm.example.com", "A", "198.51.100.77"), released: [{ ip: "198.51.100.77", at: "2026-05-20T00:00:00.000Z" }] }),
  "ADN-003": () => withRecord("partner.example.com", "A", "198.51.100.77"),
  "XP-005": () => withRecord("docs.example.com", "CNAME", "cname.vercel-dns.com"),
  "XP-021": () => withRecord("files.example.com", "CNAME", "old-bucket.oss-cn-hangzhou.aliyuncs.com"),
  // The fixture's load balancer uses a group that lets everyone reach 443; a Cloudflare-proxied hostname points at it.
  "XP-006": () => awsInventory(),
  "AID-012": () => withGithubRole([]),
  "XP-010": () => withGithubRole(["repo:other-org/app:ref:refs/heads/main"]),
  "XP-011": () => withGithubRole(["repo:example/app:*"]),

  "AMO-001": () => withRegion({ guardDuty: false }),
  "AMO-002": () => withRegion({ vpcs: [{ id: VPC, isDefault: false, flowLogs: false }] }),
  "AMO-003": () => withRegion({ loadBalancers: [{ ...region().loadBalancers![0], accessLogs: false }] }),

  "AID-013": () => awsInventory({ escalations: [{ kind: "role", name: "ci", via: "the policy deploy-tools", paths: ["iam:PassRole with ec2:RunInstances"] }] }),
  "AID-014": () => withRegion({ identityPools: [{ id: "idp-1", name: "app", guest: true, guestRole: "app" }] }),
  "AID-015": () => withRegion({ userPools: [{ id: "pool-1", name: "customers", mfa: "OFF" }] }),
  "AS3-004": () => awsInventory({ buckets: [bucket({ policy: { otherAccounts: ["999988887777"], deniesHttp: true } })] }),
  "ANW-004": () => withRegion({ transitGateways: [{ id: "tgw-1", autoAccept: true }] }),

  "AEC-009": () => withRegion({ launchTemplates: [{ id: "lt-1", name: "web", imdsV2: false, userDataSecret: null }] }),
  "AEC-010": () => withRegion({ launchTemplates: [{ id: "lt-1", name: "web", imdsV2: true, userDataSecret: "an AWS access key" }] }),
  "AEC-011": () => withRegion({ unencryptedVolumes: [{ id: "vol-1", instance: "i-1" }] }),
  "AEC-012": () => withRegion({ sharingBlocks: { snapshots: "unblocked", images: "block-new-sharing" } }),
  "AEC-013": () => withRegion({ functions: [{ ...region().functions![0], publicPolicy: true }] }),
  "AEC-014": () => withRegion({ functions: [{ ...region().functions![0], envSecret: { where: "STRIPE_KEY", kind: "a Stripe secret key", likely: false } }] }),
  "AEC-015": () => withRegion({ notebooks: [{ name: "research", internet: true }] }),

  "ACN-001": () => withRegion({ kubernetes: [{ ...region().kubernetes![0], openToAll: true }] }),
  "ACN-002": () => withRegion({ kubernetes: [{ ...region().kubernetes![0], auditLogs: false }] }),
  "ACN-003": () => withRegion({ kubernetes: [{ ...region().kubernetes![0], version: "1.29", versionStatus: "EXTENDED_SUPPORT" }] }),
  "ACN-004": () => withRegion({ taskDefinitions: [{ ...region().taskDefinitions![0], privileged: ["agent"] }] }),
  "ACN-005": () =>
    withRegion({ taskDefinitions: [{ ...region().taskDefinitions![0], secret: { where: "app: GITHUB_TOKEN", kind: "a GitHub token", likely: false } }] }),
  "ACN-006": () => withRegion({ repositories: [{ ...region().repositories![0], publicPolicy: true }] }),
  "ACN-007": () => withRegion({ repositories: [{ ...region().repositories![0], scanned: false }] }),
  "ACN-008": () => withRegion({ repositories: [{ ...region().repositories![0], immutableTags: false }] }),

  "ADB-004": () => withRegion({ dbSnapshots: [{ id: "before-migration", cluster: false, public: true }] }),
  "ADB-005": () => withDb({ tlsRequired: false }),
  "ADB-006": () => withRegion({ searchDomains: [{ ...region().searchDomains![0], vpc: false, openPolicy: true }] }),
  "ADB-007": () => withRegion({ searchDomains: [{ ...region().searchDomains![0], nodeToNode: false }] }),
  "ADB-008": () => withRegion({ searchDomains: [{ ...region().searchDomains![0], enforceHttps: false }] }),
  "ADB-009": () => withRegion({ caches: [{ id: "sessions", engine: "redis", transit: false, atRest: true }] }),
  "ADB-010": () => withRegion({ caches: [{ id: "sessions", engine: "redis", transit: true, atRest: false }] }),
  "ADB-011": () => withRegion({ warehouses: [{ id: "analytics", public: true, encrypted: true }] }),
  "ADB-012": () => withRegion({ warehouses: [{ id: "analytics", public: false, encrypted: false }] }),
  "ADB-013": () => withRegion({ tables: [{ name: "orders", pitr: false }] }),
  "ADB-014": () => withRegion({ fileSystems: [{ id: "fs-1", name: "shared", encrypted: false }] }),

  "ASC-001": () => withRegion({ secrets: [{ ...region().secrets![0], publicPolicy: true }] }),
  "ASC-002": () => withRegion({ secrets: [{ ...region().secrets![0], rotation: false, changedAt: days(-500) }] }),
  "ASC-003": () => withRegion({ secrets: [{ ...region().secrets![0], accessedAt: days(-200) }] }),
  "ASC-004": () => withRegion({ keys: [{ ...region().keys![0], publicPolicy: true }] }),
  "ASC-005": () => withRegion({ keys: [{ ...region().keys![0], rotation: false }] }),
  "ASC-006": () => withRegion({ keys: [{ ...region().keys![0], enabled: false, deletionDate: days(7) }] }),
  "ASC-007": () => withRegion({ documents: [{ name: "patch-hosts", public: true }] }),
  "ASC-008": () =>
    withRegion({ buildProjects: [{ name: "build", public: false, secret: { where: "NPM_TOKEN", kind: "a secret-looking value", likely: true } }] }),
  "ASC-009": () => withRegion({ buildProjects: [{ name: "build", public: true, secret: null }] }),

  "AMQ-001": () => withRegion({ topics: [{ name: "alerts", public: true }] }),
  "AMQ-002": () => withRegion({ httpSubscriptions: [{ topic: "alerts", host: "hooks.example.com" }] }),
  "AMQ-003": () => withRegion({ queues: [{ name: "jobs", public: true }] }),
  "AMQ-004": () => withRegion({ brokers: [{ name: "events", engine: "RABBITMQ", public: true }] }),
  "AMQ-005": () => withRegion({ kafka: [{ name: "stream", public: true, unauthenticated: true, plaintext: false }] }),
  "AMQ-006": () => withRegion({ eventBuses: [{ name: "default", public: true }] }),

  "AMO-004": () => withRegion({ trails: [] }),
  "AMO-005": () => withRegion({ trails: [{ ...region().trails![0], validation: false }] }),
  "AMO-006": () => withRegion({ configRecording: false }),
  "AMO-007": () => withRegion({ webAcls: [{ ...region().webAcls![0], logging: false }] }),

  "AED-007": () => withRegion({ webAcls: [{ ...region().webAcls![0], loadBalancers: [] }] }),
  "AED-008": () => withRegion({ webAcls: [{ ...region().webAcls![0], rules: 0 }] }),
  "AED-009": () => withRegion({ loadBalancers: [{ ...region().loadBalancers![0], desync: "monitor" }] }),
  "AED-010": () => withDist({ origins: [{ domain: "gone-assets.s3.amazonaws.com", protocolPolicy: null, s3: true, restricted: true, missingBucket: true }] }),
  "AED-011": () => withRegion({ certificates: [{ ...region().certificates![0], notAfter: days(10) }] }),
  "AED-012": () => awsInventory({ serverCertificates: [{ name: "legacy-cert", expiresAt: days(-10) }] }),
};

/** Engine options a case needs beyond the defaults: checks that span providers read the entity's other accounts. */
/** A role GitHub Actions can assume, with these subjects on its trust policy. */
function withGithubRole(github: string[]) {
  const principal = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com";
  return awsInventory({ roles: [role({ name: "deploy", trust: [{ principal, kind: "federated", conditional: true, github }], profiles: [] })] });
}

const GITHUB_ENTITY = {
  githubOrgs: ["example"],
  githubRepos: [{ repo: "example/app", defaultBranch: "main", reviewed: true }],
};

export const AWS_CASE_OPTS: Partial<Record<AwsCheckId, Partial<EngineOptions>>> = {
  "XP-010": { related: GITHUB_ENTITY },
  "XP-011": { related: GITHUB_ENTITY },
  "XP-021": { related: { alibabaEndpoints: [{ kind: "oss", name: "current-bucket" }] } },
  "XP-005": { related: { vercelDomains: [{ host: "app.example.com", project: "web", projectId: "prj_1", protectsDeploymentUrls: true }] } },
  "XP-006": { related: { toAws: [{ host: "shop.example.com", zone: "example.com", target: LB_DNS, kind: "elb", name: LB_DNS, proxied: true }] } },
};
