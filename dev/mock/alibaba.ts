// A fetch replacement that serves a small, fictional Alibaba Cloud account, so
// Alibaba Cloud scans run end to end without network access (tests and `npm run dev
// -- --mock`). It chains onto whatever fetch is installed, so it works together with
// the other mocks.
//
// One AccessKey reaches the account "mock-alibaba": RAM, OSS, two regions
// (cn-hangzhou runs the workloads, ap-southeast-1 is empty), ActionTrail, Security
// Center, CDN and Alibaba Cloud DNS. Every request must carry a valid signature:
// the mock signs each one again with the mock secret (V3, or OSS's V4) and refuses
// a mismatch, so the signing code is exercised end to end. As with the other mocks,
// the data is deliberately imperfect so every check has something to find, dates
// are relative to now, and answers are in the shapes of Alibaba Cloud's API
// metadata.

import { signAcs3, signOss4 } from "../../src/providers/alibaba/sign.ts";
import { productOfHost } from "../../src/providers/alibaba/client.ts";
import { installMockTrivy, MOCK_DIGEST, type MockTrivyOptions } from "./trivy.ts";

const DAY = 86_400_000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString().replace(/\.\d{3}Z$/, "Z");

export const MOCK_ALIBABA_ACCOUNT = "5000000000000001";
export const MOCK_ALIBABA_KEY_ID = "LTAIMOCKMOCKMOCK0001";
const SECRET = "mockSecretMockSecretMockSecret01";
/** The credential as the Accounts page sends it: AccessKey ID and secret, joined. */
export const MOCK_ALIBABA_TOKEN = `${MOCK_ALIBABA_KEY_ID}:${SECRET}`;
/** Values the mock hands out in places the scanner must scan without storing: a function's environment, a start-up script, a launch template. */
export const MOCK_ALIBABA_FUNCTION_TOKEN = "ghp_MOCKmockMOCKmockMOCKmockMOCKalib0001";
export const MOCK_ALIBABA_USER_DATA_KEY = "LTAIMOCKUSERDATA0099";
export const MOCK_ALIBABA_TEMPLATE_PASSWORD = "mock-template-password-0001";
/** An account outside the entity that roles, bucket policies and images trust. */
export const MOCK_ALIBABA_OUTSIDER = "5000000000009999";
export const MOCK_ALIBABA_ALB = "alb-mock0000000001.cn-hangzhou.alb.aliyuncs.com";
export const MOCK_ALIBABA_IP = "203.0.113.20";
/** An EIP the account gives up between the dev server's scans, which a DNS record still points at. */
export const MOCK_ALIBABA_RELEASED_IP = "203.0.113.21";
export const MOCK_ALIBABA_DOMAIN = "mock-alibaba.example";
/** The password of the registry login Container Registry hands out for Trivy: the only credential the image scanner may be given. */
export const MOCK_ALIBABA_REGISTRY_PASSWORD = "mock-acr-registry-password";
/** A value the mock returns in a container group's environment, so the scanner's job of dropping it is tested. */
export const MOCK_ALIBABA_POD_SECRET = "mock-pod-env-value-DO-NOT-STORE";

/** Switches for the dev server and tests: the EIP is released between scans. */
export const mockAlibaba = { released: false };
/** Regions ECS lists besides the two the mock serves: installMockAlibaba's refuseRegions. */
let extraRegions: string[] = [];

interface MockOptions {
  onRequest?: (url: URL, init?: RequestInit) => void;
  /** Requests (regex on "host/path?query" or on "product:Action") that answer 403, to simulate a policy that doesn't allow them. */
  deny?: RegExp[];
  /** Extra regions ECS lists that refuse every request, like a region a policy denies. */
  refuseRegions?: string[];
  /** Hosts that answer every request with 503, as Function Compute's endpoint does in a region it isn't offered in. */
  unavailable?: RegExp[];
  /** Options for the mock Trivy (dev/mock/trivy.ts), installed with the API. */
  trivy?: MockTrivyOptions;
}

const WORK = "cn-hangzhou";
const SG = { web: "sg-mockweb0001", db: "sg-mockdb0001", all: "sg-mockall0001" };
const WEB = "i-mockweb0001";
const WORKER = "i-mockworker0001";
const LEGACY = "i-mocklegacy0001";
const VPC = "vpc-mock0001";
const OIDC = `acs:ram::${MOCK_ALIBABA_ACCOUNT}:oidc-provider/github-actions`;
const b64 = (s: string) => Buffer.from(s).toString("base64");

const perm = (protocol: string, range: string, cidr: string, policy = "Accept", priority = 1) => ({
  Direction: "ingress",
  IpProtocol: protocol,
  PortRange: range,
  SourceCidrIp: cidr,
  Policy: policy,
  Priority: String(priority),
});

const RULES: Record<string, object[]> = {
  [SG.web]: [perm("TCP", "443/443", "0.0.0.0/0"), perm("TCP", "80/80", "0.0.0.0/0"), perm("TCP", "22/22", "0.0.0.0/0"), perm("TCP", "8080/8080", "10.0.0.0/8")],
  [SG.db]: [perm("TCP", "3306/3306", "0.0.0.0/0")],
  // Everything from anywhere, though nothing uses the group.
  [SG.all]: [perm("ALL", "-1/-1", "0.0.0.0/0"), perm("TCP", "22/22", "0.0.0.0/0", "Drop", 100)],
};

const trust = (statement: object) => JSON.stringify({ Version: "1", Statement: [statement] });
const ROLES: Record<string, string> = {
  "partner-access": trust({ Effect: "Allow", Action: "sts:AssumeRole", Principal: { RAM: "*" } }),
  "vendor-audit": trust({ Effect: "Allow", Action: "sts:AssumeRole", Principal: { RAM: [`acs:ram::${MOCK_ALIBABA_OUTSIDER}:root`] } }),
  "ops-admin": trust({ Effect: "Allow", Action: "sts:AssumeRole", Principal: { Service: ["ecs.aliyuncs.com"] } }),
  // GitHub Actions in any repository can assume it: the subject condition names no owner.
  "github-deploy": trust({
    Effect: "Allow",
    Action: "sts:AssumeRoleWithOIDC",
    Principal: { Federated: [OIDC] },
    Condition: { StringEquals: { "oidc:aud": "sts.aliyuncs.com" }, StringLike: { "oidc:sub": "repo:*" } },
  }),
  // Limited to the mock GitHub organization (dev/mock/github.ts), from any branch.
  "github-release": trust({
    Effect: "Allow",
    Action: "sts:AssumeRoleWithOIDC",
    Principal: { Federated: [OIDC] },
    Condition: { StringLike: { "oidc:sub": "repo:mock-org/*" } },
  }),
  AliyunServiceRoleForECS: trust({ Effect: "Allow", Action: "sts:AssumeRole", Principal: { Service: ["ecs.aliyuncs.com"] } }),
};

const POLICIES: Record<string, { doc: object; attached: { users?: string[]; groups?: string[]; roles?: string[] } }> = {
  "deploy-tools": {
    doc: { Version: "1", Statement: [{ Effect: "Allow", Action: ["oss:PutObject", "ram:AttachPolicyToUser"], Resource: "*" }] },
    attached: { users: ["ci-deploy"] },
  },
  everything: { doc: { Version: "1", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] }, attached: { roles: ["ops-admin"] } },
  "read-logs": { doc: { Version: "1", Statement: [{ Effect: "Allow", Action: "log:Get*", Resource: "*" }] }, attached: {} },
};
const SYSTEM_ATTACHED: Record<string, { users?: string[]; groups?: string[]; roles?: string[] }> = {
  AdministratorAccess: { groups: ["admins"] },
  AliyunRAMFullAccess: {},
};
const GROUPS: Record<string, string[]> = { admins: ["alex"] };

const users = [
  { UserPrincipalName: `alex@${MOCK_ALIBABA_ACCOUNT}.onaliyun.com`, CreateDate: ago(700), LastLoginDate: String(Date.now() - 1 * DAY) },
  { UserPrincipalName: `ci-deploy@${MOCK_ALIBABA_ACCOUNT}.onaliyun.com`, CreateDate: ago(500) },
  { UserPrincipalName: `sam@${MOCK_ALIBABA_ACCOUNT}.onaliyun.com`, CreateDate: ago(600), LastLoginDate: String(Date.now() - 200 * DAY) },
];
const KEYS: Record<string, { id: string; age: number; used: number }[]> = {
  alex: [{ id: "LTAIMOCKALEX0000A1B2", age: 400, used: 2 }],
  "ci-deploy": [{ id: "LTAIMOCKCI000000C3D4", age: 200, used: 150 }],
  sam: [],
};
const nameOf = (upn: string | null) => (upn ?? "").split("@")[0];

const BUCKETS: Record<string, { acl: string; block: boolean; policy?: object }> = {
  // Public, and served through the mock CDN domain, which could read it privately.
  "mock-assets": { acl: "public-read", block: false },
  "mock-uploads": { acl: "public-read-write", block: false },
  // Container Registry's own bucket: private, and not the account's to configure.
  "cri-mockregistry01-registry": { acl: "private", block: false },
  // ActionTrail delivers here, and its policy lets anyone read.
  "mock-trail-logs": {
    acl: "private",
    block: false,
    policy: { Version: "1", Statement: [{ Effect: "Allow", Principal: ["*"], Action: ["oss:GetObject"], Resource: ["acs:oss:*:*:mock-trail-logs/*"] }] },
  },
  "mock-private": {
    acl: "private",
    block: false,
    policy: {
      Version: "1",
      Statement: [{ Effect: "Allow", Principal: [MOCK_ALIBABA_OUTSIDER], Action: ["oss:GetObject"], Resource: ["acs:oss:*:*:mock-private/*"] }],
    },
  },
};

const instance = (id: string, name: string, o: { ip?: string; sg: string[]; tokens: string; network?: string; privateIp: string; keyPair?: string }) => ({
  InstanceId: id,
  InstanceName: name,
  OSType: "linux",
  KeyPairName: o.keyPair ?? "",
  Status: "Running",
  InstanceNetworkType: o.network ?? "vpc",
  PublicIpAddress: { IpAddress: [] as string[] },
  EipAddress: o.ip ? { IpAddress: o.ip, AllocationId: `eip-${id}` } : { IpAddress: "" },
  VpcAttributes: o.network === "classic" ? { VpcId: "", PrivateIpAddress: { IpAddress: [] } } : { VpcId: VPC, PrivateIpAddress: { IpAddress: [o.privateIp] } },
  InnerIpAddress: { IpAddress: o.network === "classic" ? [o.privateIp] : [] },
  SecurityGroupIds: { SecurityGroupId: o.sg },
  MetadataOptions: { HttpEndpoint: "enabled", HttpTokens: o.tokens },
});

/** RPC answers by product and action, for the working region; null is "not found". */
function rpc(product: string, action: string, q: URLSearchParams, region: string): unknown | null | undefined {
  const work = region === WORK;
  const page = <T>(list: T[], key: string, wrap?: string) => ({ [key]: wrap ? { [wrap]: list } : list, TotalCount: list.length, PageNumber: 1 });
  switch (`${product}:${action}`) {
    case "sts:GetCallerIdentity":
      return { AccountId: MOCK_ALIBABA_ACCOUNT, IdentityType: "RAMUser", Arn: `acs:ram::${MOCK_ALIBABA_ACCOUNT}:user/keelson`, UserId: "mock-user" };
    case "ram:GetAccountAlias":
      return { AccountAlias: "mock-alibaba" };
    case "ram:GetPasswordPolicy":
      return {
        PasswordPolicy: {
          MinimumPasswordLength: 8,
          RequireLowercaseCharacters: true,
          RequireUppercaseCharacters: false,
          RequireNumbers: true,
          RequireSymbols: false,
          MaxPasswordAge: 0,
          PasswordReusePrevention: 0,
          MaxLoginAttemps: 0,
        },
      };
    case "ims:GetSecurityPreference":
      // MFA left to each user, and every user may make their own AccessKeys.
      return {
        SecurityPreference: {
          LoginProfilePreference: { MFAOperationForLogin: "independent", EnforceMFAForLogin: false },
          AccessKeyPreference: { AllowUserToManageAccessKeys: true },
        },
      };
    case "ims:GetAccountSecurityPracticeReport":
      return { AccountSecurityPracticeInfo: { AccountSecurityPracticeUserInfo: { RootWithAccessKey: 1, BindMfa: false, SubUser: 3 }, Score: 40 } };
    case "ims:ListUsers":
      return { IsTruncated: false, Users: { User: users } };
    case "ims:GetLoginProfile": {
      const n = nameOf(q.get("UserPrincipalName"));
      // ci-deploy has no console password.
      return n === "ci-deploy" ? null : { LoginProfile: { UserPrincipalName: q.get("UserPrincipalName"), Status: "Active", MFABindRequired: false } };
    }
    case "ims:GetUserMFAInfo":
      return nameOf(q.get("UserPrincipalName")) === "sam"
        ? { IsMFAEnable: true, MFADevice: { SerialNumber: `acs:ram::${MOCK_ALIBABA_ACCOUNT}:mfa/sam`, Type: "VMFA" } }
        : null;
    case "ims:ListAccessKeys":
      return {
        AccessKeys: {
          AccessKey: (KEYS[nameOf(q.get("UserPrincipalName"))] ?? []).map((k) => ({ AccessKeyId: k.id, Status: "Active", CreateDate: ago(k.age) })),
        },
      };
    case "ims:GetAccessKeyLastUsed": {
      const key = Object.values(KEYS)
        .flat()
        .find((k) => k.id === q.get("UserAccessKeyId"));
      return { AccessKeyLastUsed: { LastUsedDate: key ? ago(key.used) : null, ServiceName: "Ecs" } };
    }
    case "ims:ListOIDCProviders":
      return {
        IsTruncated: false,
        OIDCProviders: { OIDCProvider: [{ OIDCProviderName: "github-actions", Arn: OIDC, IssuerUrl: "https://token.actions.githubusercontent.com" }] },
      };
    case "ram:ListPolicies":
      return {
        IsTruncated: false,
        Policies: {
          Policy: Object.entries(POLICIES).map(([name, p]) => ({
            PolicyName: name,
            PolicyType: "Custom",
            AttachmentCount: (p.attached.users?.length ?? 0) + (p.attached.groups?.length ?? 0) + (p.attached.roles?.length ?? 0),
          })),
        },
      };
    case "ram:GetPolicy": {
      const p = POLICIES[q.get("PolicyName") ?? ""];
      return p
        ? {
            Policy: { PolicyName: q.get("PolicyName") },
            DefaultPolicyVersion: { IsDefaultVersion: true, VersionId: "v1", PolicyDocument: JSON.stringify(p.doc) },
          }
        : null;
    }
    case "ram:ListEntitiesForPolicy": {
      const name = q.get("PolicyName") ?? "";
      const a = q.get("PolicyType") === "System" ? SYSTEM_ATTACHED[name] : POLICIES[name]?.attached;
      if (!a) return null;
      return {
        Users: { User: (a.users ?? []).map((UserName) => ({ UserName })) },
        Groups: { Group: (a.groups ?? []).map((GroupName) => ({ GroupName })) },
        Roles: { Role: (a.roles ?? []).map((RoleName) => ({ RoleName })) },
      };
    }
    case "ram:ListUsersForGroup":
      return { IsTruncated: false, Users: { User: (GROUPS[q.get("GroupName") ?? ""] ?? []).map((UserName) => ({ UserName })) } };
    case "ram:ListRoles":
      return { IsTruncated: false, Roles: { Role: Object.keys(ROLES).map((RoleName) => ({ RoleName })) } };
    case "ram:GetRole": {
      const name = q.get("RoleName") ?? "";
      return ROLES[name]
        ? { Role: { RoleName: name, AssumeRolePolicyDocument: ROLES[name], IsServiceLinkedRole: name.startsWith("AliyunServiceRole") } }
        : null;
    }

    case "ecs:DescribeRegions":
      return {
        Regions: {
          Region: [WORK, "ap-southeast-1", ...extraRegions].map((r) => ({
            RegionId: r,
            Status: "available",
            RegionEndpoint: `ecs.${r}.aliyuncs.com`,
            LocalName: { [WORK]: "China (Hangzhou)", "ap-southeast-1": "Singapore" }[r] ?? r,
          })),
        },
      };
    case "ecs:DescribeSecurityGroups":
      return page(
        work ? Object.values(SG).map((id) => ({ SecurityGroupId: id, SecurityGroupName: id.replace(/^sg-mock|0001$/g, ""), VpcId: VPC })) : [],
        "SecurityGroups",
        "SecurityGroup",
      );
    case "ecs:DescribeSecurityGroupAttribute":
      return { SecurityGroupId: q.get("SecurityGroupId"), Permissions: { Permission: RULES[q.get("SecurityGroupId") ?? ""] ?? [] } };
    case "ecs:DescribeInstances":
      return {
        Instances: {
          Instance: work
            ? [
                instance(WEB, "web-1", { ip: MOCK_ALIBABA_IP, sg: [SG.web], tokens: "optional", privateIp: "10.0.1.10" }),
                instance(WORKER, "worker-1", { sg: [SG.db], tokens: "required", privateIp: "10.0.1.20", keyPair: "ops" }),
                instance(LEGACY, "legacy-1", { sg: [SG.web], tokens: "required", network: "classic", privateIp: "10.10.0.5" }),
              ]
            : [],
        },
        TotalCount: work ? 3 : 0,
      };
    case "ecs:DescribeInstanceRamRole":
      return { InstanceRamRoleSets: { InstanceRamRoleSet: work ? [{ InstanceId: WEB, RamRoleName: "ops-admin" }] : [] } };
    case "ecs:DescribeNetworkInterfaces":
      return {
        NetworkInterfaceSets: {
          NetworkInterfaceSet: work
            ? [
                {
                  NetworkInterfaceId: "eni-mockweb",
                  Type: "Primary",
                  InstanceId: WEB,
                  PrivateIpAddress: "10.0.1.10",
                  SecurityGroupIds: { SecurityGroupId: [SG.web] },
                },
                {
                  NetworkInterfaceId: "eni-mockworker",
                  Type: "Primary",
                  InstanceId: WORKER,
                  PrivateIpAddress: "10.0.1.20",
                  SecurityGroupIds: { SecurityGroupId: [SG.db] },
                },
              ]
            : [],
        },
      };
    case "ecs:DescribeUserData":
      return {
        InstanceId: q.get("InstanceId"),
        UserData: q.get("InstanceId") === WEB ? b64(`#!/bin/sh\nexport ALIBABA_CLOUD_ACCESS_KEY_ID=${MOCK_ALIBABA_USER_DATA_KEY}\nsystemctl start app\n`) : "",
      };
    case "ecs:DescribeLaunchTemplates":
      return page(
        work ? [{ LaunchTemplateId: "lt-mock0001", LaunchTemplateName: "web-template", DefaultVersionNumber: 1 }] : [],
        "LaunchTemplateSets",
        "LaunchTemplateSet",
      );
    case "ecs:DescribeLaunchTemplateVersions":
      return {
        LaunchTemplateVersionSets: {
          LaunchTemplateVersionSet: [
            {
              LaunchTemplateId: q.get("LaunchTemplateId"),
              DefaultVersion: true,
              LaunchTemplateData: {
                HttpEndpoint: "enabled",
                HttpTokens: "optional",
                UserData: b64(`#!/bin/sh\ngit clone https://deploy:${MOCK_ALIBABA_TEMPLATE_PASSWORD}@git.mock-alibaba.example/app.git\n`),
              },
            },
          ],
        },
      };
    case "ecs:DescribeDisks":
      return page(
        work
          ? [
              { DiskId: "d-mockweb", Encrypted: false, Status: "In_use", InstanceId: WEB },
              { DiskId: "d-mockworker", Encrypted: true, Status: "In_use", InstanceId: WORKER },
            ]
          : [],
        "Disks",
        "Disk",
      );
    case "ecs:DescribeDiskEncryptionByDefaultStatus":
      return { Encrypted: false };
    case "ecs:DescribeImages":
      return page(work ? [{ ImageId: "m-mock0001", ImageName: "web-golden", ImageOwnerAlias: "self", IsPublic: false }] : [], "Images", "Image");
    case "ecs:DescribeImageSharePermission":
      return { ImageId: q.get("ImageId"), ShareGroups: { ShareGroup: [] }, Accounts: { Account: [{ AliyunId: MOCK_ALIBABA_OUTSIDER }] } };

    case "vpc:DescribeEipAddresses":
      return page(
        work
          ? [
              { IpAddress: MOCK_ALIBABA_IP, AllocationId: "eip-web", InstanceId: WEB, InstanceType: "EcsInstance", Status: "InUse" },
              ...(mockAlibaba.released ? [] : [{ IpAddress: MOCK_ALIBABA_RELEASED_IP, AllocationId: "eip-spare", Status: "Available" }]),
            ]
          : [],
        "EipAddresses",
        "EipAddress",
      );
    case "vpc:DescribeVpcs":
      return page(work ? [{ VpcId: VPC, IsDefault: false }] : [], "Vpcs", "Vpc");
    case "vpc:DescribeFlowLogs":
      return page([], "FlowLogs", "FlowLog");

    case "slb:DescribeLoadBalancers":
      return page(
        work ? [{ LoadBalancerId: "lb-mockclb0001", LoadBalancerName: "legacy-clb", Address: "203.0.113.30", AddressType: "internet", VpcId: VPC }] : [],
        "LoadBalancers",
        "LoadBalancer",
      );
    case "slb:DescribeLoadBalancerAttribute":
      return {
        LoadBalancerId: q.get("LoadBalancerId"),
        ListenerPortsAndProtocol: {
          ListenerPortAndProtocol: [
            { ListenerPort: 80, ListenerProtocol: "http", ListenerForward: "off" },
            { ListenerPort: 443, ListenerProtocol: "https" },
            { ListenerPort: 2222, ListenerProtocol: "tcp" },
          ],
        },
        BackendServers: { BackendServer: [{ ServerId: WEB, Weight: 100 }] },
      };
    case "slb:DescribeLoadBalancerListeners":
      // The web listeners have a whitelist; the SSH one passes anyone through to port 22.
      return {
        Listeners: work
          ? [
              { LoadBalancerId: "lb-mockclb0001", ListenerPort: 80, ListenerProtocol: "http", BackendServerPort: 80, AclStatus: "on", AclType: "black" },
              { LoadBalancerId: "lb-mockclb0001", ListenerPort: 443, ListenerProtocol: "https", AclStatus: "off" },
              { LoadBalancerId: "lb-mockclb0001", ListenerPort: 2222, ListenerProtocol: "tcp", BackendServerPort: 22, AclStatus: "off" },
            ]
          : [],
        TotalCount: work ? 3 : 0,
      };
    case "slb:DescribeLoadBalancerHTTPListenerAttribute":
      return { ListenerPort: 80, ListenerForward: "off", BackendServerPort: 80 };
    case "slb:DescribeLoadBalancerHTTPSListenerAttribute":
      return { ListenerPort: 443, TLSCipherPolicy: "tls_cipher_policy_1_0", VServerGroupId: "rsp-mock0001", Rules: { Rule: [] } };
    case "slb:DescribeVServerGroupAttribute":
      return { VServerGroupName: "legacy-web", BackendServers: { BackendServer: [{ ServerId: WEB, Port: 443, Type: "ecs" }] } };

    case "alb:ListLoadBalancers":
      return {
        LoadBalancers: work
          ? [
              {
                LoadBalancerId: "alb-mock0000000001",
                LoadBalancerName: "web-alb",
                DNSName: MOCK_ALIBABA_ALB,
                AddressType: "Internet",
                VpcId: VPC,
                SecurityGroupIds: [SG.web],
              },
            ]
          : [],
      };
    case "alb:ListListeners":
      return {
        Listeners: work
          ? [
              {
                ListenerId: "lsn-mock443",
                LoadBalancerId: "alb-mock0000000001",
                ListenerProtocol: "HTTPS",
                ListenerPort: 443,
                SecurityPolicyId: "tls_cipher_policy_1_2",
                DefaultActions: [{ Type: "ForwardGroup", ForwardGroupConfig: { ServerGroupTuples: [{ ServerGroupId: "sgp-mockweb" }] } }],
              },
            ]
          : [],
      };
    case "alb:ListRules":
      return {
        Rules: work
          ? [
              {
                RuleId: "rule-mock1",
                ListenerId: "lsn-mock443",
                Priority: 10,
                RuleConditions: [
                  { Type: "Host", HostConfig: { Values: [`api.${MOCK_ALIBABA_DOMAIN}`] } },
                  { Type: "Header", HeaderConfig: { Key: "X-Mock-Verify", Values: ["mock-secret-header-value"] } },
                ],
                RuleActions: [{ Type: "ForwardGroup", Order: 1, ForwardGroupConfig: { ServerGroupTuples: [{ ServerGroupId: "sgp-mockweb" }] } }],
              },
            ]
          : [],
      };
    case "alb:ListServerGroups":
      return { ServerGroups: [{ ServerGroupId: "sgp-mockweb", ServerGroupName: "web", ServerGroupType: "Instance" }] };
    case "alb:ListServerGroupServers":
      return { Servers: [{ ServerId: WEB, ServerIp: "10.0.1.10", ServerType: "Ecs", Port: 443 }] };
    case "nlb:ListLoadBalancers":
      return {
        LoadBalancers: work
          ? [
              {
                LoadBalancerId: "nlb-mock0001",
                LoadBalancerName: "internal-nlb",
                DNSName: "nlb-mock0001.cn-hangzhou.nlb.aliyuncs.com",
                AddressType: "Intranet",
                VpcId: VPC,
              },
            ]
          : [],
      };
    case "nlb:ListListeners":
      return {
        Listeners: work
          ? [{ ListenerId: "lsn-nlb", LoadBalancerId: "nlb-mock0001", ListenerProtocol: "TCP", ListenerPort: 6379, ServerGroupId: "sgp-nlb" }]
          : [],
      };

    case "rds:DescribeDBInstances":
      return {
        Items: { DBInstance: work ? [{ DBInstanceId: "rm-mockorders", DBInstanceDescription: "orders", Engine: "MySQL", DBInstanceNetType: "Internet" }] : [] },
        TotalRecordCount: work ? 1 : 0,
      };
    case "rds:DescribeDBInstanceIPArrayList":
      return { Items: { DBInstanceIPArray: [{ DBInstanceIPArrayName: "default", SecurityIPList: "10.0.0.0/8,0.0.0.0/0", SecurityIPType: "IPv4" }] } };
    case "rds:DescribeDBInstanceNetInfo":
      return { DBInstanceNetInfos: { DBInstanceNetInfo: [{ ConnectionString: "rm-mockorders.mysql.rds.aliyuncs.com", IPType: "Public" }] } };
    case "rds:DescribeDBInstanceSSL":
      return { SSLEnabled: "No", RequireUpdate: "No", ServerKey: "-----BEGIN PRIVATE KEY-----mock-server-key" };
    case "rds:DescribeDBInstanceTDE":
      return { TDEStatus: "Disabled" };

    // Tair: a session cache that lets the VPC in without a password ("Close" on Tair), whitelisted for everyone.
    case "kvstore:DescribeInstances":
      return page(
        work && q.get("InstanceType") === "Redis"
          ? [{ InstanceId: "r-mocksessions", InstanceName: "sessions", InstanceType: "Redis", EngineVersion: "7.0", NetworkType: "VPC", VpcId: VPC }]
          : [],
        "Instances",
        "KVStoreInstance",
      );
    case "kvstore:DescribeInstanceAttribute":
      return { Instances: { DBInstanceAttribute: [{ InstanceId: q.get("InstanceId"), VpcAuthMode: "Close", NetworkType: "VPC" }] } };
    case "kvstore:DescribeSecurityIps":
      return {
        SecurityIpGroups: {
          SecurityIpGroup: [
            { SecurityIpGroupName: "default", SecurityIpList: "0.0.0.0/0" },
            { SecurityIpGroupName: "ali_dms_group", SecurityIpGroupAttribute: "hidden", SecurityIpList: "100.104.0.0/16" },
          ],
        },
      };
    case "kvstore:DescribeDBInstanceNetInfo":
      return { NetInfoItems: { InstanceNetInfo: [{ IPType: "Private", DBInstanceNetType: "2", ConnectionString: "r-mocksessions.redis.rds.aliyuncs.com" }] } };
    case "kvstore:DescribeInstanceSSL":
      return { InstanceId: q.get("InstanceId"), SSLEnabled: "Disable" };
    // MongoDB: VpcAuthMode "Close" is the opposite of Tair's: passwords are required.
    case "dds:DescribeDBInstances":
      return {
        DBInstances: {
          DBInstance:
            work && q.get("DBInstanceType") === "replicate"
              ? [{ DBInstanceId: "dds-mockprofiles", DBInstanceDescription: "profiles", Engine: "MongoDB", EngineVersion: "6.0", VpcAuthMode: "Close" }]
              : [],
        },
        TotalCount: work && q.get("DBInstanceType") === "replicate" ? 1 : 0,
      };
    case "dds:DescribeSecurityIps":
      return { SecurityIps: "10.0.0.0/8", SecurityIpGroups: { SecurityIpGroup: [{ SecurityIpGroupName: "default", SecurityIpList: "10.0.0.0/8" }] } };
    case "dds:DescribeShardingNetworkAddress":
      return { NetworkAddresses: { NetworkAddress: [{ NetworkType: "VPC", NetworkAddress: "dds-mockprofiles.mongodb.rds.aliyuncs.com", Port: "3717" }] } };
    case "dds:DescribeDBInstanceSSL":
      return { SSLStatus: "Open" };

    case "kms:ListKeys":
      return page(work ? [{ KeyId: "key-mockdata" }, { KeyId: "key-mockold" }] : [], "Keys", "Key");
    case "kms:DescribeKey":
      return {
        KeyMetadata:
          q.get("KeyId") === "key-mockold"
            ? {
                KeyId: "key-mockold",
                KeyState: "PendingDeletion",
                Creator: MOCK_ALIBABA_ACCOUNT,
                KeyUsage: "ENCRYPT/DECRYPT",
                KeySpec: "Aliyun_AES_256",
                DeleteDate: ago(-7),
              }
            : {
                KeyId: "key-mockdata",
                KeyState: "Enabled",
                Creator: MOCK_ALIBABA_ACCOUNT,
                Description: "app data",
                KeyUsage: "ENCRYPT/DECRYPT",
                KeySpec: "Aliyun_AES_256",
                Origin: "Aliyun_KMS",
                AutomaticRotation: "Disabled",
              },
      };
    case "kms:ListSecrets":
      return page(work ? [{ SecretName: "legacy-db-password", SecretType: "Generic", CreateTime: ago(500) }] : [], "SecretList", "Secret");
    case "kms:DescribeSecret":
      return { SecretName: q.get("SecretName"), CreateTime: ago(500), AutomaticRotation: "Disabled", SecretType: "Generic" };

    // One Enterprise Edition registry: the storefront's image, which a container group with a public address runs.
    case "cr:ListInstance":
      return {
        TotalCount: work ? 1 : 0,
        Instances: work ? [{ InstanceId: "cri-mock0000000001", InstanceName: "mock-registry", InstanceStatus: "RUNNING", RegionId: WORK }] : [],
      };
    case "cr:ListInstanceEndpoint":
      return {
        Endpoints: [
          {
            EndpointType: "internet",
            Enable: true,
            Status: "RUNNING",
            Domains: [{ Domain: `mock-registry-registry.${WORK}.cr.aliyuncs.com`, Type: "SYSTEM" }],
          },
          { EndpointType: "vpc", Enable: true, Status: "RUNNING", Domains: [{ Domain: `mock-registry-registry-vpc.${WORK}.cr.aliyuncs.com`, Type: "SYSTEM" }] },
        ],
      };
    case "cr:ListRepository":
      return {
        TotalCount: "1",
        Repositories: [{ RepoId: "crr-mock0000000001", RepoName: "storefront", RepoNamespaceName: "shop", RepoType: "PRIVATE", RepoStatus: "NORMAL" }],
      };
    case "cr:ListRepoTag":
      return {
        TotalCount: "2",
        Images: [
          { Tag: "3.2.0", Digest: MOCK_DIGEST.acrShop.replace("sha256:", ""), ImageUpdate: String(Date.now() - 200 * DAY), Status: "NORMAL" },
          { Tag: "stable", Digest: MOCK_DIGEST.acrShop.replace("sha256:", ""), ImageUpdate: String(Date.now() - 200 * DAY), Status: "NORMAL" },
        ],
      };
    // A registry login, as Container Registry hands it out: a temporary user and password. It is not the AccessKey.
    case "cr:GetAuthorizationToken":
      return { TempUsername: "cr_temp_user", AuthorizationToken: MOCK_ALIBABA_REGISTRY_PASSWORD, ExpireTime: Date.now() + 3600_000 };
    // Two pods of the storefront with public addresses in the group that is open to anyone, and a job from Docker Hub.
    case "eci:DescribeContainerGroups": {
      const pod = (id: string, name: string, image: string, ip: string | null, sg: string) => ({
        ContainerGroupId: id,
        ContainerGroupName: name,
        Status: "Running",
        InternetIp: ip ?? "",
        IntranetIp: "10.0.3.10",
        SecurityGroupId: sg,
        RegionId: WORK,
        Containers: [{ Name: "main", Image: image, EnvironmentVars: [{ Key: "PAYMENT_API_KEY", Value: MOCK_ALIBABA_POD_SECRET }] }],
      });
      const shop = `mock-registry-registry-vpc.${WORK}.cr.aliyuncs.com/shop/storefront:3.2.0`;
      return {
        TotalCount: work ? 3 : 0,
        ContainerGroups: work
          ? [
              pod("eci-mock0001", "storefront-7d9f8c6b5d-abcde", shop, "203.0.113.30", SG.all),
              pod("eci-mock0002", "storefront-7d9f8c6b5d-fghij", shop, "203.0.113.31", SG.all),
              pod("eci-mock0003", "report-job", "ghcr.io/mock-org/web:latest", null, SG.db),
            ]
          : [],
      };
    }

    case "actiontrail:DescribeTrails":
      return {
        TrailList: work
          ? [{ Name: "mock-trail", HomeRegion: WORK, TrailRegion: WORK, EventRW: "Write", OssBucketName: "mock-trail-logs", Status: "Enable" }]
          : [],
      };
    case "sas:DescribeCloudCenterInstances":
      return {
        Instances: [{ InstanceId: WEB, ClientStatus: "offline", RegionId: WORK, AssetType: "0" }],
        PageInfo: { CurrentPage: 1, PageSize: 100, TotalCount: 1, Count: 1 },
      };
    case "cdn:DescribeUserDomains":
      return {
        Domains: {
          PageData: [
            {
              DomainName: `cdn.${MOCK_ALIBABA_DOMAIN}`,
              Cname: `cdn.${MOCK_ALIBABA_DOMAIN}.w.kunlunsl.com`,
              DomainStatus: "online",
              SslProtocol: "off",
              Sources: { Source: [{ Type: "oss", Content: `mock-assets.oss-${WORK}.aliyuncs.com`, Port: 80 }] },
            },
          ],
        },
        TotalCount: 1,
      };
    case "alidns:DescribeDomains":
      return { Domains: { Domain: [{ DomainName: MOCK_ALIBABA_DOMAIN }] }, TotalCount: 1 };
    case "alidns:DescribeDomainRecords": {
      const r = (RR: string, Type: string, Value: string, Status = "ENABLE") => ({ RR, Type, Value, Status, DomainName: MOCK_ALIBABA_DOMAIN });
      const records = [
        r("api", "CNAME", MOCK_ALIBABA_ALB),
        r("www", "A", MOCK_ALIBABA_IP),
        r("cdn", "CNAME", `cdn.${MOCK_ALIBABA_DOMAIN}.w.kunlunsl.com`),
        // A bucket that was deleted, and an address the account gives up between the dev server's scans.
        r("files", "CNAME", "mock-deleted-bucket.oss-cn-hangzhou.aliyuncs.com"),
        r("old", "A", MOCK_ALIBABA_RELEASED_IP),
        // Other platforms: a Vercel hostname no project serves, a missing CloudFront distribution and a Pages site nobody publishes.
        r("promo", "CNAME", "cname.vercel-dns.com"),
        r("media", "CNAME", "d9mockmissing.cloudfront.net"),
        r("docs", "CNAME", "mock-somebody.github.io"),
        r("off", "A", "203.0.113.99", "DISABLE"),
        r("@", "MX", "mx.mock-alibaba.example"),
      ];
      return { DomainRecords: { Record: records }, TotalCount: records.length };
    }
  }
  return undefined;
}

/** ROA answers: Container Service and Function Compute. */
function roa(host: string, path: string, region: string): unknown | null | undefined {
  const work = region === WORK;
  if (host.startsWith("cs.") && path === "/api/v1/clusters")
    return {
      clusters: work
        ? [
            {
              cluster_id: "c-mockcluster0001",
              name: "prod-k8s",
              region_id: WORK,
              current_version: "1.32.1-aliyun.1",
              cluster_type: "ManagedKubernetes",
              master_url: JSON.stringify({ api_server_endpoint: "https://203.0.113.40:6443", intranet_api_server_endpoint: "https://10.0.2.10:6443" }),
            },
          ]
        : [],
      page_info: { page_number: 1, page_size: 100, total_count: work ? 1 : 0 },
    };
  if (host.startsWith("fcv3.")) {
    if (path === "/2023-03-30/functions")
      return {
        functions: work
          ? [
              {
                functionName: "thumbnailer",
                runtime: "nodejs20",
                role: `acs:ram::${MOCK_ALIBABA_ACCOUNT}:role/ops-admin`,
                environmentVariables: { GITHUB_TOKEN: MOCK_ALIBABA_FUNCTION_TOKEN, BUCKET: "mock-assets" },
              },
            ]
          : [],
      };
    if (/^\/2023-03-30\/functions\/[^/]+\/triggers$/.test(path))
      return { triggers: [{ triggerName: "http", triggerType: "http", triggerConfig: JSON.stringify({ authType: "anonymous", methods: ["GET", "POST"] }) }] };
  }
  return undefined;
}

/** OSS: ListBuckets and the account's block on a service endpoint, a bucket's subresources on its own host. */
function oss(host: string, q: URLSearchParams): { status: number; body: string; json?: boolean } {
  const x = (tag: string, ...children: string[]) => `<${tag}>${children.join("")}</${tag}>`;
  const err = (status: number, code: string) => ({ status, body: x("Error", x("Code", code), x("Message", code)) });
  const service = /^oss-([a-z0-9-]+)\.aliyuncs\.com$/.exec(host);
  if (service) {
    if (q.has("publicAccessBlock")) return { status: 200, body: x("PublicAccessBlockConfiguration", x("BlockPublicAccess", "false")) };
    return {
      status: 200,
      body: x(
        "ListAllMyBucketsResult",
        x(
          "Buckets",
          ...Object.keys(BUCKETS).map((name) =>
            x("Bucket", x("Name", name), x("Location", `oss-${WORK}`), x("Region", WORK), x("ExtranetEndpoint", `oss-${WORK}.aliyuncs.com`)),
          ),
        ),
      ),
    };
  }
  const name = /^([a-z0-9-]+)\.oss-[a-z0-9-]+\.aliyuncs\.com$/.exec(host)?.[1] ?? "";
  const b = BUCKETS[name];
  if (!b) return err(404, "NoSuchBucket");
  if (q.has("acl")) return { status: 200, body: x("AccessControlPolicy", x("AccessControlList", x("Grant", b.acl))) };
  if (q.has("publicAccessBlock")) return { status: 200, body: x("PublicAccessBlockConfiguration", x("BlockPublicAccess", String(b.block))) };
  if (q.has("policy")) return b.policy ? { status: 200, body: JSON.stringify(b.policy), json: true } : err(404, "NoSuchBucketPolicy");
  return err(400, "InvalidRequest");
}

/** The region a host is for: "ecs.cn-hangzhou.aliyuncs.com", "fcv3.cn-hangzhou…", "bucket.oss-cn-hangzhou…". */
const regionOf = (host: string, q: URLSearchParams) =>
  q.get("RegionId") ?? /^(?:[a-z0-9-]+\.)?(?:oss-)?([a-z]{2}-[a-z]+-\d|[a-z]{2}-[a-z]+)\.(?:[a-z]+\.)?aliyuncs\.com$/.exec(host)?.[1] ?? WORK;

export function installMockAlibaba(o: MockOptions = {}): () => void {
  const real = globalThis.fetch;
  const restoreTrivy = installMockTrivy(o.trivy);
  extraRegions = o.refuseRegions ?? [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (!url.hostname.endsWith(".aliyuncs.com")) return real(input as string, init);
    o.onRequest?.(url, init);
    const headers = new Headers(init?.headers);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const fail = (status: number, code: string, message: string) => json({ Code: code, Message: message, RequestId: "mock" }, status);
    const auth = headers.get("authorization") ?? "";
    const q = url.searchParams;
    const query = Object.fromEntries(q.entries());
    const host = url.hostname;
    const region = regionOf(host, q);

    if (o.unavailable?.some((re) => re.test(host))) return fail(503, "ServiceUnavailable", "The request has failed due to a temporary failure of the server.");
    // OSS: V4-signed, answered in XML.
    if (/(^|\.)oss-[a-z0-9-]+\.aliyuncs\.com$/.test(host)) {
      const bucket = /^([a-z0-9-]+)\.oss-/.exec(host)?.[1] ?? null;
      const stamp = headers.get("x-oss-date") ?? "";
      const now = new Date(
        `${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(9, 11)}:${stamp.slice(11, 13)}:${stamp.slice(13, 15)}Z`,
      );
      const signRegion = /^(?:[a-z0-9-]+\.)?oss-([a-z0-9-]+)\.aliyuncs\.com$/.exec(host)?.[1] ?? WORK;
      const want = signOss4({ accessKeyId: MOCK_ALIBABA_KEY_ID, accessKeySecret: SECRET }, { bucket, query, region: signRegion, now }).authorization;
      if (auth !== want)
        return new Response("<Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match.</Message></Error>", {
          status: 403,
        });
      if (o.deny?.some((re) => re.test(`${host}${url.pathname}${url.search}`)))
        return new Response("<Error><Code>AccessDenied</Code><Message>Denied</Message></Error>", { status: 403 });
      const r = oss(host, q);
      return new Response(r.json ? r.body : `<?xml version="1.0" encoding="UTF-8"?>${r.body}`, {
        status: r.status,
        headers: { "content-type": r.json ? "application/json" : "application/xml" },
      });
    }

    // Everything else is V3-signed: the mock signs the request again and compares.
    const action = headers.get("x-acs-action") ?? "";
    const want = signAcs3(
      { accessKeyId: MOCK_ALIBABA_KEY_ID, accessKeySecret: SECRET },
      {
        host,
        path: url.pathname,
        query,
        action,
        version: headers.get("x-acs-version") ?? "",
        now: new Date(headers.get("x-acs-date") ?? 0),
        nonce: headers.get("x-acs-signature-nonce") ?? "",
      },
    ).authorization;
    if (!auth.includes(`Credential=${MOCK_ALIBABA_KEY_ID},`)) return fail(404, "InvalidAccessKeyId.NotFound", "Specified access key is not found.");
    if (auth !== want) return fail(400, "SignatureDoesNotMatch", "Specified signature does not match our calculation.");
    // tds.<region> is Security Center, fcv3.<region> Function Compute, r-kvstore Tair and mongodb MongoDB.
    const product = productOfHost(host);
    if (o.refuseRegions?.includes(region) || o.deny?.some((re) => re.test(`${host}${url.pathname}${url.search}`) || re.test(`${product}:${action}`)))
      return fail(403, "Forbidden.RAM", "User not authorized to operate on the specified resource.");

    if (url.pathname !== "/") {
      const body = roa(host, url.pathname, region);
      return body === undefined ? json({ code: "NotFound", message: `No mock for ${host}${url.pathname}` }, 404) : json(body);
    }
    // Security Center answers for the international site only; the China site's endpoint knows nothing of this account.
    if (product === "sas" && host.includes("cn-shanghai")) return fail(400, "UserNotExist", "The account has not activated Security Center on this site.");
    const body = rpc(product, action, q, region);
    if (body === undefined) return fail(400, "InvalidAction.NotFound", `No mock for ${product} ${action}`);
    if (body === null) return fail(404, `EntityNotExist.${action}`, "The specified entity does not exist.");
    return json(body);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
    extraRegions = [];
    restoreTrivy();
  };
}
