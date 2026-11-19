// A fetch replacement that serves a small, fictional AWS account, so AWS scans run
// end to end without network access (tests and `npm run dev -- --mock`). It chains
// onto whatever fetch is installed, so it works together with the other mocks.
//
// One access key reaches the account "mock-aws": IAM, S3, two regions (eu-west-1
// runs the workloads, us-east-1 is empty), CloudFront and Route 53, and the
// services read with a POST (CloudTrail, KMS, ECS…), which the mock answers only
// for the read actions Keelson names. As with the other mocks, the data is
// deliberately imperfect so every check family has something to find, and dates
// are relative to now. Answers are XML or JSON in the shapes of the AWS API
// references.

import { installMockTrivy, MOCK_DIGEST, type MockTrivyOptions } from "./trivy.ts";

const DAY = 86_400_000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

export const MOCK_AWS_ACCOUNT = "111122223333";
export const MOCK_AWS_KEY_ID = "AKIAMOCKMOCKMOCK0001";
/** The credential as the Accounts page sends it: key ID and secret, joined. */
export const MOCK_AWS_TOKEN = `${MOCK_AWS_KEY_ID}:mockSecretMockSecretMockSecretMockSecret0`;
/** A value the mock returns in a Lambda environment variable, so the scanner's job of dropping it is tested. */
export const MOCK_AWS_SECRET_VALUE = "mock-lambda-env-value-DO-NOT-STORE";
export const MOCK_AWS_CLOUDFRONT = "d1mockexample.cloudfront.net";
/** Credentials the mock hands out in places the scanner must scan without storing: an ECS task's environment, a CodeBuild source URL, an SNS endpoint. */
export const MOCK_AWS_TASK_TOKEN = "ghp_MOCKmockMOCKmockMOCKmockMOCKmock0001";
export const MOCK_AWS_BUILD_PASSWORD = "mock-build-password-0001";
export const MOCK_AWS_SNS_SECRET = "mock-sns-endpoint-secret";
/** The password of the registry login ECR hands out for Trivy: the only credential the image scanner may be given. */
export const MOCK_AWS_REGISTRY_PASSWORD = "mock-ecr-registry-password";

interface MockOptions {
  onRequest?: (url: URL, init?: RequestInit) => void;
  /** Requests (regex on "host/path?query") that answer 403, to simulate a policy that doesn't allow them. */
  deny?: RegExp[];
  /** Extra enabled regions that refuse every request, like a region closed by a service control policy. */
  refuseRegions?: string[];
  /** Options for the mock Trivy (dev/mock/trivy.ts), installed with the API. */
  trivy?: MockTrivyOptions;
}

const x = (tag: string, ...children: (string | number | boolean)[]) => `<${tag}>${children.join("")}</${tag}>`;
const doc = (enc: object) => encodeURIComponent(JSON.stringify(enc));
const policy = (name: string) => x("PolicyName", name) + x("PolicyArn", `arn:aws:iam::aws:policy/${name}`);

const WORK = "eu-west-1";
const VPC = "vpc-0a1b2c3d4e5f60001";
const SG = { web: "sg-0web0000000000001", admin: "sg-0admin00000000001", db: "sg-0db00000000000001", legacy: "sg-0legacy0000000001" };

const iam: Record<string, (q: URLSearchParams) => string | null> = {
  ListAccountAliases: () => x("ListAccountAliasesResult", x("AccountAliases", x("member", "mock-aws")), x("IsTruncated", false)),
  GetAccountSummary: () =>
    x(
      "GetAccountSummaryResult",
      x(
        "SummaryMap",
        ...Object.entries({ AccountMFAEnabled: 0, AccountAccessKeysPresent: 1, Users: 3 }).map(([k, v]) => x("entry", x("key", k), x("value", v))),
      ),
    ),
  // The account never set a password policy.
  GetAccountPasswordPolicy: () => null,
  ListUsers: () =>
    x(
      "ListUsersResult",
      x(
        "Users",
        x("member", x("UserName", "alex"), x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:user/alex`), x("CreateDate", ago(700)), x("PasswordLastUsed", ago(1))),
        x("member", x("UserName", "ci-deploy"), x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:user/ci-deploy`), x("CreateDate", ago(500))),
        x("member", x("UserName", "sam"), x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:user/sam`), x("CreateDate", ago(600)), x("PasswordLastUsed", ago(200))),
      ),
      x("IsTruncated", false),
    ),
  ListAccessKeys: (q) => {
    const keys: Record<string, [string, number][]> = { alex: [["AKIAMOCKALEX00000A1B2", 400]], "ci-deploy": [["AKIAMOCKCI0000000C3D4", 200]], sam: [] };
    return x(
      "ListAccessKeysResult",
      x(
        "AccessKeyMetadata",
        ...(keys[q.get("UserName") ?? ""] ?? []).map(([id, age]) => x("member", x("AccessKeyId", id), x("Status", "Active"), x("CreateDate", ago(age)))),
      ),
    );
  },
  GetAccessKeyLastUsed: (q) =>
    x(
      "GetAccessKeyLastUsedResult",
      x("AccessKeyLastUsed", q.get("AccessKeyId")?.endsWith("A1B2") ? x("LastUsedDate", ago(2)) : x("LastUsedDate", ago(150)), x("ServiceName", "s3")),
    ),
  ListMFADevices: (q) => x("ListMFADevicesResult", x("MFADevices", q.get("UserName") === "sam" ? x("member", x("SerialNumber", "mock-device")) : "")),
  // A certificate from before ACM, expired a month ago.
  ListServerCertificates: () =>
    x(
      "ListServerCertificatesResult",
      x("ServerCertificateMetadataList", x("member", x("ServerCertificateName", "old-shop-cert"), x("Expiration", ago(30)))),
      x("IsTruncated", false),
    ),
  // ci-deploy has no console password.
  GetLoginProfile: (q) => (q.get("UserName") === "ci-deploy" ? null : x("GetLoginProfileResult", x("LoginProfile", x("UserName", q.get("UserName") ?? "")))),
  GetAccountAuthorizationDetails: () =>
    x(
      "GetAccountAuthorizationDetailsResult",
      x("IsTruncated", false),
      x(
        "UserDetailList",
        x("member", x("UserName", "alex"), x("GroupList", x("member", "Admins")), x("AttachedManagedPolicies", ""), x("UserPolicyList", "")),
        x("member", x("UserName", "ci-deploy"), x("GroupList", ""), x("AttachedManagedPolicies", x("member", policy("AmazonS3FullAccess")))),
        x("member", x("UserName", "sam"), x("GroupList", ""), x("AttachedManagedPolicies", x("member", policy("ReadOnlyAccess")))),
      ),
      x("GroupDetailList", x("member", x("GroupName", "Admins"), x("AttachedManagedPolicies", x("member", policy("AdministratorAccess"))))),
      x(
        "RoleDetailList",
        x(
          "member",
          x("RoleName", "partner-access"),
          x("Path", "/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { AWS: "*" }, Action: "sts:AssumeRole" }] })),
          x("AttachedManagedPolicies", x("member", policy("AdministratorAccess"))),
        ),
        x(
          "member",
          x("RoleName", "app-server"),
          x("Path", "/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] })),
          x("AttachedManagedPolicies", ""),
        ),
        x(
          "member",
          x("RoleName", "web-admin-role"),
          x("Path", "/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] })),
          x("AttachedManagedPolicies", x("member", policy("AdministratorAccess"))),
          x("InstanceProfileList", x("member", x("InstanceProfileName", "web-admin"))),
        ),
        // A vendor's account, trusted without an external ID, and not used for months.
        x(
          "member",
          x("RoleName", "vendor-monitoring"),
          x("Path", "/"),
          x(
            "AssumeRolePolicyDocument",
            doc({ Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::999988887777:root" }, Action: "sts:AssumeRole" }] }),
          ),
          x("AttachedManagedPolicies", x("member", policy("ReadOnlyAccess"))),
          x("RoleLastUsed", x("LastUsedDate", ago(200))),
        ),
        // GitHub Actions deploys from any branch of any repository in the mock GitHub organization (dev/mock/github.ts).
        x(
          "member",
          x("RoleName", "github-deploy"),
          x("Path", "/"),
          x(
            "AssumeRolePolicyDocument",
            doc({
              Statement: [
                {
                  Effect: "Allow",
                  Principal: { Federated: `arn:aws:iam::${MOCK_AWS_ACCOUNT}:oidc-provider/token.actions.githubusercontent.com` },
                  Action: "sts:AssumeRoleWithWebIdentity",
                  Condition: {
                    StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
                    StringLike: { "token.actions.githubusercontent.com:sub": "repo:mock-org/*" },
                  },
                },
              ],
            }),
          ),
          x("AttachedManagedPolicies", x("member", policy("PowerUserAccess"))),
          x("RoleLastUsed", x("LastUsedDate", ago(1))),
        ),
        // An older role for GitHub Actions that names no repository at all.
        x(
          "member",
          x("RoleName", "github-legacy"),
          x("Path", "/"),
          x(
            "AssumeRolePolicyDocument",
            doc({
              Statement: [
                {
                  Effect: "Allow",
                  Principal: { Federated: `arn:aws:iam::${MOCK_AWS_ACCOUNT}:oidc-provider/token.actions.githubusercontent.com` },
                  Action: "sts:AssumeRoleWithWebIdentity",
                  Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" } },
                },
              ],
            }),
          ),
          x("AttachedManagedPolicies", x("member", policy("ReadOnlyAccess"))),
          x("RoleLastUsed", x("LastUsedDate", ago(300))),
        ),
        // A CI role that can start an instance with any role, including an administrator's.
        x(
          "member",
          x("RoleName", "ci-runner"),
          x("Path", "/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { Service: "codebuild.amazonaws.com" }, Action: "sts:AssumeRole" }] })),
          x("AttachedManagedPolicies", ""),
          x(
            "RolePolicyList",
            x(
              "member",
              x("PolicyName", "ci"),
              x("PolicyDocument", doc({ Statement: [{ Effect: "Allow", Action: ["iam:PassRole", "ec2:RunInstances"], Resource: "*" }] })),
            ),
          ),
          x("RoleLastUsed", x("LastUsedDate", ago(3))),
        ),
        x(
          "member",
          x("RoleName", "AWSServiceRoleForSupport"),
          x("Path", "/aws-service-role/support.amazonaws.com/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { Service: "support.amazonaws.com" }, Action: "sts:AssumeRole" }] })),
        ),
      ),
      x(
        "Policies",
        x(
          "member",
          x("PolicyName", "legacy-full-access"),
          x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:policy/legacy-full-access`),
          x("AttachmentCount", 2),
          x(
            "PolicyVersionList",
            x("member", x("Document", doc({ Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] })), x("IsDefaultVersion", true)),
          ),
        ),
      ),
    ),
};

const openRule = (protocol: string, from: number | null, to: number | null, cidr = "0.0.0.0/0") =>
  x("item", x("ipProtocol", protocol), from == null ? "" : x("fromPort", from) + x("toPort", to ?? from), x("ipRanges", x("item", x("cidrIp", cidr))));
const prefixRule = (from: number, prefixList: string) =>
  x("item", x("ipProtocol", "tcp"), x("fromPort", from), x("toPort", from), x("prefixListIds", x("item", x("prefixListId", prefixList))));
export const MOCK_AWS_PREFIX_LIST = "pl-0cloudflare000001";
const group = (id: string, name: string, vpc: string, ...rules: string[]) =>
  x("item", x("groupId", id), x("groupName", name), x("vpcId", vpc), x("ipPermissions", ...rules));
/** Addresses in the mock's "EC2 range" (TEST-NET-2), which the mock ip-ranges file publishes. */
export const MOCK_AWS_IP = "198.51.100.50";
/** An Elastic IP the account gives up when `mockAws.released` is set, as when an old server is deleted between two scans. */
export const MOCK_AWS_OLD_IP = "198.51.100.99";
/**
 * `cloudflareOnly`: the web security group admits HTTPS only from a managed prefix list of Cloudflare's ranges instead
 * of from anywhere, as after following XP-006's fix, so Cloudflare's ATS-001 can tell a locked origin from an open one.
 */
export const mockAws = { released: false, cloudflareOnly: false };
const LB_IP = "198.51.100.60";
const DB_IP = "198.51.100.70";
const WEB = "i-0web00000000000001";

const instance = (id: string, name: string, o: { ip?: string; sg: string[]; tokens: string; profile?: string }) =>
  x(
    "item",
    x(
      "instancesSet",
      x(
        "item",
        x("instanceId", id),
        x("instanceState", x("name", "running")),
        x("vpcId", VPC),
        o.ip ? x("ipAddress", o.ip) : "",
        x("groupSet", ...o.sg.map((g) => x("item", x("groupId", g)))),
        o.profile ? x("iamInstanceProfile", x("arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:instance-profile/${o.profile}`)) : "",
        x("metadataOptions", x("httpTokens", o.tokens), x("httpEndpoint", "enabled")),
        x("tagSet", x("item", x("key", "Name"), x("value", name))),
      ),
    ),
  );

const eni = (id: string, groups: string[], o: { ip?: string; privateIp?: string; instance?: string; description?: string }) =>
  x(
    "item",
    x("networkInterfaceId", id),
    x("description", o.description ?? ""),
    x("interfaceType", "interface"),
    x("groupSet", ...groups.map((g) => x("item", x("groupId", g)))),
    o.privateIp ? x("privateIpAddress", o.privateIp) : "",
    o.ip ? x("association", x("publicIp", o.ip)) : "",
    o.instance ? x("attachment", x("instanceId", o.instance)) : "",
  );

/** The web instance's start-up script exports a credential; the mock returns it so the scanner's job of not keeping it is tested. */
export const MOCK_AWS_USER_DATA_KEY = "AKIAMOCKUSERDATA0001";
const USER_DATA = Buffer.from(`#!/bin/bash\nexport AWS_ACCESS_KEY_ID=${MOCK_AWS_USER_DATA_KEY}\nsystemctl start web\n`).toString("base64");

const ec2: Record<string, (region: string) => string> = {
  DescribeVpcs: (r) =>
    x("vpcSet", r === WORK ? x("item", x("vpcId", VPC), x("isDefault", false)) : x("item", x("vpcId", "vpc-0default000000001"), x("isDefault", true))),
  DescribeFlowLogs: () => x("flowLogSet", ""),
  DescribeSecurityGroups: (r) =>
    x(
      "securityGroupInfo",
      ...(r === WORK
        ? [
            group(SG.web, "web", VPC, mockAws.cloudflareOnly ? prefixRule(443, MOCK_AWS_PREFIX_LIST) : openRule("tcp", 443, 443)),
            group(SG.admin, "admin-access", VPC, openRule("tcp", 22, 22)),
            group(SG.db, "database", VPC, openRule("tcp", 5432, 5432)),
            group(SG.legacy, "legacy-open", VPC, openRule("-1", null, null)),
          ]
        : [group("sg-0default000000001", "default", "vpc-0default000000001")]),
    ),
  DescribeInstances: (r) =>
    x(
      "reservationSet",
      ...(r === WORK
        ? [
            // Public, reachable on SSH and HTTPS, IMDSv1 allowed, and running as an administrator.
            instance(WEB, "web-1", { ip: MOCK_AWS_IP, sg: [SG.admin, SG.web], tokens: "optional", profile: "web-admin" }),
            instance("i-0worker0000000001", "worker-1", { sg: [SG.web], tokens: "required" }),
          ]
        : []),
    ),
  // What each group is attached to: the web instance, the load balancer and the database have public addresses.
  DescribeNetworkInterfaces: (r) =>
    x(
      "networkInterfaceSet",
      ...(r === WORK
        ? [
            eni("eni-0web0000000000001", [SG.admin, SG.web], { ip: MOCK_AWS_IP, privateIp: "10.0.1.10", instance: WEB }),
            eni("eni-0worker00000000001", [SG.web], { instance: "i-0worker0000000001" }),
            eni("eni-0alb0000000000001", [SG.web], { ip: LB_IP, description: "ELB app/web-alb/0001" }),
            eni("eni-0rds0000000000001", [SG.db], { ip: DB_IP, description: "RDSNetworkInterface" }),
          ]
        : []),
    ),
  // The second Elastic IP is there until `mockAws.released` is set: then DNS that points at it is left dangling.
  DescribeAddresses: (r) =>
    x(
      "addressesSet",
      r === WORK
        ? x("item", x("publicIp", MOCK_AWS_IP), x("allocationId", "eipalloc-0mock0001")) +
            (mockAws.released ? "" : x("item", x("publicIp", MOCK_AWS_OLD_IP), x("allocationId", "eipalloc-0mock0002")))
        : "",
    ),
  // The customer-managed list the web group uses when `mockAws.cloudflareOnly` is set: two of Cloudflare's ranges.
  GetManagedPrefixListEntries: () =>
    x(
      "entrySet",
      x("item", x("cidr", "173.245.48.0/20"), x("description", "Cloudflare")),
      x("item", x("cidr", "2606:4700::/32"), x("description", "Cloudflare")),
    ),
  GetEbsEncryptionByDefault: () => x("ebsEncryptionByDefault", false),
  DescribeSnapshots: (r) => x("snapshotSet", r === WORK ? x("item", x("snapshotId", "snap-0mock0000000001")) : ""),
  DescribeImages: (r) => x("imagesSet", r === WORK ? x("item", x("imageId", "ami-0mock00000000001"), x("name", "legacy-base")) : ""),
  // The Auto Scaling group's template: IMDSv1 allowed, and the same start-up script as the web instance.
  DescribeLaunchTemplateVersions: (r) =>
    x(
      "launchTemplateVersionSet",
      r === WORK
        ? x(
            "item",
            x("launchTemplateId", "lt-0mock000000000001"),
            x("launchTemplateName", "web-asg"),
            x("defaultVersion", true),
            x("launchTemplateData", x("metadataOptions", x("httpTokens", "optional"), x("httpEndpoint", "enabled")), x("userData", USER_DATA)),
          )
        : "",
    ),
  DescribeVolumes: (r) =>
    x(
      "volumeSet",
      r === WORK
        ? x("item", x("volumeId", "vol-0mock000000000001"), x("encrypted", false), x("status", "in-use"), x("attachmentSet", x("item", x("instanceId", WEB))))
        : "",
    ),
  GetSnapshotBlockPublicAccessState: () => x("state", "unblocked"),
  GetImageBlockPublicAccessState: () => x("imageBlockPublicAccessState", "unblocked"),
  DescribeTransitGateways: (r) =>
    x(
      "transitGatewaySet",
      r === WORK
        ? x(
            "item",
            x("transitGatewayId", "tgw-0mock000000000001"),
            x("ownerId", MOCK_AWS_ACCOUNT),
            x("state", "available"),
            x("options", x("autoAcceptSharedAttachments", "enable")),
          )
        : "",
    ),
};

const ELB_DNS = `web-alb-1234567890.${WORK}.elb.amazonaws.com`;
const CLASSIC_DNS = `internal-legacy-elb-123456789.${WORK}.elb.amazonaws.com`;
export const MOCK_AWS_API_DOMAIN = "d5apigwmockexample.cloudfront.net";
export const MOCK_AWS_ELB = ELB_DNS;
const ELB_ARN = `arn:aws:elasticloadbalancing:${WORK}:${MOCK_AWS_ACCOUNT}:loadbalancer/app/web-alb/0001`;
const TG = (name: string, n: string) => `arn:aws:elasticloadbalancing:${WORK}:${MOCK_AWS_ACCOUNT}:targetgroup/${name}/${n}`;
const TG_WEB = TG("web", "0001");
const TG_ADMIN = TG("admin", "0002");
const listenerArn = (port: number) => `arn:aws:elasticloadbalancing:${WORK}:${MOCK_AWS_ACCOUNT}:listener/app/web-alb/0001/${port}`;
const listener = (port: number, protocol: string, extra = "") =>
  x(
    "member",
    x("ListenerArn", listenerArn(port)),
    x("Port", port),
    x("Protocol", protocol),
    extra,
    x("DefaultActions", x("member", x("Type", "forward"), x("TargetGroupArn", TG_WEB))),
  );
const forward = (arn: string, order = 1) => x("member", x("Type", "forward"), x("Order", order), x("TargetGroupArn", arn));
const condition = (field: string, config: string, ...values: string[]) =>
  x("member", x("Field", field), x(config, x("Values", ...values.map((v) => x("member", v)))));
/**
 * The web load balancer's routing on 443: /admin on api.mock-aws.example signs visitors in first, beta.mock-aws.example
 * is routed though no DNS record points at it, other names need a secret header, and the rest goes to the web group. Both groups hold web-1,
 * whose public address and open 443 let anyone skip the load balancer.
 */
const rules = (listener: string) =>
  x(
    "Rules",
    ...(listener === listenerArn(443)
      ? [
          x(
            "member",
            x("Priority", "10"),
            x("Conditions", condition("host-header", "HostHeaderConfig", "api.mock-aws.example"), condition("path-pattern", "PathPatternConfig", "/admin/*")),
            x("Actions", x("member", x("Type", "authenticate-oidc"), x("Order", 1)), forward(TG_ADMIN, 2)),
          ),
          x(
            "member",
            x("Priority", "20"),
            x("Conditions", condition("host-header", "HostHeaderConfig", "beta.mock-aws.example")),
            x("Actions", forward(TG_WEB)),
          ),
          x(
            "member",
            x("Priority", "30"),
            x(
              "Conditions",
              condition("host-header", "HostHeaderConfig", "*.mock-aws.example"),
              // A header condition's value can be a shared secret: Keelson keeps the header's name only.
              x(
                "member",
                x("Field", "http-header"),
                x("HttpHeaderConfig", x("HttpHeaderName", "X-Mock-Verify"), x("Values", x("member", "mock-secret-value"))),
              ),
            ),
            x("Actions", forward(TG_WEB)),
          ),
        ]
      : []),
    x("member", x("Priority", "default"), x("IsDefault", true), x("Conditions", ""), x("Actions", forward(TG_WEB))),
  );
const targetGroups = () =>
  x(
    "TargetGroups",
    ...[
      [TG_WEB, "web"],
      [TG_ADMIN, "admin"],
    ].map(([arn, name]) =>
      x(
        "member",
        x("TargetGroupArn", arn),
        x("TargetGroupName", name),
        x("Protocol", "HTTPS"),
        x("Port", 443),
        x("TargetType", "instance"),
        x("LoadBalancerArns", x("member", ELB_ARN)),
      ),
    ),
  );
const targetHealth = (group: string) =>
  x(
    "TargetHealthDescriptions",
    ...(group === TG_WEB ? [WEB, "i-0worker0000000001"] : [WEB]).map((id) =>
      x("member", x("Target", x("Id", id), x("Port", 443)), x("TargetHealth", x("State", "healthy"))),
    ),
  );

const BUCKETS: Record<string, { region: string; block: boolean; public: boolean; policy?: object }> = {
  "mock-backups": { region: "us-east-1", block: true, public: false },
  // A former partner's account can still write logs here.
  "mock-logs": {
    region: WORK,
    block: false,
    public: false,
    policy: {
      Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::999988887777:root" }, Action: "s3:PutObject", Resource: "arn:aws:s3:::mock-logs/*" }],
    },
  },
  "mock-public-assets": { region: WORK, block: false, public: true },
};
const blockXml = () =>
  x("PublicAccessBlockConfiguration", ...["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"].map((k) => x(k, true)));

function s3(path: string, q: URLSearchParams): string | null {
  if (path === "/")
    return x("ListAllMyBucketsResult", x("Buckets", ...Object.entries(BUCKETS).map(([n, b]) => x("Bucket", x("Name", n), x("BucketRegion", b.region)))));
  const b = BUCKETS[path.slice(1)];
  if (!b) return NO_BUCKET;
  if (q.has("publicAccessBlock")) return b.block ? blockXml() : null;
  if (q.has("location")) return x("LocationConstraint", b.region === "us-east-1" ? "" : b.region);
  if (q.has("policyStatus")) return b.public ? x("PolicyStatus", x("IsPublic", "TRUE")) : null;
  if (q.has("acl")) return x("AccessControlPolicy", x("AccessControlList", x("Grant", x("Grantee", x("ID", "owner")), x("Permission", "FULL_CONTROL"))));
  return null;
}

/** S3's answer for a bucket nobody owns. */
const NO_BUCKET = "NoSuchBucket";

const cloudfront = () =>
  x(
    "DistributionList",
    x("IsTruncated", false),
    x(
      "Items",
      x(
        "DistributionSummary",
        x("Id", "E1MOCKDIST00001"),
        x("DomainName", MOCK_AWS_CLOUDFRONT),
        x("Enabled", true),
        x("Aliases", x("Quantity", 1), x("Items", x("CNAME", "cdn.mock.example"))),
        x(
          "Origins",
          x(
            "Items",
            x("Origin", x("DomainName", "origin.mock.example"), x("CustomOriginConfig", x("OriginProtocolPolicy", "http-only"))),
            // A bucket that was deleted: anyone could create it again.
            x("Origin", x("DomainName", "mock-old-assets.s3.amazonaws.com"), x("S3OriginConfig", x("OriginAccessIdentity", ""))),
          ),
        ),
        x("DefaultCacheBehavior", x("ViewerProtocolPolicy", "allow-all")),
        x("CacheBehaviors", x("Quantity", 0)),
        x("ViewerCertificate", x("CloudFrontDefaultCertificate", false), x("MinimumProtocolVersion", "TLSv1_2016")),
        x("WebACLId", ""),
      ),
    ),
  );

const ZONE = "Z0MOCKZONE000001";
const record = (name: string, type: string, target: string, alias = false) =>
  x(
    "ResourceRecordSet",
    x("Name", `${name}.`),
    x("Type", type),
    alias ? x("AliasTarget", x("DNSName", `${target}.`)) : x("ResourceRecords", x("ResourceRecord", x("Value", target))),
  );
function route53(path: string): string | null {
  if (path === "/2013-04-01/hostedzone")
    return x(
      "ListHostedZonesResponse",
      x("HostedZones", x("HostedZone", x("Id", `/hostedzone/${ZONE}`), x("Name", "mock-aws.example."), x("Config", x("PrivateZone", false)))),
      x("IsTruncated", false),
    );
  if (path === `/2013-04-01/hostedzone/${ZONE}/rrset`)
    return x(
      "ListResourceRecordSetsResponse",
      x(
        "ResourceRecordSets",
        record("www.mock-aws.example", "A", MOCK_AWS_CLOUDFRONT, true),
        record("api.mock-aws.example", "A", `dualstack.${ELB_DNS}`, true),
        // The distribution and the bucket behind these two are gone.
        record("old-shop.mock-aws.example", "CNAME", "d9gonemockexample.cloudfront.net"),
        record("static.mock-aws.example", "A", `s3-website-${WORK}.amazonaws.com`, true),
        // A classic load balancer, an API Gateway domain and the web instance's address: all still there.
        record("legacy.mock-aws.example", "CNAME", CLASSIC_DNS),
        record("gateway.mock-aws.example", "CNAME", MOCK_AWS_API_DOMAIN),
        record("vm.mock-aws.example", "A", MOCK_AWS_IP),
        // The Elastic IP the account gives up (see mockAws.released), an address that was never the account's,
        // and a load balancer that was deleted.
        record("old-vm.mock-aws.example", "A", MOCK_AWS_OLD_IP),
        record("partner.mock-aws.example", "A", "198.51.100.200"),
        record("gone-lb.mock-aws.example", "CNAME", `gone-lb-987654321.${WORK}.elb.amazonaws.com`),
        // No Vercel project serves this one.
        record("docs.mock-aws.example", "CNAME", "cname.vercel-dns.com"),
      ),
      x("IsTruncated", false),
    );
  return null;
}

function lambda(path: string, region: string): unknown {
  if (region !== WORK) return path.endsWith("/urls") ? { FunctionUrlConfigs: [] } : { Functions: [] };
  if (path === "/2015-03-31/functions/")
    return {
      Functions: [
        {
          FunctionName: "thumbnailer",
          Runtime: "nodejs16.x",
          Role: `arn:aws:iam::${MOCK_AWS_ACCOUNT}:role/web-admin-role`,
          Environment: { Variables: { UPLOAD_API_KEY: MOCK_AWS_SECRET_VALUE } },
        },
        { FunctionName: "billing-export", Runtime: "python3.13" },
      ],
    };
  // The thumbnailer can be invoked by anyone; the other function has no resource policy.
  const withPolicy = /^\/2015-03-31\/functions\/([^/]+)\/policy$/.exec(path)?.[1];
  if (withPolicy)
    return withPolicy === "thumbnailer"
      ? { Policy: JSON.stringify({ Statement: [{ Effect: "Allow", Principal: "*", Action: "lambda:InvokeFunction", Resource: "*" }] }) }
      : null;
  const name = /^\/2021-10-31\/functions\/([^/]+)\/urls$/.exec(path)?.[1];
  return name ? { FunctionUrlConfigs: [{ AuthType: name === "thumbnailer" ? "NONE" : "AWS_IAM" }] } : null;
}

const sec = (daysAgo: number) => Math.floor((Date.now() - daysAgo * DAY) / 1000);
const ECR = `${MOCK_AWS_ACCOUNT}.dkr.ecr.${WORK}.amazonaws.com`;
const ARN = (service: string, resource: string) => `arn:aws:${service}:${WORK}:${MOCK_AWS_ACCOUNT}:${resource}`;
/** A resource policy that lets anyone in. */
const OPEN_POLICY = (action: string) => JSON.stringify({ Statement: [{ Effect: "Allow", Principal: { AWS: "*" }, Action: action, Resource: "*" }] });
const notFound = (type: string) =>
  new Response(JSON.stringify({ __type: type, message: "Not found" }), { status: 400, headers: { "content-type": "application/json" } });

/**
 * The read actions of POST-only APIs. eu-west-1 holds one failing example for each check; every other region answers
 * empty lists. undefined: an action the mock doesn't know, which a real API would refuse too.
 */
function rpc(service: string, action: string, body: Record<string, unknown>, region: string): unknown {
  const work = region === WORK;
  const list = (key: string, items: unknown[]) => ({ [key]: work ? items : [] });
  const key = `${service}:${action}`;
  switch (key) {
    // One trail, in eu-west-1 only, without log file validation: us-east-1 isn't recorded.
    case "cloudtrail:DescribeTrails":
      return list("trailList", [
        {
          Name: "ops",
          TrailARN: ARN("cloudtrail", "trail/ops"),
          HomeRegion: WORK,
          IsMultiRegionTrail: false,
          LogFileValidationEnabled: false,
          S3BucketName: "mock-logs",
        },
      ]);
    case "cloudtrail:GetTrailStatus":
      return { IsLogging: true };
    case "config:DescribeConfigurationRecorderStatus":
      return { ConfigurationRecordersStatus: [] };
    // A key anyone may use, without rotation; one scheduled for deletion; and one AWS manages.
    case "kms:ListKeys":
      return { ...list("Keys", [{ KeyId: "k-open" }, { KeyId: "k-old" }, { KeyId: "k-aws" }]), Truncated: false };
    case "kms:DescribeKey": {
      const id = String(body.KeyId);
      const base = { KeyId: id, KeySpec: "SYMMETRIC_DEFAULT", Origin: "AWS_KMS", KeyUsage: "ENCRYPT_DECRYPT" };
      if (id === "k-aws") return { KeyMetadata: { ...base, KeyManager: "AWS", KeyState: "Enabled" } };
      if (id === "k-old")
        return { KeyMetadata: { ...base, KeyManager: "CUSTOMER", KeyState: "PendingDeletion", DeletionDate: sec(-6), Description: "old exports" } };
      return { KeyMetadata: { ...base, KeyManager: "CUSTOMER", KeyState: "Enabled", Description: "orders data" } };
    }
    case "kms:GetKeyRotationStatus":
      return { KeyRotationEnabled: false };
    case "kms:GetKeyPolicy":
      return {
        Policy:
          body.KeyId === "k-open"
            ? OPEN_POLICY("kms:*")
            : JSON.stringify({ Statement: [{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${MOCK_AWS_ACCOUNT}:root` }, Action: "kms:*", Resource: "*" }] }),
      };
    // An imported certificate on the load balancer, expiring in ten days.
    case "acm:ListCertificates":
      return list("CertificateSummaryList", [
        {
          CertificateArn: ARN("acm", "certificate/c-0mock"),
          DomainName: "legacy.mock-aws.example",
          Type: "IMPORTED",
          Status: "ISSUED",
          InUse: true,
          NotAfter: sec(-10),
        },
      ]);
    // An API key nobody has changed or read for a long time, readable by anyone.
    case "secretsmanager:ListSecrets":
      return list("SecretList", [
        {
          ARN: ARN("secretsmanager", "secret:old-api-key-AbCdEf"),
          Name: "old-api-key",
          CreatedDate: sec(800),
          LastChangedDate: sec(700),
          LastAccessedDate: sec(200),
          RotationEnabled: false,
        },
      ]);
    case "secretsmanager:GetResourcePolicy":
      return { ResourcePolicy: OPEN_POLICY("secretsmanager:GetSecretValue") };
    // "web" is public and runs behind the load balancer; "api" runs a worker inside the network; nothing runs "tools".
    case "ecr:DescribeRepositories":
      return list("repositories", [
        { repositoryName: "web", imageTagMutability: "MUTABLE", imageScanningConfiguration: { scanOnPush: false } },
        { repositoryName: "api", imageTagMutability: "IMMUTABLE", imageScanningConfiguration: { scanOnPush: true } },
        { repositoryName: "tools", imageTagMutability: "IMMUTABLE", imageScanningConfiguration: { scanOnPush: true } },
      ]);
    case "ecr:GetRepositoryPolicy":
      return body.repositoryName === "web" ? { policyText: OPEN_POLICY("ecr:BatchGetImage") } : notFound("RepositoryPolicyNotFoundException");
    case "ecr:GetRegistryScanningConfiguration":
      return { scanningConfiguration: { scanType: "BASIC", rules: [] } };
    case "ecr:DescribeImages": {
      const image = (digest: string, tags: string[], pushed: number, pulled: number | null, index = false) => ({
        imageDigest: digest,
        imageTags: tags,
        imagePushedAt: sec(pushed),
        ...(pulled == null ? {} : { lastRecordedPullTime: sec(pulled) }),
        imageSizeInBytes: 80_000_000,
        imageManifestMediaType: index ? "application/vnd.oci.image.index.v1+json" : "application/vnd.oci.image.manifest.v1+json",
      });
      const images: Record<string, unknown[]> = {
        web: [
          // Pushed as an index, as BuildKit does: the arm64 image and its build attestation are listed beside it, untagged.
          image(MOCK_DIGEST.web, ["1.4.2", "latest"], 20, 0, true),
          image(MOCK_DIGEST.webArm, [], 20, 0),
          image(MOCK_DIGEST.webAttestation, [], 20, 0),
          image(MOCK_DIGEST.webOld, ["1.4.1"], 60, 45),
          // Left behind by a build: untagged and never pulled.
          image(`sha256:${"09".repeat(32)}`, [], 90, null),
        ],
        api: [image(MOCK_DIGEST.api, ["2026.11.1"], 6, 0)],
        tools: [image(MOCK_DIGEST.tools, ["latest"], 420, 300)],
      };
      return { imageDetails: work ? (images[String(body.repositoryName)] ?? []) : [] };
    }
    // An index's manifest: which images it lists and for which platform. Never a layer.
    case "ecr:BatchGetImage":
      return {
        images: (body.imageIds as { imageDigest: string }[])
          .filter((i) => i.imageDigest === MOCK_DIGEST.web)
          .map((i) => ({
            imageId: i,
            imageManifestMediaType: "application/vnd.oci.image.index.v1+json",
            imageManifest: JSON.stringify({
              schemaVersion: 2,
              mediaType: "application/vnd.oci.image.index.v1+json",
              manifests: [
                { mediaType: "application/vnd.oci.image.manifest.v1+json", digest: MOCK_DIGEST.webArm, platform: { architecture: "arm64", os: "linux" } },
                {
                  mediaType: "application/vnd.oci.image.manifest.v1+json",
                  digest: MOCK_DIGEST.webAttestation,
                  platform: { architecture: "unknown", os: "unknown" },
                  annotations: { "vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": MOCK_DIGEST.webArm },
                },
              ],
            }),
          })),
      };
    // A registry login, as ECR hands it out: "AWS:<password>" in base64. It is not the access key.
    case "ecr:GetAuthorizationToken":
      return {
        authorizationData: [
          {
            authorizationToken: Buffer.from(`AWS:${MOCK_AWS_REGISTRY_PASSWORD}`).toString("base64"),
            expiresAt: sec(-0.5),
            proxyEndpoint: `https://${MOCK_AWS_ACCOUNT}.dkr.ecr.${region}.amazonaws.com`,
          },
        ],
      };
    // The web service runs a privileged container on the host's network, with a GitHub token in its environment, behind
    // the internet-facing load balancer. The worker runs inside the network, pinned to a digest.
    case "ecs:ListClusters":
      return list("clusterArns", [ARN("ecs", "cluster/main")]);
    case "ecs:ListServices":
      return { serviceArns: [ARN("ecs", "service/main/web"), ARN("ecs", "service/main/worker")] };
    case "ecs:DescribeServices":
      return {
        services: [
          {
            serviceName: "web",
            taskDefinition: ARN("ecs", "task-definition/web:7"),
            launchType: "EC2",
            runningCount: 2,
            loadBalancers: [{ targetGroupArn: TG_WEB, containerName: "web", containerPort: 8080 }],
          },
          {
            serviceName: "worker",
            taskDefinition: ARN("ecs", "task-definition/worker:3"),
            launchType: "FARGATE",
            runningCount: 1,
            networkConfiguration: { awsvpcConfiguration: { assignPublicIp: "DISABLED", securityGroups: [SG.db], subnets: ["subnet-0mock"] } },
          },
        ],
      };
    case "ecs:DescribeTaskDefinition":
      if (String(body.taskDefinition).includes("worker"))
        return {
          taskDefinition: {
            family: "worker",
            revision: 3,
            networkMode: "awsvpc",
            containerDefinitions: [{ name: "worker", image: `${ECR}/api@${MOCK_DIGEST.api}`, environment: [{ name: "QUEUE", value: "orders" }] }],
          },
        };
      return {
        taskDefinition: {
          family: "web",
          revision: 7,
          networkMode: "host",
          containerDefinitions: [
            {
              name: "web",
              image: `${ECR}/web:1.4.2`,
              privileged: true,
              environment: [
                { name: "GITHUB_TOKEN", value: MOCK_AWS_TASK_TOKEN },
                { name: "PORT", value: "8080" },
              ],
            },
            // A sidecar pulled from Docker Hub.
            { name: "logs", image: "mock/log-shipper:2.1" },
          ],
        },
      };
    case "dynamodb:ListTables":
      return list("TableNames", ["orders"]);
    case "dynamodb:DescribeContinuousBackups":
      return { ContinuousBackupsDescription: { PointInTimeRecoveryDescription: { PointInTimeRecoveryStatus: "DISABLED" } } };
    // Customers sign in with a password alone; guests get the administrator role.
    case "cognito-idp:ListUserPools":
      return list("UserPools", [{ Id: `${WORK}_mockpool`, Name: "customers" }]);
    case "cognito-idp:DescribeUserPool":
      return { UserPool: { Id: body.UserPoolId, MfaConfiguration: "OFF" } };
    case "cognito-identity:ListIdentityPools":
      return list("IdentityPools", [{ IdentityPoolId: `${WORK}:mock-pool`, IdentityPoolName: "app" }]);
    case "cognito-identity:DescribeIdentityPool":
      return { IdentityPoolId: body.IdentityPoolId, AllowUnauthenticatedIdentities: true };
    case "cognito-identity:GetIdentityPoolRoles":
      return { Roles: { unauthenticated: `arn:aws:iam::${MOCK_AWS_ACCOUNT}:role/partner-access` } };
    // A web ACL with no rules and no logging, on another load balancer than web-alb.
    case "wafv2:ListWebACLs":
      return body.Scope === "REGIONAL"
        ? list("WebACLs", [{ Name: "empty-acl", Id: "acl-1", ARN: ARN("wafv2", "regional/webacl/empty-acl/acl-1") }])
        : { WebACLs: [] };
    case "wafv2:GetWebACL":
      return { WebACL: { Name: "empty-acl", Rules: [] } };
    case "wafv2:GetLoggingConfiguration":
      return notFound("WAFNonexistentItemException");
    case "wafv2:ListResourcesForWebACL":
      return { ResourceArns: [ARN("elasticloadbalancing", "loadbalancer/app/admin-alb/0002")] };
    case "ssm:ListDocuments":
      return list("DocumentIdentifiers", [{ Name: "bootstrap-hosts", Owner: MOCK_AWS_ACCOUNT }]);
    case "ssm:DescribeDocumentPermission":
      return { AccountIds: ["all"] };
    // A public build whose source URL carries a password.
    case "codebuild:ListProjects":
      return list("projects", ["site-build"]);
    case "codebuild:BatchGetProjects":
      return {
        projects: [
          {
            name: "site-build",
            projectVisibility: "PUBLIC_READ",
            source: { type: "GIT", location: `https://deploy:${MOCK_AWS_BUILD_PASSWORD}@git.mock.example/site.git` },
            environment: { environmentVariables: [{ name: "NODE_ENV", value: "production", type: "PLAINTEXT" }] },
          },
        ],
      };
    case "events:ListEventBuses":
      return { EventBuses: [{ Name: "default", Policy: work ? OPEN_POLICY("events:PutEvents") : undefined }] };
    case "sagemaker:ListNotebookInstances":
      return list("NotebookInstances", [{ NotebookInstanceName: "research" }]);
    case "sagemaker:DescribeNotebookInstance":
      return { NotebookInstanceName: "research", DirectInternetAccess: "Enabled" };
    case "sqs:ListQueues":
      return work ? { QueueUrls: [`https://sqs.${WORK}.amazonaws.com/${MOCK_AWS_ACCOUNT}/jobs`] } : {};
    case "sqs:GetQueueAttributes":
      return { Attributes: { Policy: OPEN_POLICY("sqs:*") } };
  }
  return undefined;
}

/** REST-JSON services read with GET: EKS, OpenSearch, MQ, MSK, EFS. undefined: not one of them; null: not found. */
function restJson(service: string, path: string, region: string): unknown {
  const work = region === WORK;
  if (service === "eks") {
    if (path === "/clusters") return { clusters: work ? ["prod"] : [] };
    if (path === "/clusters/prod")
      return {
        cluster: {
          name: "prod",
          version: "1.29",
          resourcesVpcConfig: { endpointPublicAccess: true, endpointPrivateAccess: false, publicAccessCidrs: ["0.0.0.0/0"] },
          logging: {
            clusterLogging: [
              { types: ["api"], enabled: true },
              { types: ["audit", "authenticator"], enabled: false },
            ],
          },
        },
      };
    if (path === "/cluster-versions") return { clusterVersions: [{ clusterVersion: "1.29", versionStatus: "EXTENDED_SUPPORT" }] };
    return null;
  }
  if (service === "es") {
    if (path === "/2021-01-01/domain") return { DomainNames: work ? [{ DomainName: "logs" }] : [] };
    if (path === "/2021-01-01/opensearch/domain/logs")
      return {
        DomainStatus: {
          DomainName: "logs",
          AccessPolicies: OPEN_POLICY("es:*"),
          EncryptionAtRestOptions: { Enabled: false },
          NodeToNodeEncryptionOptions: { Enabled: false },
          DomainEndpointOptions: { EnforceHTTPS: false, TLSSecurityPolicy: "Policy-Min-TLS-1-0-2019-07" },
          AdvancedSecurityOptions: { Enabled: false },
        },
      };
    return null;
  }
  if (service === "mq") {
    if (path === "/v1/brokers") return { brokerSummaries: work ? [{ brokerId: "b-mock", brokerName: "events", engineType: "RABBITMQ" }] : [] };
    if (path === "/v1/brokers/b-mock") return { brokerName: "events", engineType: "RABBITMQ", publiclyAccessible: true };
    return null;
  }
  if (service === "kafka" && path === "/api/v2/clusters")
    return {
      clusterInfoList: work
        ? [
            {
              clusterName: "stream",
              clusterType: "PROVISIONED",
              provisioned: {
                brokerNodeGroupInfo: { connectivityInfo: { publicAccess: { type: "SERVICE_PROVIDED_EIPS" } } },
                clientAuthentication: { unauthenticated: { enabled: true } },
                encryptionInfo: { encryptionInTransit: { clientBroker: "TLS_PLAINTEXT" } },
              },
            },
          ]
        : [],
    };
  if (service === "elasticfilesystem" && path === "/2015-02-01/file-systems")
    return { FileSystems: work ? [{ FileSystemId: "fs-0mock0001", Name: "shared", Encrypted: false, LifeCycleState: "available" }] : [] };
  return undefined;
}

/** Query services beyond the core ones: ElastiCache, Redshift, SNS. The result element's content, or null. */
function queryMock(service: string, action: string, region: string): string | null {
  const work = region === WORK;
  switch (`${service}:${action}`) {
    case "elasticache:DescribeReplicationGroups":
      return x(
        "ReplicationGroups",
        work
          ? x(
              "ReplicationGroup",
              x("ReplicationGroupId", "sessions"),
              x("Engine", "redis"),
              x("TransitEncryptionEnabled", false),
              x("AtRestEncryptionEnabled", false),
            )
          : "",
      );
    case "elasticache:DescribeCacheClusters":
      return x("CacheClusters", "");
    case "redshift:DescribeClusters":
      return x("Clusters", work ? x("Cluster", x("ClusterIdentifier", "analytics"), x("PubliclyAccessible", true), x("Encrypted", false)) : "");
    case "sns:ListTopics":
      return x("Topics", work ? x("member", x("TopicArn", ARN("sns", "alerts"))) : "");
    case "sns:GetTopicAttributes":
      return x("Attributes", x("entry", x("key", "Policy"), x("value", OPEN_POLICY("sns:Publish"))));
    // A webhook subscription over plain HTTP, with a secret in its query string.
    case "sns:ListSubscriptions":
      return x(
        "Subscriptions",
        work
          ? x("member", x("Protocol", "http"), x("Endpoint", `http://hooks.mock.example/sns?token=${MOCK_AWS_SNS_SECRET}`), x("TopicArn", ARN("sns", "alerts")))
          : "",
      );
  }
  return null;
}

/** RDS actions beyond listing instances: a public manual snapshot, and a parameter group that doesn't require TLS. */
function rdsMock(action: string, q: URLSearchParams, region: string): string | null {
  const work = region === WORK;
  switch (action) {
    case "DescribeDBSnapshots":
      return x("DBSnapshots", work ? x("DBSnapshot", x("DBSnapshotIdentifier", "orders-before-migration")) : "");
    case "DescribeDBSnapshotAttributes":
      return x(
        "DBSnapshotAttributesResult",
        x("DBSnapshotIdentifier", q.get("DBSnapshotIdentifier") ?? ""),
        x("DBSnapshotAttributes", x("DBSnapshotAttribute", x("AttributeName", "restore"), x("AttributeValues", x("AttributeValue", "all")))),
      );
    case "DescribeDBClusterSnapshots":
      return x("DBClusterSnapshots", "");
    case "DescribeDBClusters":
      return x("DBClusters", "");
    case "DescribeDBParameters":
      return x(
        "Parameters",
        x("Parameter", x("ParameterName", "rds.force_ssl"), x("ParameterValue", 0)),
        x("Parameter", x("ParameterName", "max_connections")),
      );
  }
  return null;
}

export function installMockAws(o: MockOptions = {}): () => void {
  const real = globalThis.fetch;
  const restoreTrivy = installMockTrivy(o.trivy);
  const regions = ["us-east-1", WORK, ...(o.refuseRegions ?? [])];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (!url.hostname.endsWith(".amazonaws.com")) return real(input as string, init);
    o.onRequest?.(url, init);
    const xml = (body: string, status = 200) => new Response(`<?xml version="1.0"?>${body}`, { status, headers: { "content-type": "text/xml" } });
    const fail = (status: number, code: string, message: string) => xml(x("ErrorResponse", x("Error", x("Code", code), x("Message", message))), status);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const missing = () => fail(404, "NoSuchEntity", "Not found");

    // AWS's published address ranges: a public file, read without a credential.
    if (url.hostname === "ip-ranges.amazonaws.com")
      return json({
        prefixes: [
          { ip_prefix: "198.51.100.0/24", region: WORK, service: "AMAZON" },
          { ip_prefix: "198.51.100.0/24", region: WORK, service: "EC2" },
        ],
      });
    const auth = String(new Headers(init?.headers).get("authorization") ?? "");
    const method = init?.method || "GET";
    if (!auth.includes(`Credential=${MOCK_AWS_KEY_ID}/`)) return fail(403, "InvalidClientTokenId", "The security token included in the request is invalid.");
    // api.ecr.<region> and api.sagemaker.<region> put "api." first.
    const [service, second] = url.hostname.replace(/^api\./, "").split(".");
    const region = /^[a-z]{2}-[a-z]+-\d$/.test(second) ? second : "us-east-1";
    const q = url.searchParams;
    const action = q.get("Action") ?? "";
    if (o.deny?.some((re) => re.test(`${url.hostname}${url.pathname}${url.search}`)) || o.refuseRegions?.includes(region))
      return fail(403, "UnauthorizedOperation", "You are not authorized to perform this operation.");

    if (service === "sts")
      return xml(
        x("GetCallerIdentityResponse", x("GetCallerIdentityResult", x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:user/keelson`), x("Account", MOCK_AWS_ACCOUNT))),
      );
    if (service === "iam") {
      const body = iam[action]?.(q);
      return body ? xml(x(`${action}Response`, body)) : missing();
    }
    if (service === "ec2") {
      if (action === "DescribeRegions") return xml(x("DescribeRegionsResponse", x("regionInfo", ...regions.map((r) => x("item", x("regionName", r))))));
      if (action === "DescribeInstanceAttribute")
        return xml(
          x(
            "DescribeInstanceAttributeResponse",
            x("instanceId", q.get("InstanceId") ?? ""),
            x("userData", q.get("InstanceId") === WEB ? x("value", USER_DATA) : ""),
          ),
        );
      const body = ec2[action]?.(region);
      return body ? xml(x(`${action}Response`, body)) : missing();
    }
    // Read actions of POST-only APIs: the action is in X-Amz-Target and its parameters in the body.
    const target = String(new Headers(init?.headers).get("x-amz-target") ?? "");
    if (method === "POST") {
      const answer = rpc(service, target.split(".").pop() ?? "", JSON.parse(String(init?.body ?? "{}")), region);
      if (answer === undefined) return json({ __type: "UnknownOperationException", message: `No mock for ${service} ${target}` }, 400);
      if (answer instanceof Response) return answer;
      return json(answer);
    }
    const rest = restJson(service, url.pathname, region);
    if (rest !== undefined) return rest === null ? json({ message: "Not found" }, 404) : json(rest);
    if (service === "elasticache" || service === "redshift" || service === "sns") {
      const body = queryMock(service, action, region);
      return body ? xml(x(`${action}Response`, x(`${action}Result`, body))) : missing();
    }
    if (service === "rds" && action !== "DescribeDBInstances") {
      const body = rdsMock(action, q, region);
      return body ? xml(x(`${action}Response`, x(`${action}Result`, body))) : missing();
    }
    if (service === "rds")
      return xml(
        x(
          "DescribeDBInstancesResponse",
          x(
            "DescribeDBInstancesResult",
            x(
              "DBInstances",
              region === WORK
                ? x(
                    "DBInstance",
                    x("DBInstanceIdentifier", "orders-db"),
                    x("Engine", "postgres"),
                    x("PubliclyAccessible", true),
                    x("StorageEncrypted", false),
                    x("BackupRetentionPeriod", 0),
                    x("DBSubnetGroup", x("VpcId", VPC)),
                    x("VpcSecurityGroups", x("VpcSecurityGroupMembership", x("VpcSecurityGroupId", SG.db))),
                    x("Endpoint", x("Port", 5432)),
                    x("DBParameterGroups", x("DBParameterGroup", x("DBParameterGroupName", "orders-pg"))),
                  )
                : "",
            ),
          ),
        ),
      );
    if (service === "elasticloadbalancing") {
      // The older API version lists classic load balancers: one, which a Route 53 record still uses.
      if (q.get("Version") === "2012-06-01") {
        if (action === "DescribeLoadBalancerAttributes")
          return xml(x("DescribeLoadBalancerAttributesResponse", x("LoadBalancerAttributes", x("AccessLog", x("Enabled", true)))));
        const classic = x(
          "member",
          x("LoadBalancerName", "legacy-elb"),
          x("DNSName", CLASSIC_DNS),
          x("Scheme", "internal"),
          x("VPCId", VPC),
          x("SecurityGroups", x("member", SG.web)),
          x("ListenerDescriptions", x("member", x("Listener", x("Protocol", "TCP"), x("LoadBalancerPort", 8443), x("InstancePort", 8443)))),
          x("Instances", x("member", x("InstanceId", "i-0worker0000000001"))),
        );
        return xml(x("DescribeLoadBalancersResponse", x("LoadBalancerDescriptions", region === WORK ? classic : "")));
      }
      if (action === "DescribeLoadBalancerAttributes")
        return xml(
          x(
            "DescribeLoadBalancerAttributesResponse",
            x(
              "Attributes",
              x("member", x("Key", "access_logs.s3.enabled"), x("Value", false)),
              x("member", x("Key", "routing.http.desync_mitigation_mode"), x("Value", "monitor")),
            ),
          ),
        );
      if (action === "DescribeListeners")
        return xml(x("DescribeListenersResponse", x("Listeners", listener(80, "HTTP"), listener(443, "HTTPS", x("SslPolicy", "ELBSecurityPolicy-2016-08")))));
      if (action === "DescribeRules") return xml(x("DescribeRulesResponse", rules(q.get("ListenerArn") ?? "")));
      if (action === "DescribeTargetGroups") return xml(x("DescribeTargetGroupsResponse", region === WORK ? targetGroups() : x("TargetGroups", "")));
      if (action === "DescribeTargetHealth") return xml(x("DescribeTargetHealthResponse", targetHealth(q.get("TargetGroupArn") ?? "")));
      const lb = x(
        "member",
        x("LoadBalancerArn", ELB_ARN),
        x("LoadBalancerName", "web-alb"),
        x("DNSName", ELB_DNS),
        x("Scheme", "internet-facing"),
        x("Type", "application"),
        x("VpcId", VPC),
        x("SecurityGroups", x("member", SG.web)),
      );
      return xml(x("DescribeLoadBalancersResponse", x("LoadBalancers", region === WORK ? lb : "")));
    }
    if (service === "guardduty") return json({ detectorIds: [] });
    // An edge-optimised custom domain: its CloudFront distribution belongs to AWS, not to the account.
    if (service === "apigateway")
      return json({ item: region === WORK ? [{ domainName: "gateway.mock-aws.example", distributionDomainName: MOCK_AWS_API_DOMAIN }] : [] });
    if (service === "lambda") {
      const body = lambda(url.pathname, region);
      return body ? json(body) : json({ Message: "Not found" }, 404);
    }
    if (service === "cloudfront") return xml(cloudfront());
    if (service === "route53") {
      const body = route53(url.pathname);
      return body ? xml(body) : missing();
    }
    // S3's account-level API is addressed as <account>.s3-control.<region>; this account never set its block.
    if (second === "s3-control") return fail(404, "NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found");
    if (service === "s3") {
      if (q.has("policy")) {
        const policy = BUCKETS[url.pathname.slice(1)]?.policy;
        return policy ? json(policy) : fail(404, "NoSuchBucketPolicy", "The bucket policy does not exist");
      }
      const body = s3(url.pathname, q);
      if (body === NO_BUCKET) return fail(404, "NoSuchBucket", "The specified bucket does not exist");
      return body ? xml(body) : fail(404, "NoSuchConfiguration", "Not found");
    }
    return fail(404, "UnknownOperation", `No mock for ${url.hostname}${url.pathname}`);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
    restoreTrivy();
  };
}
