// The RAM actions an Alibaba Cloud scan sends, by the source each one reads, and
// the custom policy Keelson asks for. Alibaba Cloud's system ReadOnlyAccess policy
// also reads data (objects in OSS buckets, secret values in KMS), so Keelson asks
// for a policy that names only these actions. The client refuses to send any
// other (src/providers/alibaba/client.ts), and test/alibaba.test.ts fails when a
// scan sends an action this list doesn't name.

export const ALIBABA_ACTIONS = {
  identity: ["ram:GetAccountAlias"],
  accountSecurity: ["ram:GetAccountSecurityPracticeReport"],
  ramUsers: ["ram:ListUsers", "ram:ListAccessKeys", "ram:GetLoginProfile", "ram:GetUserMFAInfo", "ram:GetAccessKeyLastUsed"],
  passwordPolicy: ["ram:GetPasswordPolicy"],
  securityPreference: ["ram:GetSecurityPreference"],
  ramPolicies: ["ram:ListPolicies", "ram:GetPolicy", "ram:ListEntitiesForPolicy", "ram:ListUsersForGroup"],
  ramRoles: ["ram:ListRoles", "ram:GetRole", "ram:ListOIDCProviders"],
  ossAccount: ["oss:GetPublicAccessBlock"],
  ossBuckets: ["oss:ListBuckets"],
  ossBucketAccess: ["oss:GetBucketAcl", "oss:GetBucketPublicAccessBlock"],
  bucketPolicies: ["oss:GetBucketPolicy"],
  regions: ["ecs:DescribeRegions"],
  securityGroups: ["ecs:DescribeSecurityGroups", "ecs:DescribeSecurityGroupAttribute"],
  instances: ["ecs:DescribeInstances", "ecs:DescribeInstanceRamRole"],
  networkInterfaces: ["ecs:DescribeNetworkInterfaces", "vpc:DescribeEipAddresses"],
  userData: ["ecs:DescribeUserData"],
  launchTemplates: ["ecs:DescribeLaunchTemplates", "ecs:DescribeLaunchTemplateVersions"],
  disks: ["ecs:DescribeDisks", "ecs:DescribeDiskEncryptionByDefaultStatus"],
  images: ["ecs:DescribeImages", "ecs:DescribeImageSharePermission"],
  vpcs: ["vpc:DescribeVpcs", "vpc:DescribeFlowLogs"],
  loadBalancers: [
    "slb:DescribeLoadBalancers",
    "slb:DescribeLoadBalancerAttribute",
    "slb:DescribeLoadBalancerHTTPListenerAttribute",
    "slb:DescribeLoadBalancerHTTPSListenerAttribute",
    "alb:ListLoadBalancers",
    "alb:ListListeners",
    "alb:ListRules",
    "nlb:ListLoadBalancers",
    "nlb:ListListeners",
  ],
  lbAccess: ["slb:DescribeLoadBalancerListeners"],
  lbRouting: ["alb:ListServerGroups", "alb:ListServerGroupServers", "slb:DescribeVServerGroupAttribute"],
  databases: [
    "rds:DescribeDBInstances",
    "rds:DescribeDBInstanceIPArrayList",
    "rds:DescribeDBInstanceNetInfo",
    "rds:DescribeDBInstanceSSL",
    "rds:DescribeDBInstanceTDE",
  ],
  redis: [
    "kvstore:DescribeInstances",
    "kvstore:DescribeInstanceAttribute",
    "kvstore:DescribeSecurityIps",
    "kvstore:DescribeDBInstanceNetInfo",
    "kvstore:DescribeInstanceSSL",
  ],
  mongodb: ["dds:DescribeDBInstances", "dds:DescribeSecurityIps", "dds:DescribeShardingNetworkAddress", "dds:DescribeDBInstanceSSL"],
  functions: ["fc:ListFunctions", "fc:ListTriggers"],
  kms: ["kms:ListKeys", "kms:DescribeKey", "kms:ListSecrets", "kms:DescribeSecret"],
  clusters: ["cs:GetClusters"],
  actiontrail: ["actiontrail:DescribeTrails"],
  securityCenter: ["yundun-sas:DescribeCloudCenterInstances"],
  cdn: ["cdn:DescribeUserDomains"],
  dns: ["alidns:DescribeDomains", "alidns:DescribeDomainRecords"],
} as const satisfies Record<string, readonly string[]>;

/** Every action, once, sorted: what the custom policy allows. */
export const ALIBABA_POLICY_ACTIONS: string[] = [...new Set(Object.values(ALIBABA_ACTIONS).flat())].sort();

/** The custom RAM policy to give Keelson's RAM user, as the console's JSON editor takes it. */
export const alibabaPolicy = (): string =>
  JSON.stringify({ Version: "1", Statement: [{ Effect: "Allow", Action: ALIBABA_POLICY_ACTIONS, Resource: "*" }] }, null, 2);
