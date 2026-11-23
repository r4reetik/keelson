// Every AWS data source a scan reads. Like the other providers' registries, each
// source has a coverage label, what grants it, and an optional probe for the setup
// screen. `permission` names the IAM actions; AWS's managed SecurityAudit policy
// grants all of them and nothing that writes.

import type { AwsClient } from "./client.ts";
import { toolNeed } from "../../shared/tools.ts";

export interface AwsSource {
  label: string;
  /** The IAM actions that read it. */
  permission: string;
  /** A cheap request that proves the access key can read this source (Add accounts). */
  probe?: (c: AwsClient) => Promise<unknown>;
  /** Read in every enabled region. A region that refuses (a service control policy, for example) is left out rather than failing the source. */
  regional?: boolean;
}

/** The region the global services (IAM, STS, CloudFront, Route 53) sign for, and where probes ask regional services. */
export const HOME_REGION = "us-east-1";

const iam =
  (action: string, params: Record<string, string> = {}) =>
  (c: AwsClient) =>
    c.query("iam", HOME_REGION, action, params);
const ec2 =
  (action: string, params: Record<string, string> = {}) =>
  (c: AwsClient) =>
    c.query("ec2", HOME_REGION, action, params);

const DEFS = {
  identity: { label: "Account identity", permission: "sts:GetCallerIdentity", probe: (c) => c.query("sts", HOME_REGION, "GetCallerIdentity") },
  iamSummary: { label: "IAM account summary (root user)", permission: "iam:GetAccountSummary", probe: iam("GetAccountSummary") },
  passwordPolicy: {
    label: "IAM password policy",
    permission: "iam:GetAccountPasswordPolicy",
    probe: (c) => c.optional(() => c.query("iam", HOME_REGION, "GetAccountPasswordPolicy")),
  },
  iamUsers: {
    label: "IAM users, their access keys and MFA devices",
    permission: "iam:ListUsers, iam:ListAccessKeys, iam:GetAccessKeyLastUsed, iam:ListMFADevices, iam:GetLoginProfile",
    probe: iam("ListUsers", { MaxItems: "1" }),
  },
  iamDetails: {
    label: "IAM roles, groups and policies",
    permission: "iam:GetAccountAuthorizationDetails",
    probe: iam("GetAccountAuthorizationDetails", { MaxItems: "1", "Filter.member.1": "LocalManagedPolicy" }),
  },
  s3Account: {
    label: "S3 Block Public Access for the account",
    permission: "s3:GetAccountPublicAccessBlock",
    probe: (c) => c.optional(() => c.s3Control("/v20180820/configuration/publicAccessBlock")),
  },
  s3Buckets: { label: "S3 buckets", permission: "s3:ListAllMyBuckets, s3:GetBucketLocation", probe: (c) => c.s3(HOME_REGION, "/", {}) },
  s3BucketAccess: {
    label: "S3 bucket access settings",
    permission: "s3:GetBucketPublicAccessBlock, s3:GetBucketPolicyStatus, s3:GetBucketAcl",
  },
  regions: { label: "Enabled regions", permission: "ec2:DescribeRegions", probe: ec2("DescribeRegions") },
  securityGroups: {
    label: "Security groups",
    permission: "ec2:DescribeSecurityGroups",
    probe: ec2("DescribeSecurityGroups", { MaxResults: "5" }),
    regional: true,
  },
  prefixLists: {
    label: "Managed prefix lists that security groups admit web traffic from",
    permission: "ec2:GetManagedPrefixListEntries",
    regional: true,
  },
  networkInterfaces: {
    label: "Network interfaces and Elastic IPs",
    permission: "ec2:DescribeNetworkInterfaces, ec2:DescribeAddresses",
    probe: ec2("DescribeAddresses"),
    regional: true,
  },
  instances: { label: "EC2 instances", permission: "ec2:DescribeInstances", probe: ec2("DescribeInstances", { MaxResults: "5" }), regional: true },
  ebs: {
    label: "EBS encryption, public snapshots and public images",
    permission: "ec2:GetEbsEncryptionByDefault, ec2:DescribeSnapshots, ec2:DescribeImages",
    probe: ec2("GetEbsEncryptionByDefault"),
    regional: true,
  },
  vpcs: { label: "VPCs and flow logs", permission: "ec2:DescribeVpcs, ec2:DescribeFlowLogs", probe: ec2("DescribeVpcs"), regional: true },
  databases: {
    label: "RDS databases",
    permission: "rds:DescribeDBInstances",
    probe: (c) => c.query("rds", HOME_REGION, "DescribeDBInstances", { MaxRecords: "20" }),
    regional: true,
  },
  loadBalancers: {
    label: "Load balancers and listeners",
    permission: "elasticloadbalancing:DescribeLoadBalancers, elasticloadbalancing:DescribeListeners, elasticloadbalancing:DescribeLoadBalancerAttributes",
    probe: (c) => c.query("elasticloadbalancing", HOME_REGION, "DescribeLoadBalancers", { PageSize: "1" }),
    regional: true,
  },
  lbRouting: {
    label: "Load balancer rules, target groups and their targets",
    permission: "elasticloadbalancing:DescribeRules, elasticloadbalancing:DescribeTargetGroups, elasticloadbalancing:DescribeTargetHealth",
    probe: (c) => c.query("elasticloadbalancing", HOME_REGION, "DescribeTargetGroups", { PageSize: "1" }),
    regional: true,
  },
  functions: {
    label: "Lambda functions and function URLs",
    permission: "lambda:ListFunctions, lambda:ListFunctionUrlConfigs",
    probe: (c) => c.json("lambda", HOME_REGION, "/2015-03-31/functions/", { MaxItems: "1" }),
    regional: true,
  },
  userData: {
    label: "Instance start-up scripts (scanned for credentials, never stored)",
    permission: "ec2:DescribeInstanceAttribute",
    regional: true,
  },
  apiDomains: {
    label: "API Gateway custom domain names",
    permission: "apigateway:GET",
    probe: (c) => c.json("apigateway", HOME_REGION, "/domainnames", { limit: "1" }),
    regional: true,
  },
  guardduty: {
    label: "GuardDuty detectors",
    permission: "guardduty:ListDetectors, guardduty:GetDetector",
    probe: (c) => c.json("guardduty", HOME_REGION, "/detector", {}),
    regional: true,
  },
  cloudfront: {
    label: "CloudFront distributions",
    permission: "cloudfront:ListDistributions",
    probe: (c) => c.xml("cloudfront", HOME_REGION, "cloudfront.amazonaws.com", "/2020-05-31/distribution", { MaxItems: "1" }),
  },
  route53: {
    label: "Route 53 hosted zones and records",
    permission: "route53:ListHostedZones, route53:ListResourceRecordSets",
    probe: (c) => c.xml("route53", HOME_REGION, "route53.amazonaws.com", "/2013-04-01/hostedzone", { maxitems: "1" }),
  },
  ipRanges: { label: "AWS's published address ranges (ip-ranges.amazonaws.com)", permission: "None: a public file, read without the access key" },
  serverCertificates: { label: "IAM server certificates", permission: "iam:ListServerCertificates", probe: iam("ListServerCertificates") },
  bucketPolicies: { label: "S3 bucket policies (reduced to the accounts they allow, never stored)", permission: "s3:GetBucketPolicy" },
  functionPolicies: { label: "Lambda function policies", permission: "lambda:GetPolicy", regional: true },
  launchTemplates: {
    label: "EC2 launch templates (start-up scripts scanned for credentials, never stored)",
    permission: "ec2:DescribeLaunchTemplateVersions",
    probe: ec2("DescribeLaunchTemplateVersions", { "LaunchTemplateVersion.1": "$Default", MaxResults: "5" }),
    regional: true,
  },
  volumes: { label: "EBS volumes", permission: "ec2:DescribeVolumes", probe: ec2("DescribeVolumes", { MaxResults: "5" }), regional: true },
  sharingBlocks: {
    label: "Blocks on sharing snapshots and images publicly",
    permission: "ec2:GetSnapshotBlockPublicAccessState, ec2:GetImageBlockPublicAccessState",
    probe: ec2("GetSnapshotBlockPublicAccessState"),
    regional: true,
  },
  transitGateways: { label: "Transit gateways", permission: "ec2:DescribeTransitGateways", probe: ec2("DescribeTransitGateways"), regional: true },
  dbSnapshots: {
    label: "RDS manual snapshots and who may restore them",
    permission: "rds:DescribeDBSnapshots, rds:DescribeDBSnapshotAttributes, rds:DescribeDBClusterSnapshots, rds:DescribeDBClusterSnapshotAttributes",
    regional: true,
  },
  dbParameters: {
    label: "RDS parameters that require TLS",
    permission: "rds:DescribeDBParameters, rds:DescribeDBClusters, rds:DescribeDBClusterParameters",
    regional: true,
  },
  cloudtrail: {
    label: "CloudTrail trails",
    permission: "cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus",
    probe: (c) => c.rpc("cloudtrail", HOME_REGION, "DescribeTrails", {}),
    regional: true,
  },
  config: {
    label: "AWS Config recorders",
    permission: "config:DescribeConfigurationRecorderStatus",
    probe: (c) => c.rpc("config", HOME_REGION, "DescribeConfigurationRecorderStatus", {}),
    regional: true,
  },
  kms: {
    label: "KMS keys, their rotation and key policies",
    permission: "kms:ListKeys, kms:DescribeKey, kms:GetKeyRotationStatus, kms:GetKeyPolicy",
    probe: (c) => c.rpc("kms", HOME_REGION, "ListKeys", { Limit: 1 }),
    regional: true,
  },
  acm: {
    label: "ACM certificates",
    permission: "acm:ListCertificates",
    probe: (c) => c.rpc("acm", HOME_REGION, "ListCertificates", { MaxItems: 1 }),
    regional: true,
  },
  secrets: {
    label: "Secrets Manager secrets (names and dates, never values) and their resource policies",
    permission: "secretsmanager:ListSecrets, secretsmanager:GetResourcePolicy",
    probe: (c) => c.rpc("secretsmanager", HOME_REGION, "ListSecrets", { MaxResults: 1 }),
    regional: true,
  },
  ecr: {
    label: "ECR repositories, their policies and image scanning",
    permission: "ecr:DescribeRepositories, ecr:GetRepositoryPolicy, ecr:GetRegistryScanningConfiguration",
    probe: (c) => c.rpc("ecr", HOME_REGION, "DescribeRepositories", { maxResults: 1 }),
    regional: true,
  },
  ecrImages: {
    label: "ECR images: tags, digests, and when each was pushed and last pulled",
    permission: "ecr:DescribeImages",
    regional: true,
  },
  imagePull: {
    label: "Pulling ECR images, for Trivy to scan",
    permission:
      "ecr:GetAuthorizationToken, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer. SecurityAudit doesn't grant them: add them to the key's user in an inline policy (all three only read)",
  },
  registryNetwork: {
    label: "Connecting to container registries from where Keelson runs, to pull images",
    permission:
      "A connection to the account's ECR registry hosts (<account>.dkr.ecr.<region>.amazonaws.com) and the S3 hosts its layers come from. A firewall or proxy that blocks them stops the pull",
  },
  trivy: {
    label: "Packages, vulnerabilities and stored credentials in container images (Aqua Trivy)",
    permission: toolNeed("trivy"),
  },
  kev: {
    label: "CISA's catalog of known exploited vulnerabilities",
    permission: "None: a public file, read from www.cisa.gov without a credential",
  },
  ecs: {
    label: "ECS services and their task definitions (environment variables scanned for credentials, never stored)",
    permission: "ecs:ListClusters, ecs:ListServices, ecs:DescribeServices, ecs:DescribeTaskDefinition",
    probe: (c) => c.rpc("ecs", HOME_REGION, "ListClusters", { maxResults: 1 }),
    regional: true,
  },
  eks: {
    label: "EKS clusters",
    permission: "eks:ListClusters, eks:DescribeCluster, eks:DescribeClusterVersions",
    probe: (c) => c.json("eks", HOME_REGION, "/clusters", { maxResults: "1" }),
    regional: true,
  },
  dynamodb: {
    label: "DynamoDB tables and point-in-time recovery",
    permission: "dynamodb:ListTables, dynamodb:DescribeContinuousBackups",
    probe: (c) => c.rpc("dynamodb", HOME_REGION, "ListTables", { Limit: 1 }),
    regional: true,
  },
  cognito: {
    label: "Cognito user pools and identity pools",
    permission:
      "cognito-idp:ListUserPools, cognito-idp:DescribeUserPool, cognito-identity:ListIdentityPools, cognito-identity:DescribeIdentityPool, cognito-identity:GetIdentityPoolRoles",
    probe: (c) => c.rpc("cognito-idp", HOME_REGION, "ListUserPools", { MaxResults: 1 }),
    regional: true,
  },
  waf: {
    label: "WAF web ACLs, their logging and what they protect",
    permission: "wafv2:ListWebACLs, wafv2:GetWebACL, wafv2:GetLoggingConfiguration, wafv2:ListResourcesForWebACL",
    probe: (c) => c.rpc("wafv2", HOME_REGION, "ListWebACLs", { Scope: "REGIONAL", Limit: 1 }),
    regional: true,
  },
  ssmDocuments: {
    label: "Systems Manager documents and who they're shared with",
    permission: "ssm:ListDocuments, ssm:DescribeDocumentPermission",
    probe: (c) => c.rpc("ssm", HOME_REGION, "ListDocuments", { MaxResults: 1 }),
    regional: true,
  },
  codebuild: {
    label: "CodeBuild projects (environment variables scanned for credentials, never stored)",
    permission: "codebuild:ListProjects, codebuild:BatchGetProjects",
    probe: (c) => c.rpc("codebuild", HOME_REGION, "ListProjects", {}),
    regional: true,
  },
  eventBuses: {
    label: "EventBridge event buses",
    permission: "events:ListEventBuses",
    probe: (c) => c.rpc("events", HOME_REGION, "ListEventBuses", { Limit: 1 }),
    regional: true,
  },
  sagemaker: {
    label: "SageMaker notebook instances",
    permission: "sagemaker:ListNotebookInstances, sagemaker:DescribeNotebookInstance",
    probe: (c) => c.rpc("sagemaker", HOME_REGION, "ListNotebookInstances", { MaxResults: 1 }),
    regional: true,
  },
  opensearch: {
    label: "OpenSearch domains",
    permission: "es:ListDomainNames, es:DescribeDomain",
    probe: (c) => c.json("es", HOME_REGION, "/2021-01-01/domain"),
    regional: true,
  },
  elasticache: {
    label: "ElastiCache clusters",
    permission: "elasticache:DescribeReplicationGroups, elasticache:DescribeCacheClusters",
    probe: (c) => c.query("elasticache", HOME_REGION, "DescribeReplicationGroups", { MaxRecords: "20" }),
    regional: true,
  },
  redshift: {
    label: "Redshift clusters",
    permission: "redshift:DescribeClusters",
    probe: (c) => c.query("redshift", HOME_REGION, "DescribeClusters", { MaxRecords: "20" }),
    regional: true,
  },
  sns: {
    label: "SNS topics, their policies and subscriptions",
    permission: "sns:ListTopics, sns:GetTopicAttributes, sns:ListSubscriptions",
    probe: (c) => c.query("sns", HOME_REGION, "ListTopics"),
    regional: true,
  },
  sqs: {
    label: "SQS queues and their policies",
    permission: "sqs:ListQueues, sqs:GetQueueAttributes",
    probe: (c) => c.rpc("sqs", HOME_REGION, "ListQueues", { MaxResults: 1 }),
    regional: true,
  },
  mq: {
    label: "Amazon MQ brokers",
    permission: "mq:ListBrokers, mq:DescribeBroker",
    probe: (c) => c.json("mq", HOME_REGION, "/v1/brokers", { maxResults: "1" }),
    regional: true,
  },
  msk: {
    label: "MSK (Kafka) clusters",
    permission: "kafka:ListClustersV2",
    probe: (c) => c.json("kafka", HOME_REGION, "/api/v2/clusters", { maxResults: "1" }),
    regional: true,
  },
  efs: {
    label: "EFS file systems",
    permission: "elasticfilesystem:DescribeFileSystems",
    probe: (c) => c.json("elasticfilesystem", HOME_REGION, "/2015-02-01/file-systems", { MaxItems: "1" }),
    regional: true,
  },
} satisfies Record<string, AwsSource>;

export type AwsSourceKey = keyof typeof DEFS;
export const AWS_SOURCES: Record<AwsSourceKey, AwsSource> = DEFS;
export const AWS_SOURCE_KEYS = Object.keys(DEFS) as AwsSourceKey[];
