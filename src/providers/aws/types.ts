// What an AWS scan collects: the fields checks read, typed from the AWS API
// references. Payloads are trimmed when they're read, so the inventory never holds
// a secret access key, a Lambda environment variable or a policy document: only
// what was concluded from them.

import type { AwsSourceKey } from "./sources.ts";
import type { Prefixes } from "../../core/aws-ranges.ts";
import type { ImageHighlights } from "../../core/images.ts";
import type { ImagesSnapshot, WorkloadLink } from "../../shared/images.ts";

/** The name findings use for resources that aren't in a region (IAM, S3 settings, CloudFront, Route 53). */
export const GLOBAL = "Global";

export interface AwsAccessKey {
  /** The last four characters of the key ID, enough to find it in the console. */
  hint: string;
  active: boolean;
  createdAt: number | null;
  lastUsedAt: number | null;
}

export interface AwsUser {
  name: string;
  createdAt: number | null;
  /** Whether the user can sign in to the console; null when it couldn't be read. */
  console: boolean | null;
  passwordLastUsedAt: number | null;
  mfa: boolean | null;
  keys: AwsAccessKey[] | null;
}

/** Who holds administrator access, from the account's authorization details. */
export interface AwsAdmin {
  user: string;
  /** How: "AdministratorAccess", "group Admins", "inline policy". */
  via: string;
}

/** One principal a role's trust policy lets assume it. */
export interface AwsTrust {
  /** "*", an account ID, a role or user ARN, a service or a federated provider. */
  principal: string;
  kind: "anyone" | "account" | "service" | "federated";
  /** The statement has a Condition (an external ID, an organization, MFA…). */
  conditional: boolean;
  /**
   * For GitHub Actions (the token.actions.githubusercontent.com provider): the subjects the condition allows, lowercase,
   * such as "repo:org/app:ref:refs/heads/main" or "repo:org/*". An empty list means no subject condition: any repository.
   */
  github?: string[];
}

export interface AwsRole {
  name: string;
  trust: AwsTrust[];
  admin: boolean;
  /** Created by AWS for one of its services. */
  serviceLinked: boolean;
  /** Instance profiles that hand this role to EC2 instances. */
  profiles: string[];
  /** When the role was last assumed; null when never, or more than 400 days ago (AWS's tracking window). */
  lastUsedAt: number | null;
}

export interface AwsPolicy {
  name: string;
  /** Allows every action on every resource. */
  fullAdmin: boolean;
  attachments: number;
}

export interface AwsEscalation {
  kind: "user" | "group" | "role";
  name: string;
  /** The policy that grants it: "the policy deploy-tools", "the inline policy ci". */
  via: string;
  /** The actions, or pairs of actions, that make it possible. */
  paths: string[];
}

export interface PublicAccessBlock {
  blockPublicAcls: boolean;
  ignorePublicAcls: boolean;
  blockPublicPolicy: boolean;
  restrictPublicBuckets: boolean;
}

export interface AwsBucket {
  name: string;
  region: string;
  /** undefined: unreadable. null: the bucket has no setting of its own. */
  block: PublicAccessBlock | null | undefined;
  /** Whether AWS judges the bucket policy public. null: no policy. undefined: unreadable. */
  policyPublic: boolean | null | undefined;
  /** Groups the ACL grants access to: "everyone", "any AWS account". undefined: unreadable. */
  aclPublic: string[] | undefined;
  /**
   * What its bucket policy says, reduced to what checks need: the other AWS accounts it allows, and whether it refuses
   * plain HTTP. null: no policy. undefined: unreadable. The policy itself is never kept.
   */
  policy?: { otherAccounts: string[]; deniesHttp: boolean } | null;
}

export interface AwsSecurityGroup {
  id: string;
  name: string;
  vpcId: string | null;
  /** Inbound rules that allow the whole internet (0.0.0.0/0 or ::/0). */
  open: { protocol: string; from: number | null; to: number | null; cidr: string }[];
  /**
   * Who else its inbound rules let reach ports 80 and 443: Cloudflare's ranges, or other public ranges. Managed prefix
   * lists count by their entries; `prefixLists` holds the ones whose entries couldn't be read. Private ranges and
   * other security groups don't count. Only the kinds are kept, never the ranges. Absent when it wasn't worked out,
   * which is never taken to mean "nobody".
   */
  webFrom?: { cloudflare: boolean; other: boolean; prefixLists: string[] };
}

export interface AwsInstance {
  id: string;
  name: string | null;
  running: boolean;
  publicIp: string | null;
  vpcId: string | null;
  securityGroups: string[];
  /** IMDSv2 is required (HttpTokens = required). null: the metadata service is off. */
  imdsV2: boolean | null;
  /** The instance profile attached to it, which names the role its software runs as. */
  profile: string | null;
  /** The kind of credential found in its start-up script (user data). null: none. undefined: not read. The script itself is never kept. */
  userDataSecret: string | null | undefined;
}

/** A network interface: what a security group is really attached to, and whether it has a public address. */
export interface AwsInterface {
  id: string;
  publicIp: string | null;
  securityGroups: string[];
  /** What owns it: "instance", "load balancer", "database", "NAT gateway", "Lambda", or AWS's own type. */
  kind: string;
  /** The instance ID, or AWS's description of the owner. */
  owner: string | null;
  /** Its primary private address, which a load balancer's IP target names. */
  privateIp?: string | null;
}

export interface AwsDatabase {
  id: string;
  engine: string;
  public: boolean;
  encrypted: boolean;
  backupDays: number;
  /** Clients must connect with TLS (rds.force_ssl, require_secure_transport). null: unknown. */
  tlsRequired?: boolean | null;
  /** Its parameter group, or its cluster's for Aurora. */
  parameterGroup?: string | null;
  cluster?: string | null;
  /** A read replica: its backups are the source database's. */
  replica: boolean;
  vpcId: string | null;
  securityGroups: string[];
  port: number | null;
}

export interface AwsListener {
  port: number | null;
  protocol: string;
  sslPolicy: string | null;
  /** The default action sends visitors to HTTPS. */
  redirects: boolean;
  arn?: string;
  /** Classic load balancers: the port on the instances that the listener forwards to. */
  instancePort?: number | null;
  /**
   * How the listener routes requests, in the order the load balancer tries them, the default last. Read from
   * DescribeRules for application load balancers, from the default actions for the others. Undefined: not read;
   * null: couldn't be read.
   */
  rules?: AwsRule[] | null;
}

/** One listener rule, reduced to what decides where a request goes. A header condition keeps its name, never its values. */
export interface AwsRule {
  /** The rule's priority, or "default". */
  priority: string;
  /** Host header values it matches, as AWS writes them (with * and ? wildcards); empty: any host. */
  hosts: string[];
  paths: string[];
  /** Its other conditions, by kind: "source IP 10.0.0.0/8", "header X-Origin-Verify", "query string", "method POST". */
  conditions: string[];
  action: "forward" | "redirect" | "fixed-response" | "other";
  /** Visitors sign in through Cognito or an OpenID Connect provider before the request is forwarded. */
  authenticates: boolean;
  /** A redirect's destination ("HTTPS", "https://other.example") or a fixed response's status code. */
  detail: string | null;
  /** The target groups it forwards to, by ARN. A classic load balancer's single route uses "classic". */
  targetGroups: string[];
}

/** A target group and what is registered in it. */
export interface AwsTargetGroup {
  arn: string;
  name: string;
  protocol: string | null;
  port: number | null;
  /** "instance", "ip", "lambda" or "alb". */
  type: string;
  /** Registered targets and their health state; null when they couldn't be read (or past the limit). */
  targets: { id: string; port: number | null; health: string | null }[] | null;
}

export interface AwsLoadBalancer {
  name: string;
  dnsName: string;
  type: string;
  internetFacing: boolean;
  vpcId: string | null;
  /** Empty for network load balancers without their own groups: their targets' groups decide. */
  securityGroups: string[];
  /** Whether access logs are written; null when it couldn't be read. */
  accessLogs: boolean | null;
  arn?: string;
  /** How it handles requests that could be read two ways (desync mitigation): "monitor", "defensive", "strictest". */
  desync?: string | null;
  listeners: AwsListener[] | null;
  /** Classic load balancers: the instances registered with it. */
  instances?: string[];
}

export interface AwsFunction {
  name: string;
  runtime: string | null;
  /** The name of its execution role. */
  role: string | null;
  /** Function URLs by auth type ("NONE", "AWS_IAM"); null when they couldn't be read. */
  urls: { authType: string }[] | null;
  /** Its resource policy lets anyone invoke it. null: unread. */
  publicPolicy?: boolean | null;
  /**
   * A credential found in its environment variables: the variable's name and the kind, never the value. `likely` when only
   * the name says so. null: none found.
   */
  envSecret?: FoundSecret | null;
}

/** A credential found in configuration text or variables: where, and what kind. The value is never kept. */
export interface FoundSecret {
  /** The variable or field it was found in. */
  where: string;
  kind: string;
  /** Only the name looks like a secret; the value matched no known credential format. */
  likely: boolean;
}

/** A CloudTrail trail that records this region: its own, a multi-region trail or an organization's. */
export interface AwsTrail {
  arn: string;
  name: string;
  homeRegion: string;
  multiRegion: boolean;
  organization: boolean;
  /** Belongs to this account, not to the organization's management account. */
  own: boolean;
  /** null: its status couldn't be read (an organization trail, from a member account). */
  logging: boolean | null;
  validation: boolean;
}

/** A customer managed KMS key. AWS managed keys rotate themselves and aren't kept. */
export interface AwsKey {
  id: string;
  description: string | null;
  enabled: boolean;
  /** Symmetric encryption keys with AWS-made key material: the only kind that can rotate automatically. */
  rotatable: boolean;
  rotation: boolean | null;
  deletionDate: number | null;
  /** Its key policy lets any principal use it without a condition. null: unread. */
  publicPolicy: boolean | null;
}

export interface AwsCertificate {
  /** The last part of its ARN. */
  id: string;
  domain: string;
  type: string;
  inUse: boolean;
  notAfter: number | null;
  /** AWS renews it on its own: issued by ACM and eligible for renewal. */
  renews: boolean;
}

export interface AwsSecret {
  name: string;
  createdAt: number | null;
  changedAt: number | null;
  accessedAt: number | null;
  rotation: boolean;
  /** Its resource policy lets any principal read it. null: unread. */
  publicPolicy: boolean | null;
}

export interface AwsRepository {
  name: string;
  /** Images are scanned when pushed, by the repository's setting or a registry rule. */
  scanned: boolean;
  immutableTags: boolean;
  /** Its repository policy lets anyone pull or push. null: unread. */
  publicPolicy: boolean | null;
  /** Its images that are tagged or were pulled lately; null when they couldn't be listed, undefined when not read. */
  images?: AwsRepoImage[] | null;
}

export interface AwsRepoImage {
  digest: string;
  tags: string[];
  pushedAt: string | null;
  /** When it was last pulled; AWS records it at most once a day. */
  pulledAt: string | null;
  /** It is an index: a list of images, one per platform, with their build attestations beside them. */
  index?: boolean;
  /** The platforms an index has an image for ("linux/arm64"), once its manifest was read. */
  platforms?: string[];
}

/** An ECS service: what it runs and how the internet could reach it. */
export interface AwsService {
  name: string;
  cluster: string;
  /** "family:revision". */
  taskDefinition: string;
  running: number | null;
  /** Its tasks get a public address (awsvpc networking with assignPublicIp); null when its tasks use their instance's network. */
  publicIp: boolean | null;
  securityGroups: string[];
  /** Target groups its tasks are registered in, by ARN, and classic load balancers by name. */
  targetGroups: string[];
  classicLoadBalancers: string[];
}

/** An ECS task definition that a service runs. */
export interface AwsTaskDefinition {
  /** "family:revision". */
  name: string;
  services: string[];
  privileged: string[];
  /** Host namespaces it shares: "network", "process", "IPC". */
  hostNamespaces: string[];
  secret: FoundSecret | null;
  /** Each container's image, as the task definition writes it. */
  containers?: { name: string; image: string }[];
}

export interface AwsKubernetes {
  name: string;
  version: string | null;
  /** The API endpoint can be reached from the internet. */
  publicEndpoint: boolean;
  /** …from any address (publicAccessCidrs includes 0.0.0.0/0). */
  openToAll: boolean;
  secretsEncrypted: boolean;
  auditLogs: boolean;
  /** AWS's support status of its version: "STANDARD_SUPPORT", "EXTENDED_SUPPORT", "UNSUPPORTED"; null when unknown. */
  versionStatus: string | null;
}

export interface AwsWebAcl {
  name: string;
  arn: string;
  scope: "REGIONAL" | "CLOUDFRONT";
  rules: number;
  /** null: unread. */
  logging: boolean | null;
  /** The application load balancers it protects, by ARN. */
  loadBalancers: string[];
}

export interface AwsSearchDomain {
  name: string;
  /** Inside a VPC: not reachable from the internet. */
  vpc: boolean;
  /** Its access policy lets anyone in without a condition. */
  openPolicy: boolean;
  /** Fine-grained access control is on: users still need to sign in. */
  fineGrained: boolean;
  encryptedAtRest: boolean;
  nodeToNode: boolean;
  enforceHttps: boolean;
  /** The minimum TLS version is 1.2 or later. */
  tls12: boolean;
}

export interface AwsKafka {
  name: string;
  public: boolean;
  unauthenticated: boolean;
  /** Clients may connect without TLS. */
  plaintext: boolean;
}

export interface AwsLaunchTemplate {
  id: string;
  name: string;
  /** Of its default version. null: the metadata service is off, or not set (the AMI's default applies). */
  imdsV2: boolean | null;
  /** The kind of credential found in its start-up script; null when none. The script is never kept. */
  userDataSecret: string | null;
}

export interface AwsRegion {
  name: string;
  securityGroups: AwsSecurityGroup[] | null;
  instances: AwsInstance[] | null;
  ebsEncryptionByDefault: boolean | null;
  publicSnapshots: string[] | null;
  publicImages: { id: string; name: string | null }[] | null;
  vpcs: { id: string; isDefault: boolean; flowLogs: boolean | null }[] | null;
  databases: AwsDatabase[] | null;
  loadBalancers: AwsLoadBalancer[] | null;
  /** Target groups of the region's load balancers; null when unread, undefined when not read at all. */
  targetGroups?: AwsTargetGroup[] | null;
  functions: AwsFunction[] | null;
  /** Every network interface in the region; null when unreadable. */
  interfaces: AwsInterface[] | null;
  /** Elastic IPs allocated in the region, attached or not; null when unreadable. */
  addresses: string[] | null;
  /** CloudFront domain names AWS runs for API Gateway custom domains: they aren't in the account's distributions. null when unreadable. */
  apiDomains: string[] | null;
  /** Whether a GuardDuty detector is on; null when it couldn't be read. */
  guardDuty: boolean | null;
  // Every field below is null when it couldn't be read, and empty where the service isn't offered.
  trails?: AwsTrail[] | null;
  /** Whether AWS Config is recording. */
  configRecording?: boolean | null;
  keys?: AwsKey[] | null;
  certificates?: AwsCertificate[] | null;
  secrets?: AwsSecret[] | null;
  repositories?: AwsRepository[] | null;
  taskDefinitions?: AwsTaskDefinition[] | null;
  /** ECS services; null when unread, like the task definitions they run. */
  services?: AwsService[] | null;
  kubernetes?: AwsKubernetes[] | null;
  tables?: { name: string; pitr: boolean | null }[] | null;
  userPools?: { id: string; name: string; mfa: string }[] | null;
  /** `guestRole`: the role anyone gets when guest access is on. */
  identityPools?: { id: string; name: string; guest: boolean; guestRole: string | null }[] | null;
  webAcls?: AwsWebAcl[] | null;
  /** Systems Manager documents the account owns, and whether they are shared with everyone. */
  documents?: { name: string; public: boolean }[] | null;
  buildProjects?: { name: string; public: boolean; secret: FoundSecret | null }[] | null;
  eventBuses?: { name: string; public: boolean }[] | null;
  notebooks?: { name: string; internet: boolean }[] | null;
  searchDomains?: AwsSearchDomain[] | null;
  caches?: { id: string; engine: string; transit: boolean; atRest: boolean }[] | null;
  warehouses?: { id: string; public: boolean; encrypted: boolean }[] | null;
  topics?: { name: string; public: boolean }[] | null;
  /** SNS subscriptions that deliver over plain HTTP: the topic and the endpoint's host, never its path. */
  httpSubscriptions?: { topic: string; host: string }[] | null;
  queues?: { name: string; public: boolean }[] | null;
  brokers?: { name: string; engine: string; public: boolean }[] | null;
  kafka?: AwsKafka[] | null;
  fileSystems?: { id: string; name: string | null; encrypted: boolean }[] | null;
  launchTemplates?: AwsLaunchTemplate[] | null;
  /** Volumes attached to an instance that aren't encrypted. */
  unencryptedVolumes?: { id: string; instance: string | null }[] | null;
  /** The account's blocks on sharing snapshots and images publicly in this region: AWS's state names. */
  sharingBlocks?: { snapshots: string; images: string } | null;
  transitGateways?: { id: string; autoAccept: boolean }[] | null;
  /** Manual database snapshots, and whether anyone may restore them. */
  dbSnapshots?: { id: string; cluster: boolean; public: boolean }[] | null;
}

export interface AwsDistribution {
  id: string;
  domainName: string;
  enabled: boolean;
  aliases: string[];
  /** Viewer protocol policies across its behaviours ("allow-all", "redirect-to-https", "https-only"). */
  viewerPolicies: string[];
  minTls: string | null;
  defaultCertificate: boolean;
  waf: boolean;
  /**
   * `restricted`: an S3 origin read through origin access control (or the older origin access identity), so the bucket can
   * stay private. `missingBucket`: the S3 origin's bucket doesn't exist (anyone could create it); null when unknown.
   */
  origins: { domain: string; protocolPolicy: string | null; s3: boolean; restricted: boolean; missingBucket?: boolean | null }[];
}

export interface AwsRecord {
  name: string;
  type: string;
  /** Record values, or the alias target. Trailing dots removed, lowercase. */
  targets: string[];
  alias: boolean;
}

export interface AwsHostedZone {
  id: string;
  name: string;
  private: boolean;
  records: AwsRecord[] | null;
}

export interface AwsInventory {
  accountId: string;
  /** The account alias, when it has one. */
  accountName: string | null;
  now: number;
  unreadable: AwsSourceKey[];
  /** Whether the access key belongs to the root user. */
  rootKey: boolean;
  root: { mfa: boolean; accessKeys: boolean; users: number } | null;
  /** undefined: unreadable. null: the account has no password policy. */
  passwordPolicy:
    | { minLength: number; symbols: boolean; numbers: boolean; uppercase: boolean; lowercase: boolean; reusePrevention: number | null }
    | null
    | undefined;
  users: AwsUser[] | null;
  admins: AwsAdmin[] | null;
  roles: AwsRole[] | null;
  policies: AwsPolicy[] | null;
  /**
   * Users, groups and roles whose own policies let them give themselves more access (iam:CreatePolicyVersion,
   * iam:PassRole with a way to run code…), without already being administrators. From customer managed and inline
   * policies; null when unread.
   */
  escalations?: AwsEscalation[] | null;
  /** undefined: unreadable. null: never set. */
  s3Block: PublicAccessBlock | null | undefined;
  buckets: AwsBucket[] | null;
  /** Regions that were read. */
  regions: AwsRegion[];
  /** Enabled regions that refused the access key (a service control policy, usually): nothing there was evaluated. */
  skippedRegions: string[];
  distributions: AwsDistribution[] | null;
  /** IAM server certificates (for load balancers and CloudFront before ACM). */
  serverCertificates?: { name: string; expiresAt: number | null }[] | null;
  hostedZones: AwsHostedZone[] | null;
  /** Addresses this account was seen to give up on earlier scans, with when (set by the provider from the previous scan). */
  released: { ip: string; at: string }[];
  /** AWS's published EC2 address ranges, to recognise a record that points at an AWS address. Held for the scan, never stored. */
  ec2Prefixes: Prefixes | null;
  /** The images this scan looked at and what Trivy found in each, with the workloads known in the entity (set by the provider). */
  images?: { snapshot: ImagesSnapshot; scans: Map<string, ImageHighlights>; workloads: WorkloadLink[] };
}

export type { Related } from "../../core/types.ts";
